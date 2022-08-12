/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>

#include "hfp_msbc_decoder.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "stack/btm/btm_sco.h"
#include "udrv/include/uipc.h"

#define SCO_DATA_READ_POLL_MS 10
#define SCO_HOST_DATA_PATH "/var/run/bluetooth/audio/.sco_data"
// TODO(b/198260375): Make SCO data owner group configurable.
#define SCO_HOST_DATA_GROUP "bluetooth-audio"

#define BTM_MSBC_H2_HEADER_0 0x01
#define BTM_MSBC_CODE_SIZE 240
#define BTM_MSBC_PKT_LEN 60
#define BTM_MSBC_SYNC_WORD 0xAD

namespace {

std::unique_ptr<tUIPC_STATE> sco_uipc = nullptr;

void sco_data_cb(tUIPC_CH_ID, tUIPC_EVENT event) {
  switch (event) {
    case UIPC_OPEN_EVT:
      /*
       * Read directly from media task from here on (keep callback for
       * connection events.
       */
      UIPC_Ioctl(*sco_uipc, UIPC_CH_ID_AV_AUDIO, UIPC_REG_REMOVE_ACTIVE_READSET,
                 NULL);
      UIPC_Ioctl(*sco_uipc, UIPC_CH_ID_AV_AUDIO, UIPC_SET_READ_POLL_TMO,
                 reinterpret_cast<void*>(SCO_DATA_READ_POLL_MS));
      break;
    default:
      break;
  }
}

}  // namespace

namespace bluetooth {
namespace audio {
namespace sco {

void open() {
  if (sco_uipc != nullptr) {
    LOG_WARN("Re-opening UIPC that is already running");
  }
  sco_uipc = UIPC_Init();
  UIPC_Open(*sco_uipc, UIPC_CH_ID_AV_AUDIO, sco_data_cb, SCO_HOST_DATA_PATH);
  struct group* grp = getgrnam(SCO_HOST_DATA_GROUP);
  chmod(SCO_HOST_DATA_PATH, 0770);
  if (grp) {
    int res = chown(SCO_HOST_DATA_PATH, -1, grp->gr_gid);
    if (res == -1) {
      LOG_ERROR("%s failed: %s", __func__, strerror(errno));
    }
  }
}

void cleanup() {
  if (sco_uipc == nullptr) {
    return;
  }
  UIPC_Close(*sco_uipc, UIPC_CH_ID_ALL);
  sco_uipc = nullptr;
}

size_t read(uint8_t* p_buf, uint32_t len) {
  if (sco_uipc == nullptr) {
    LOG_WARN("Read from uninitialized or closed UIPC");
    return 0;
  }
  return UIPC_Read(*sco_uipc, UIPC_CH_ID_AV_AUDIO, p_buf, len);
}

size_t write(const uint8_t* p_buf, uint32_t len) {
  if (sco_uipc == nullptr) {
    LOG_WARN("Write to uninitialized or closed UIPC");
    return 0;
  }
  return UIPC_Send(*sco_uipc, UIPC_CH_ID_AV_AUDIO, 0, p_buf, len) ? len : 0;
}

namespace wbs {

/* Second octet of H2 header is composed by 4 bits fixed 0x8 and 4 bits
 * sequence number 0000, 0011, 1100, 1111. */
static const uint8_t btm_h2_header_frames_count[] = {0x08, 0x38, 0xc8, 0xf8};

/* Supported SCO packet sizes for mSBC. The wideband speech mSBC frame parsing
 * code ties to limited packet size values. Specifically list them out
 * to check against when setting packet size. The first entry is the default
 * value as a fallback. */
constexpr size_t btm_wbs_supported_pkt_size[] = {BTM_MSBC_PKT_LEN, 72, 0};
/* Buffer size should be set to least common multiple of SCO packet size and
 * BTM_MSBC_PKT_LEN for optimizing buffer copy. */
constexpr size_t btm_wbs_msbc_buffer_size[] = {BTM_MSBC_PKT_LEN, 360, 0};

static const uint8_t btm_msbc_zero_frames[BTM_MSBC_CODE_SIZE] = {0};

/* Define the structure that contains mSBC data */
typedef struct {
  size_t packet_size;   /* SCO mSBC packet size supported by lower layer */
  bool check_alignment; /* True to wait for mSBC packet to align */
  size_t buf_size; /* The size of the buffer, determined by the packet_size. */

  uint8_t* msbc_decode_buf; /* Buffer to store mSBC packets to decode */
  size_t decode_buf_wo;     /* Write offset of the decode buffer */
  size_t decode_buf_ro;     /* Read offset of the decode buffer */

  static size_t get_supported_packet_size(size_t pkt_size,
                                          size_t* buffer_size) {
    int i;
    for (i = 0; btm_wbs_supported_pkt_size[i] != 0 &&
                btm_wbs_supported_pkt_size[i] != pkt_size;
         i++)
      ;
    /* In case of unsupported value, error log and fallback to
     * BTM_MSBC_PKT_LEN(60). */
    if (btm_wbs_supported_pkt_size[i] == 0) {
      LOG_WARN("Unsupported packet size %lu", (unsigned long)pkt_size);
      i = 0;
    }

    if (buffer_size) {
      *buffer_size = btm_wbs_msbc_buffer_size[i];
    }
    return btm_wbs_supported_pkt_size[i];
  }

  bool verify_h2_header_seq_num(const uint8_t num) {
    for (int i = 0; i < 4; i++) {
      if (num == btm_h2_header_frames_count[i]) {
        return true;
      }
    }
    return false;
  }

 public:
  void init(size_t pkt_size) {
    decode_buf_wo = 0;
    decode_buf_ro = 0;

    pkt_size = get_supported_packet_size(pkt_size, &buf_size);
    if (pkt_size != BTM_MSBC_PKT_LEN) check_alignment = true;
    if (pkt_size == packet_size) return;
    packet_size = pkt_size;

    if (msbc_decode_buf) osi_free(msbc_decode_buf);
    msbc_decode_buf = (uint8_t*)osi_calloc(buf_size);
  }

  void deinit() {
    if (msbc_decode_buf) osi_free(msbc_decode_buf);
  }

  size_t decodable() { return decode_buf_wo - decode_buf_ro; }

  size_t write(const uint8_t* input, size_t len) {
    if (len > buf_size - decode_buf_wo) {
      return 0;
    }

    std::copy(input, input + len, msbc_decode_buf + decode_buf_wo);
    decode_buf_wo += len;
    return len;
  }

  const uint8_t* find_msbc_pkt_head() {
    size_t rp = 0;
    while (decode_buf_wo - decode_buf_ro - rp >= BTM_MSBC_PKT_LEN) {
      if ((msbc_decode_buf[decode_buf_ro + rp] != BTM_MSBC_H2_HEADER_0) ||
          (!verify_h2_header_seq_num(
              msbc_decode_buf[decode_buf_ro + rp + 1])) ||
          (msbc_decode_buf[decode_buf_ro + rp + 2] != BTM_MSBC_SYNC_WORD)) {
        rp++;
        continue;
      }
      return &msbc_decode_buf[decode_buf_ro + rp];
    }

    return nullptr;
  }

  void mark_pkt_decoded() {
    if (decode_buf_ro + BTM_MSBC_PKT_LEN > decode_buf_wo) {
      LOG_ERROR("Trying to mark read offset beyond write offset.");
      return;
    }

    decode_buf_ro += BTM_MSBC_PKT_LEN;
    if (decode_buf_ro == decode_buf_wo) {
      decode_buf_ro = 0;
      decode_buf_wo = 0;
    }
  }

} tBTM_MSBC_INFO;

static tBTM_MSBC_INFO* msbc_info = nullptr;

void init(size_t pkt_size) {
  hfp_msbc_decoder_init();

  if (msbc_info) {
    LOG_WARN("Re-initiating mSBC buffer that is active or not cleaned");
    msbc_info->deinit();
    osi_free(msbc_info);
  }

  msbc_info = (tBTM_MSBC_INFO*)osi_calloc(sizeof(*msbc_info));
  msbc_info->init(pkt_size);
}

void cleanup() {
  hfp_msbc_decoder_cleanup();

  if (msbc_info == nullptr) return;

  msbc_info->deinit();
  osi_free(msbc_info);
  msbc_info = nullptr;
}

size_t enqueue_packet(const uint8_t* data, size_t pkt_size) {
  if (msbc_info == nullptr) {
    LOG_WARN("mSBC buffer uninitialized or cleaned");
    return 0;
  }

  if (pkt_size != msbc_info->packet_size) {
    LOG_WARN(
        "Ignoring the coming packet with size %lu that is inconsistent with "
        "the HAL reported packet size %lu",
        (unsigned long)pkt_size, (unsigned long)msbc_info->packet_size);
    return 0;
  }

  if (msbc_info->check_alignment) {
    if (data[0] != BTM_MSBC_H2_HEADER_0 || data[2] != BTM_MSBC_SYNC_WORD) {
      LOG_DEBUG("Waiting for valid mSBC frame head");
      return 0;
    }
    msbc_info->check_alignment = false;
  }

  if (msbc_info->write(data, pkt_size) != pkt_size) {
    LOG_DEBUG("Fail to write packet with size %lu to buffer",
              (unsigned long)pkt_size);
    return 0;
  }

  return pkt_size;
}

size_t decode(const uint8_t** out_data) {
  const uint8_t* frame_head = nullptr;

  if (msbc_info == nullptr) {
    LOG_WARN("mSBC buffer uninitialized or cleaned");
    return 0;
  }

  if (msbc_info->decodable() < BTM_MSBC_PKT_LEN) {
    LOG_DEBUG("No complete mSBC packet to decode");
    return 0;
  }

  frame_head = msbc_info->find_msbc_pkt_head();
  if (frame_head == nullptr) {
    LOG_DEBUG("No valid mSBC packet to decode %lu, %lu",
              (unsigned long)msbc_info->decode_buf_ro,
              (unsigned long)msbc_info->decode_buf_wo);
    /* Done with parsing the raw bytes just read. If mSBC frame head not found,
     * we shall handle it as packet loss. */
    goto packet_loss;
  }

  if (!hfp_msbc_decoder_decode_packet(frame_head, out_data)) {
    LOG_DEBUG("Decoding mSBC packet failed");
    goto packet_loss;
  }

  msbc_info->mark_pkt_decoded();
  return BTM_MSBC_CODE_SIZE;

packet_loss:
  *out_data = btm_msbc_zero_frames;
  msbc_info->mark_pkt_decoded();
  return BTM_MSBC_CODE_SIZE;
}

}  // namespace wbs

}  // namespace sco
}  // namespace audio
}  // namespace bluetooth
