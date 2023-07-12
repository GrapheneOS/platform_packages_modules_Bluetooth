/*
 * Copyright 2023 The Android Open Source Project
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

#define LOG_TAG "a2dp_aac_encoder"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/common.h>
#include <libavutil/frame.h>
#include <libavutil/samplefmt.h>
}

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include "a2dp_aac.h"
#include "a2dp_aac_encoder.h"
#include "common/time_util.h"
#include "os/rand.h"
#include "osi/include/allocator.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "stack/include/bt_hdr.h"

const int A2DP_AAC_HEADER_LEN = 9;
const int A2DP_AAC_MAX_LEN_REPR = 4;
const int A2DP_AAC_MAX_PREFIX_SIZE =
    AVDT_MEDIA_HDR_SIZE + A2DP_AAC_HEADER_LEN + A2DP_AAC_MAX_LEN_REPR;

// TODO(b/285999597): Run the APIs in a sandbox.
class FFmpegInterface {
 public:
  // Updates the context and configures codec parameters.
  //
  // Returns:
  //   The (fixed) input pcm frame size that the encoder accepts.
  //   Otherwise a negative errno on error.
  int prepare_context(int sample_rate, int channel_count, int bit_rate) {
    const AVCodec* codec = avcodec_find_encoder(AV_CODEC_ID_AAC);
    if (!codec) {
      LOG_ERROR("%s: Codec not found", __func__);
      return -ENOENT;
    }

    if (!avctx) {
      avctx = avcodec_alloc_context3(codec);
      if (!avctx) {
        LOG_ERROR("%s: Cannot allocate context", __func__);
        return -EINVAL;
      }
    }

    if (channel_count == 1) {
      AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
      av_channel_layout_copy(&avctx->ch_layout, &mono);
    } else if (channel_count == 2) {
      AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
      av_channel_layout_copy(&avctx->ch_layout, &stereo);
    } else {
      LOG_ERROR("%s: Invalid number of channels %d", __func__, channel_count);
      return -EINVAL;
    }

    if (sample_rate != 44100 && sample_rate != 48000) {
      LOG_ERROR("%s: Unsupported sample rate %d", __func__, sample_rate);
      return -EINVAL;
    }

    avctx->sample_rate = sample_rate;
    avctx->bit_rate = bit_rate;
    avctx->bit_rate_tolerance = 0;
    avctx->sample_fmt = AV_SAMPLE_FMT_FLTP;

    int rc = avcodec_open2(avctx, codec, NULL);
    if (rc < 0) {
      LOG_ERROR("%s: Could not open context: %d", __func__, rc);
      return -EINVAL;
    }

    return avctx->frame_size;
  }

  void clear_context() {
    if (avctx) {
      avcodec_free_context(&avctx);
      avctx = NULL;
    }
  }

  // Returns a negative errno if the encoded frame was not produced.
  // Otherwise returns the length of the encoded frame stored in `o_buf`.
  int encode_pcm(uint8_t* i_buf, int i_len, int bit_depth, uint8_t* o_buf) {
    int rc;

    AVFrame* frame = av_frame_alloc();

    frame->nb_samples = avctx->frame_size;
    frame->format = avctx->sample_fmt;
    frame->sample_rate = avctx->sample_rate;

    rc = av_channel_layout_copy(&frame->ch_layout, &avctx->ch_layout);
    if (rc < 0) {
      LOG_ERROR("%s: Failed to copy channel layout: %d", __func__, rc);
      av_frame_free(&frame);
      return -EINVAL;
    }

    rc = av_frame_get_buffer(frame, 0);
    if (rc < 0) {
      LOG_ERROR("%s: Failed to get buffer for frame: %d", __func__, rc);
      av_frame_free(&frame);
      return -EIO;
    }

    rc = av_frame_make_writable(frame);
    if (rc < 0) {
      LOG_ERROR("%s: Failed to make frame writable: %d", __func__, rc);
      av_frame_free(&frame);
      return -EIO;
    }

    const int bytes_per_sample = bit_depth / 8;
    const float scaling_factor = (float)1 / (1 << (bit_depth - 1));

    uint8_t* buff = i_buf;
    float* data[] = {(float*)frame->data[0], (float*)frame->data[1]};

    auto read_pcm = [](uint8_t* buff, int nbits) -> int {
      int pcm = 0;

      switch (nbits) {
        case 16:
          pcm = *((int16_t*)buff);
          break;
        case 24:
          pcm = *buff | *(buff + 1) << 8 | *(buff + 2) << 16;
          pcm |= pcm & 0x00800000 ? 0xff000000 : 0;
          break;
        case 32:
          pcm = *((int32_t*)buff);
          break;
        default:
          ASSERT_LOG(false, "Attempting to read %d bits as bit depth", nbits);
      }

      return pcm;
    };

    for (int i = 0; i < i_len / bytes_per_sample; ++i) {
      *data[i & 1]++ = read_pcm(buff, bit_depth) * scaling_factor;
      buff += bytes_per_sample;
    }

    AVPacket* pkt = av_packet_alloc();

    rc = avcodec_send_frame(avctx, frame);
    if (rc < 0) {
      LOG_ERROR("%s: Failed to send frame: %d", __func__, rc);
      av_frame_free(&frame);
      av_packet_free(&pkt);
      return -EIO;
    }

    rc = avcodec_receive_packet(avctx, pkt);
    if (rc < 0 && rc != -EAGAIN) {
      LOG_INFO("%s: Failed to receive packet: %d", __func__, rc);
      av_frame_free(&frame);
      av_packet_free(&pkt);
      return -EIO;
    }

    uint8_t* dst = o_buf;

    const uint8_t* header = avctx->sample_rate == 44100 ? A2DP_AAC_HEADER_44100
                                                        : A2DP_AAC_HEADER_48000;

    std::copy(header, header + A2DP_AAC_HEADER_LEN, dst);

    int written = A2DP_AAC_HEADER_LEN;
    dst += written;

    int cap = a2dp_aac_get_effective_frame_size();
    if (rc == -EAGAIN || cap < pkt->size + A2DP_AAC_MAX_PREFIX_SIZE) {
      if (rc != -EAGAIN) {
        LOG_WARN("Dropped pkt: size=%d, cap=%d", pkt->size, cap);
      }
      static uint8_t silent_frame[7] = {
          0x06, 0x21, 0x10, 0x04, 0x60, 0x8c, 0x1c,
      };
      std::copy(silent_frame, std::end(silent_frame), dst);
      dst += sizeof(silent_frame);
      written += sizeof(silent_frame);
    } else {
      int fsize = pkt->size;

      while (fsize >= 255) {
        *(dst++) = 0xff;
        fsize -= 255;
        ++written;
      }
      *(dst++) = fsize;
      ++written;

      std::copy(pkt->data, pkt->data + pkt->size, dst);
      written += pkt->size;
    }

    av_packet_unref(pkt);
    av_frame_free(&frame);
    av_packet_free(&pkt);

    return written;
  }

 private:
  static constexpr uint8_t A2DP_AAC_HEADER_44100[A2DP_AAC_HEADER_LEN] = {
      0x47, 0xfc, 0x00, 0x00, 0xb0, 0x90, 0x80, 0x03, 0x00,
  };
  static constexpr uint8_t A2DP_AAC_HEADER_48000[A2DP_AAC_HEADER_LEN] = {
      0x47, 0xfc, 0x00, 0x00, 0xb0, 0x8c, 0x80, 0x03, 0x00,
  };

  AVCodecContext* avctx;
};

typedef struct {
  float counter;
  uint32_t bytes_per_tick; /* pcm bytes read for each media task tick */
  uint64_t last_frame_us;
} tA2DP_AAC_FEEDING_STATE;

typedef struct {
  uint64_t session_start_us;
  size_t media_read_total_expected_packets;
  size_t media_read_total_expected_reads_count;
  size_t media_read_total_expected_read_bytes;
  size_t media_read_total_dropped_packets;
  size_t media_read_total_actual_reads_count;
  size_t media_read_total_actual_read_bytes;
} a2dp_aac_encoder_stats_t;

typedef struct {
  a2dp_source_read_callback_t read_callback;
  a2dp_source_enqueue_callback_t enqueue_callback;
  tA2DP_ENCODER_INIT_PEER_PARAMS peer_params;
  tA2DP_FEEDING_PARAMS feeding_params;
  tA2DP_AAC_FEEDING_STATE aac_feeding_state;
  uint16_t TxAaMtuSize;
  uint32_t timestamp;  // Timestamp embedded into the BT frames
  uint32_t pcm_samples_per_frame;
  uint32_t encoder_interval_ms;
  a2dp_aac_encoder_stats_t stats;
} tA2DP_AAC_ENCODER_CB;

static void a2dp_aac_get_num_frame_iteration(uint8_t* num_of_iterations,
                                             uint8_t* num_of_frames,
                                             uint64_t timestamp_us);
static void a2dp_aac_encode_frames(uint8_t nb_frame);
static bool a2dp_aac_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read);
static uint16_t adjust_effective_mtu(
    const tA2DP_ENCODER_INIT_PEER_PARAMS& peer_params);

namespace {
tA2DP_AAC_ENCODER_CB a2dp_aac_encoder_cb;
FFmpegInterface codec_intf;
}  // namespace

bool A2DP_LoadEncoderAac() { return true; }

void A2DP_UnloadEncoderAac(void) {
  codec_intf.clear_context();
  a2dp_aac_encoder_cb = tA2DP_AAC_ENCODER_CB{};
}

void a2dp_aac_encoder_init(const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
                           A2dpCodecConfig* a2dp_codec_config,
                           a2dp_source_read_callback_t read_callback,
                           a2dp_source_enqueue_callback_t enqueue_callback) {
  uint8_t codec_info[AVDT_CODEC_SIZE];
  if (!a2dp_codec_config->copyOutOtaCodecConfig(codec_info)) {
    LOG_ERROR(
        "%s: Cannot update the codec encoder for %s: "
        "invalid codec config",
        __func__, a2dp_codec_config->name().c_str());
    return;
  }

  uint16_t mtu = adjust_effective_mtu(*p_peer_params);

  int max_bit_rate =
      A2DP_ComputeMaxBitRateAac(codec_info, mtu - A2DP_AAC_MAX_PREFIX_SIZE) /
      8 * 8;
  int bit_rate = std::min(A2DP_GetBitRateAac(codec_info) / 8 * 8, max_bit_rate);

  tA2DP_SAMPLE_RATE sample_rate = A2DP_GetTrackSampleRateAac(codec_info);
  tA2DP_CHANNEL_COUNT channel_count = A2DP_GetTrackChannelCountAac(codec_info);
  tA2DP_BITS_PER_SAMPLE bits_per_sample =
      a2dp_codec_config->getAudioBitsPerSample();

  uint32_t pcm_samples_per_frame =
      codec_intf.prepare_context(sample_rate, channel_count, bit_rate);

  uint32_t encoder_interval_ms = pcm_samples_per_frame * 1000 / sample_rate;

  a2dp_aac_encoder_cb = tA2DP_AAC_ENCODER_CB{
      .read_callback = read_callback,
      .enqueue_callback = enqueue_callback,
      .TxAaMtuSize = mtu,
      .peer_params = *p_peer_params,
      .timestamp = bluetooth::os::GenerateRandom(),  // (RFC 6416)
      .feeding_params =
          {
              .sample_rate = sample_rate,
              .bits_per_sample = bits_per_sample,
              .channel_count = channel_count,
          },
      .aac_feeding_state =
          tA2DP_AAC_FEEDING_STATE{
              .bytes_per_tick = (sample_rate * bits_per_sample / 8 *
                                 channel_count * encoder_interval_ms) /
                                1000,
          },
      .pcm_samples_per_frame = pcm_samples_per_frame,
      .encoder_interval_ms = encoder_interval_ms,
      .stats =
          a2dp_aac_encoder_stats_t{
              .session_start_us = bluetooth::common::time_get_os_boottime_us(),
          },
  };
}

void a2dp_aac_encoder_cleanup() {
  codec_intf.clear_context();
  a2dp_aac_encoder_cb = tA2DP_AAC_ENCODER_CB{};
}

void a2dp_aac_feeding_reset() {
  auto frame_length = a2dp_aac_encoder_cb.pcm_samples_per_frame;
  auto sample_rate = a2dp_aac_encoder_cb.feeding_params.sample_rate;
  if (sample_rate == 0) {
    LOG_WARN("%s: Sample rate is not configured", __func__);
    return;
  }

  a2dp_aac_encoder_cb.encoder_interval_ms = frame_length * 1000 / sample_rate;

  a2dp_aac_encoder_cb.aac_feeding_state = tA2DP_AAC_FEEDING_STATE{
      .bytes_per_tick = (a2dp_aac_encoder_cb.feeding_params.sample_rate *
                         a2dp_aac_encoder_cb.feeding_params.bits_per_sample /
                         8 * a2dp_aac_encoder_cb.feeding_params.channel_count *
                         a2dp_aac_encoder_cb.encoder_interval_ms) /
                        1000,
  };

  LOG_WARN("%s: PCM bytes %d per tick (%dms)", __func__,
           a2dp_aac_encoder_cb.aac_feeding_state.bytes_per_tick,
           a2dp_aac_encoder_cb.encoder_interval_ms);
}

void a2dp_aac_feeding_flush() {
  a2dp_aac_encoder_cb.aac_feeding_state.counter = 0.0f;
}

uint64_t a2dp_aac_get_encoder_interval_ms() {
  return a2dp_aac_encoder_cb.encoder_interval_ms;
}

int a2dp_aac_get_effective_frame_size() {
  return a2dp_aac_encoder_cb.TxAaMtuSize;
}

void a2dp_aac_send_frames(uint64_t timestamp_us) {
  uint8_t nb_frame = 0;
  uint8_t nb_iterations = 0;

  a2dp_aac_get_num_frame_iteration(&nb_iterations, &nb_frame, timestamp_us);
  if (nb_frame == 0) return;

  for (uint8_t counter = 0; counter < nb_iterations; counter++) {
    a2dp_aac_encode_frames(nb_frame);
  }
}

// Obtains the number of frames to send and number of iterations
// to be used. |num_of_iterations| and |num_of_frames| parameters
// are used as output param for returning the respective values.
static void a2dp_aac_get_num_frame_iteration(uint8_t* num_of_iterations,
                                             uint8_t* num_of_frames,
                                             uint64_t timestamp_us) {
  uint32_t result = 0;
  uint8_t nof = 0;
  uint8_t noi = 1;

  uint32_t pcm_bytes_per_frame =
      a2dp_aac_encoder_cb.pcm_samples_per_frame *
      a2dp_aac_encoder_cb.feeding_params.channel_count *
      a2dp_aac_encoder_cb.feeding_params.bits_per_sample / 8;
  LOG_VERBOSE("%s: pcm_bytes_per_frame %u", __func__, pcm_bytes_per_frame);

  uint32_t us_this_tick = a2dp_aac_encoder_cb.encoder_interval_ms * 1000;
  uint64_t now_us = timestamp_us;
  if (a2dp_aac_encoder_cb.aac_feeding_state.last_frame_us != 0)
    us_this_tick =
        (now_us - a2dp_aac_encoder_cb.aac_feeding_state.last_frame_us);
  a2dp_aac_encoder_cb.aac_feeding_state.last_frame_us = now_us;

  a2dp_aac_encoder_cb.aac_feeding_state.counter +=
      (float)a2dp_aac_encoder_cb.aac_feeding_state.bytes_per_tick *
      us_this_tick / (a2dp_aac_encoder_cb.encoder_interval_ms * 1000);

  result = a2dp_aac_encoder_cb.aac_feeding_state.counter / pcm_bytes_per_frame;
  a2dp_aac_encoder_cb.aac_feeding_state.counter -= result * pcm_bytes_per_frame;
  nof = result;

  LOG_VERBOSE("%s: effective num of frames %u, iterations %u", __func__, nof,
              noi);

  *num_of_frames = nof;
  *num_of_iterations = noi;
}

static void a2dp_aac_encode_frames(uint8_t nb_frame) {
  uint8_t read_buffer[BT_DEFAULT_BUFFER_SIZE];
  int pcm_bytes_per_frame = a2dp_aac_encoder_cb.pcm_samples_per_frame *
                            a2dp_aac_encoder_cb.feeding_params.channel_count *
                            a2dp_aac_encoder_cb.feeding_params.bits_per_sample /
                            8;
  CHECK(pcm_bytes_per_frame <= static_cast<int>(sizeof(read_buffer)));

  while (nb_frame) {
    a2dp_aac_encoder_cb.stats.media_read_total_expected_packets++;

    uint32_t bytes_read = 0;
    if (!a2dp_aac_read_feeding(read_buffer, &bytes_read)) {
      LOG_WARN("%s: Underflow %u", __func__, nb_frame);
      a2dp_aac_encoder_cb.aac_feeding_state.counter +=
          nb_frame * a2dp_aac_encoder_cb.pcm_samples_per_frame *
          a2dp_aac_encoder_cb.feeding_params.channel_count *
          a2dp_aac_encoder_cb.feeding_params.bits_per_sample / 8;
      return;
    }

    BT_HDR* p_buf = (BT_HDR*)osi_calloc(BT_DEFAULT_BUFFER_SIZE);
    p_buf->offset = AVDT_MEDIA_OFFSET;
    p_buf->len = 0;
    p_buf->layer_specific = 0;

    int written = codec_intf.encode_pcm(
        read_buffer, bytes_read,
        a2dp_aac_encoder_cb.feeding_params.bits_per_sample,
        (uint8_t*)(p_buf + 1) + p_buf->offset);

    if (written < 0) {
      a2dp_aac_encoder_cb.stats.media_read_total_dropped_packets++;
      osi_free(p_buf);
      return;
    }

    if (written == 0) {
      LOG_INFO("%s: Dropped a frame, likely due to buffering", __func__);
      a2dp_aac_encoder_cb.stats.media_read_total_dropped_packets++;
      osi_free(p_buf);
      continue;
    }

    p_buf->layer_specific++;
    p_buf->len += written;
    --nb_frame;

    *((uint32_t*)(p_buf + 1)) = a2dp_aac_encoder_cb.timestamp;

    a2dp_aac_encoder_cb.timestamp +=
        p_buf->layer_specific * a2dp_aac_encoder_cb.pcm_samples_per_frame;

    if (!a2dp_aac_encoder_cb.enqueue_callback(p_buf, 1, bytes_read)) return;
  }
}

static bool a2dp_aac_read_feeding(uint8_t* read_buffer, uint32_t* bytes_read) {
  uint32_t read_size = a2dp_aac_encoder_cb.pcm_samples_per_frame *
                       a2dp_aac_encoder_cb.feeding_params.channel_count *
                       a2dp_aac_encoder_cb.feeding_params.bits_per_sample / 8;

  a2dp_aac_encoder_cb.stats.media_read_total_expected_reads_count++;
  a2dp_aac_encoder_cb.stats.media_read_total_expected_read_bytes += read_size;

  /* Read Data from UIPC channel */
  uint32_t nb_byte_read =
      a2dp_aac_encoder_cb.read_callback(read_buffer, read_size);
  a2dp_aac_encoder_cb.stats.media_read_total_actual_read_bytes += nb_byte_read;
  *bytes_read = nb_byte_read;

  if (nb_byte_read < read_size) {
    if (nb_byte_read == 0) return false;

    /* Fill the unfilled part of the read buffer with silence (0) */
    std::fill_n((uint8_t*)read_buffer + nb_byte_read, read_size - nb_byte_read,
                0x00);
    nb_byte_read = read_size;
  }
  a2dp_aac_encoder_cb.stats.media_read_total_actual_reads_count++;

  return true;
}

static uint16_t adjust_effective_mtu(
    const tA2DP_ENCODER_INIT_PEER_PARAMS& peer_params) {
  uint16_t mtu_size =
      BT_DEFAULT_BUFFER_SIZE - AVDT_MEDIA_OFFSET - sizeof(BT_HDR);
  if (mtu_size > peer_params.peer_mtu) {
    mtu_size = peer_params.peer_mtu;
  }
  LOG_VERBOSE("%s: original AVDTP MTU size: %d", __func__, mtu_size);
  if (peer_params.is_peer_edr && !peer_params.peer_supports_3mbps) {
    // This condition would be satisfied only if the remote device is
    // EDR and supports only 2 Mbps, but the effective AVDTP MTU size
    // exceeds the 2DH5 packet size.
    LOG_VERBOSE("%s: The remote device is EDR but does not support 3 Mbps",
                __func__);
    if (mtu_size > MAX_2MBPS_AVDTP_MTU) {
      LOG_WARN("%s: Restricting AVDTP MTU size from %d to %d", __func__,
               mtu_size, MAX_2MBPS_AVDTP_MTU);
      mtu_size = MAX_2MBPS_AVDTP_MTU;
    }
  }
  return mtu_size;
}

void A2dpCodecConfigAacSource::debug_codec_dump(int fd) {
  a2dp_aac_encoder_stats_t* stats = &a2dp_aac_encoder_cb.stats;

  A2dpCodecConfig::debug_codec_dump(fd);

  auto codec_specific_1 = getCodecConfig().codec_specific_1;
  dprintf(
      fd,
      "  AAC bitrate mode                                        : %s "
      "(0x%" PRIx64 ")\n",
      ((codec_specific_1 & ~A2DP_AAC_VARIABLE_BIT_RATE_MASK) == 0 ? "Constant"
                                                                  : "Variable"),
      codec_specific_1);
  dprintf(fd, "  Encoder interval (ms): %" PRIu64 "\n",
          a2dp_aac_get_encoder_interval_ms());
  dprintf(fd, "  Effective MTU: %d\n", a2dp_aac_get_effective_frame_size());
  dprintf(fd,
          "  Packet counts (expected/dropped)                        : %zu / "
          "%zu\n",
          stats->media_read_total_expected_packets,
          stats->media_read_total_dropped_packets);

  dprintf(fd,
          "  PCM read counts (expected/actual)                       : %zu / "
          "%zu\n",
          stats->media_read_total_expected_reads_count,
          stats->media_read_total_actual_reads_count);

  dprintf(fd,
          "  PCM read bytes (expected/actual)                        : %zu / "
          "%zu\n",
          stats->media_read_total_expected_read_bytes,
          stats->media_read_total_actual_read_bytes);
}
