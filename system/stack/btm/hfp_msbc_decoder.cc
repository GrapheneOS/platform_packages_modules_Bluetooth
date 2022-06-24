/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "hfp_msbc_decoder"

#include "hfp_msbc_decoder.h"

#include <base/logging.h>

#include <cstring>

#include "embdrv/sbc/decoder/include/oi_codec_sbc.h"
#include "embdrv/sbc/decoder/include/oi_status.h"
#include "osi/include/log.h"
#include "stack/include/bt_hdr.h"

typedef struct {
  OI_CODEC_SBC_DECODER_CONTEXT decoder_context;
  uint32_t context_data[CODEC_DATA_WORDS(2, SBC_CODEC_FAST_FILTER_BUFFERS)];
  int16_t decode_buf[120];
} tHFP_MSBC_DECODER;

static tHFP_MSBC_DECODER hfp_msbc_decoder;

bool hfp_msbc_decoder_init() {
  OI_STATUS status = OI_CODEC_SBC_DecoderReset(
      &hfp_msbc_decoder.decoder_context, hfp_msbc_decoder.context_data,
      sizeof(hfp_msbc_decoder.context_data), 1, 1, false);
  if (!OI_SUCCESS(status)) {
    LOG_ERROR("%s: OI_CODEC_SBC_DecoderReset failed with error code %d",
              __func__, status);
    return false;
  }

  status = OI_CODEC_SBC_DecoderConfigureMSbc(&hfp_msbc_decoder.decoder_context);
  if (!OI_SUCCESS(status)) {
    LOG_ERROR("%s: OI_CODEC_SBC_DecoderConfigureMSbc failed with error code %d",
              __func__, status);
    return false;
  }

  return true;
}

void hfp_msbc_decoder_cleanup(void) {
  memset(&hfp_msbc_decoder, 0, sizeof(hfp_msbc_decoder));
}

bool hfp_msbc_decoder_decode_packet(BT_HDR* p_buf, uint8_t** out_buf) {
  const OI_BYTE* oi_data;
  uint32_t oi_size, out_avail;
  int16_t* out_ptr;

  // TODO(b/232463744): Query the HFP HAL for the packet size.
  if (p_buf->len != 63) {
    LOG_ERROR("%s: Invalid packet", __func__);
    return false;
  }

  oi_data = p_buf->data + p_buf->offset;
  oi_size = p_buf->len;
  out_avail = sizeof(hfp_msbc_decoder.decode_buf);
  out_ptr = hfp_msbc_decoder.decode_buf;

  OI_STATUS status =
      OI_CODEC_SBC_DecodeFrame(&hfp_msbc_decoder.decoder_context, &oi_data,
                               &oi_size, out_ptr, &out_avail);
  if (!OI_SUCCESS(status) || out_avail != 240 || oi_size != 0) {
    LOG_ERROR("%s: Decoding failure: %d, %lu, %lu", __func__, status,
              (unsigned long)out_avail, (unsigned long)oi_size);
    return false;
  }

  *out_buf = (uint8_t*)&hfp_msbc_decoder.decode_buf;
  return true;
}
