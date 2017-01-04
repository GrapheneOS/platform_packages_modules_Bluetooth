/*
 * Copyright (C) 2016 The Android Open Source Project
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

/**
 * Vendor Specific A2DP Codecs Support
 */

#define LOG_TAG "a2dp_vendor"

#include "a2dp_vendor.h"
#include "bt_target.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

bool A2DP_IsVendorSourceCodecValid(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_IsVendorSinkCodecValid(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

bool A2DP_IsVendorPeerSourceCodecValid(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

bool A2DP_IsVendorPeerSinkCodecValid(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_IsVendorSinkCodecSupported(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

bool A2DP_IsVendorPeerSourceCodecSupported(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id> and peer codec capabilities
  // NOTE: Should be done only for local Sink codecs.

  return false;
}

tA2DP_STATUS A2DP_VendorBuildSrc2SinkConfig(
    UNUSED_ATTR const uint8_t* p_src_cap, UNUSED_ATTR uint8_t* p_pref_cfg) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return A2DP_NS_CODEC_TYPE;
}

uint32_t A2DP_VendorCodecGetVendorId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_VENDOR_ID_START_IDX];

  uint32_t vendor_id = (p[0] & 0x000000ff) | ((p[1] << 8) & 0x0000ff00) |
                       ((p[2] << 16) & 0x00ff0000) |
                       ((p[3] << 24) & 0xff000000);

  return vendor_id;
}

uint16_t A2DP_VendorCodecGetCodecId(const uint8_t* p_codec_info) {
  const uint8_t* p = &p_codec_info[A2DP_VENDOR_CODEC_CODEC_ID_START_IDX];

  uint16_t codec_id = (p[0] & 0x00ff) | ((p[1] << 8) & 0xff00);

  return codec_id;
}

bool A2DP_VendorUsesRtpHeader(UNUSED_ATTR bool content_protection_enabled,
                              UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <content_protection_enabled, vendor_id, codec_id>

  return true;
}

const char* A2DP_VendorCodecName(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_src_config);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_src_config);

  // Add checks based on <vendor_id, codec_id>

  return "UNKNOWN VENDOR CODEC";
}

bool A2DP_VendorCodecTypeEquals(const uint8_t* p_codec_info_a,
                                const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) ||
      (codec_type_a != A2DP_MEDIA_CT_NON_A2DP)) {
    return false;
  }

  uint32_t vendor_id_a = A2DP_VendorCodecGetVendorId(p_codec_info_a);
  uint16_t codec_id_a = A2DP_VendorCodecGetCodecId(p_codec_info_a);
  uint32_t vendor_id_b = A2DP_VendorCodecGetVendorId(p_codec_info_b);
  uint16_t codec_id_b = A2DP_VendorCodecGetCodecId(p_codec_info_b);

  // OPTIONAL: Add extra vendor-specific checks based on the
  // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".

  return (vendor_id_a == vendor_id_b) && (codec_id_a == codec_id_b);
}

bool A2DP_VendorCodecEquals(const uint8_t* p_codec_info_a,
                            const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if ((codec_type_a != codec_type_b) ||
      (codec_type_a != A2DP_MEDIA_CT_NON_A2DP)) {
    return false;
  }

  uint32_t vendor_id_a = A2DP_VendorCodecGetVendorId(p_codec_info_a);
  uint16_t codec_id_a = A2DP_VendorCodecGetCodecId(p_codec_info_a);
  uint32_t vendor_id_b = A2DP_VendorCodecGetVendorId(p_codec_info_b);
  uint16_t codec_id_b = A2DP_VendorCodecGetCodecId(p_codec_info_b);

  if ((vendor_id_a != vendor_id_b) || (codec_id_a != codec_id_b)) return false;

  // Add extra vendor-specific checks based on the
  // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".

  return false;
}

int A2DP_VendorGetTrackSampleRate(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetTrackBitsPerSample(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetTrackChannelCount(UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return -1;
}

int A2DP_VendorGetSinkTrackChannelType(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return -1;
}

int A2DP_VendorGetSinkFramesCountToProcess(
    UNUSED_ATTR uint64_t time_interval_ms,
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>
  // NOTE: Should be done only for local Sink codecs.

  return -1;
}

bool A2DP_VendorGetPacketTimestamp(UNUSED_ATTR const uint8_t* p_codec_info,
                                   UNUSED_ATTR const uint8_t* p_data,
                                   UNUSED_ATTR uint32_t* p_timestamp) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return false;
}

bool A2DP_VendorBuildCodecHeader(UNUSED_ATTR const uint8_t* p_codec_info,
                                 UNUSED_ATTR BT_HDR* p_buf,
                                 UNUSED_ATTR uint16_t frames_per_packet) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return false;
}

const tA2DP_ENCODER_INTERFACE* A2DP_VendorGetEncoderInterface(
    const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return NULL;
}

bool A2DP_VendorAdjustCodec(uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return false;
}

btav_a2dp_codec_index_t A2DP_VendorSourceCodecIndex(
    UNUSED_ATTR const uint8_t* p_codec_info) {
  // uint32_t vendor_id = A2DP_VendorCodecGetVendorId(p_codec_info);
  // uint16_t codec_id = A2DP_VendorCodecGetCodecId(p_codec_info);

  // Add checks based on <vendor_id, codec_id>

  return BTAV_A2DP_CODEC_INDEX_MAX;
}

const char* A2DP_VendorCodecIndexStr(btav_a2dp_codec_index_t codec_index) {
  // Add checks based on codec_index
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
      break;  // This is not a vendor-specific codec
    // Add a switch statement for each vendor-specific codec
    case BTAV_A2DP_CODEC_INDEX_MAX:
      break;
  }

  return "UNKNOWN CODEC INDEX";
}

bool A2DP_VendorInitCodecConfig(btav_a2dp_codec_index_t codec_index,
                                tAVDT_CFG* p_cfg) {
  // Add checks based on codec_index
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
      break;  // This is not a vendor-specific codec
    // Add a switch statement for each vendor-specific codec
    case BTAV_A2DP_CODEC_INDEX_MAX:
      break;
  }

  return false;
}
