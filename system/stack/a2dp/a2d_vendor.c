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

#define LOG_TAG "a2d_vendor"

#include "bt_target.h"
#include "a2d_vendor.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

bool A2D_IsVendorValidCodec(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return false;
}

bool A2D_IsVendorSourceCodecSupported(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return false;
}

bool A2D_IsVendorSinkCodecSupported(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return false;
}

bool A2D_IsVendorPeerSourceCodecSupported(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id> and peer codec capabilities

    return false;
}

tA2D_STATUS A2D_VendorBuildSrc2SinkConfig(UNUSED_ATTR uint8_t *p_pref_cfg,
                                          UNUSED_ATTR const uint8_t *p_src_cap)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return A2D_NS_CODEC_TYPE;
}

uint32_t A2D_VendorCodecGetVendorId(const uint8_t *p_codec_info)
{
    const uint8_t *p = &p_codec_info[A2D_VENDOR_CODEC_VENDOR_ID_START_IDX];

    uint32_t vendor_id =
      (p[0] & 0x000000ff) |
      ((p[1] << 8) & 0x0000ff00) |
      ((p[2] << 16) & 0x00ff0000) |
      ((p[3] << 24) & 0xff000000);

    return vendor_id;
}

uint16_t A2D_VendorCodecGetCodecId(const uint8_t *p_codec_info)
{
    const uint8_t *p = &p_codec_info[A2D_VENDOR_CODEC_CODEC_ID_START_IDX];

    uint16_t codec_id = (p[0] & 0x00ff) | ((p[1] << 8) & 0xff00);

    return codec_id;
}

bool A2D_VendorUsesRtpHeader(UNUSED_ATTR bool content_protection_enabled,
                             UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <content_protection_enabled, vendor_id, codec_id>

    return true;
}

bool A2D_VendorCodecTypeEquals(const uint8_t *p_codec_info_a,
                               const uint8_t *p_codec_info_b)
{
    tA2D_CODEC_TYPE codec_type_a = A2D_GetCodecType(p_codec_info_a);
    tA2D_CODEC_TYPE codec_type_b = A2D_GetCodecType(p_codec_info_b);

    if ((codec_type_a != codec_type_b) ||
        (codec_type_a != A2D_MEDIA_CT_NON_A2DP)) {
        return false;
    }

    uint32_t vendor_id_a = A2D_VendorCodecGetVendorId(p_codec_info_a);
    uint16_t codec_id_a = A2D_VendorCodecGetCodecId(p_codec_info_a);
    uint32_t vendor_id_b = A2D_VendorCodecGetVendorId(p_codec_info_b);
    uint16_t codec_id_b = A2D_VendorCodecGetCodecId(p_codec_info_b);

    // OPTIONAL: Add extra vendor-specific checks based on the
    // vendor-specific data stored in "p_codec_info_a" and "p_codec_info_b".

    return (vendor_id_a == vendor_id_b) && (codec_id_a == codec_id_b);
}

int A2D_VendorGetTrackFrequency(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetTrackChannelCount(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetNumberOfSubbands(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetNumberOfBlocks(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetAllocationMethodCode(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetChannelModeCode(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetSamplingFrequencyCode(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetMinBitpool(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetMaxBitpool(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetSinkTrackChannelType(UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}

int A2D_VendorGetSinkFramesCountToProcess(UNUSED_ATTR uint64_t time_interval_ms,
                                          UNUSED_ATTR const uint8_t *p_codec_info)
{
    // uint32_t vendor_id = A2D_VendorCodecGetVendorId(p_codec_info);
    // uint16_t codec_id = A2D_VendorCodecGetCodecId(p_codec_info);

    // Add checks based on <vendor_id, codec_id>

    return -1;
}
