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

#ifndef A2D_VENDOR_H
#define A2D_VENDOR_H

#include <stdbool.h>

/* Offset for A2DP vendor codec */
#define A2D_VENDOR_CODEC_START_IDX              3

/* Offset for Vendor ID for A2DP vendor codec */
#define A2D_VENDOR_CODEC_VENDOR_ID_START_IDX    A2D_VENDOR_CODEC_START_IDX

/* Offset for Codec ID for A2DP vendor codec */
#define A2D_VENDOR_CODEC_CODEC_ID_START_IDX     \
                (A2D_VENDOR_CODEC_VENDOR_ID_START_IDX + sizeof(uint32_t))

#ifdef __cplusplus
extern "C"
{
#endif

// Checks whether a vendor-specific A2DP codec is supported.
// |p_codec_info| contains information about the codec capabilities.
// Returns true if the vendor-specific A2DP codec is supported, otherwise
// false.
bool A2D_IsVendorCodecSupported(const uint8_t *p_codec_info);

// Gets the Vendor ID for the vendor-specific A2DP codec.
// |p_codec_info| contains information about the codec capabilities.
// Returns the Vendor ID for the vendor-specific A2DP codec.
uint32_t A2D_VendorCodecGetVendorId(const uint8_t *p_codec_info);

// Gets the Codec ID for the vendor-specific A2DP codec.
// |p_codec_info| contains information about the codec capabilities.
// Returns the Codec ID for the vendor-specific A2DP codec.
uint16_t A2D_VendorCodecGetCodecId(const uint8_t *p_codec_info);

// Checks whether the A2DP vendor-specific data packets should contain RTP
// header. |content_protection_enabled| is true if Content Protection is
// enabled. |p_codec_info| contains information about the codec capabilities.
// Returns true if the A2DP vendor-specific data packets should contain RTP
// header, otherwise false.
bool A2D_VendorUsesRtpHeader(bool content_protection_enabled,
                             const uint8_t *p_codec_info);

#ifdef __cplusplus
}
#endif

#endif /* A2D_VENDOR_H */
