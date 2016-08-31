/******************************************************************************
 *
 *  Copyright (C) 2016 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <gtest/gtest.h>

#include "stack/include/a2d_api.h"
#include "stack/include/a2d_vendor.h"

namespace {
const uint8_t codec_info_sbc[AVDT_CODEC_SIZE] =
        { 1, 2, A2D_MEDIA_CT_SBC, 3, 4, 5, 6, 7, 8 };
const uint8_t codec_info_non_a2dp[AVDT_CODEC_SIZE] =
        { 1, 2, A2D_MEDIA_CT_NON_A2DP,
          3, 4, 0, 0,   // Vendor ID: LSB first, upper two octets should be 0
          7, 8 };       // Codec ID: LSB first
} // namespace

TEST(StackA2dpTest, test_a2d_get_codec_type) {
  tA2D_CODEC codec_type = A2D_GetCodecType(codec_info_sbc);
  EXPECT_EQ(codec_type, A2D_MEDIA_CT_SBC);

  codec_type = A2D_GetCodecType(codec_info_non_a2dp);
  EXPECT_EQ(codec_type, A2D_MEDIA_CT_NON_A2DP);
}

TEST(StackA2dpTest, test_a2d_is_codec_supported) {
  EXPECT_TRUE(A2D_IsCodecSupported(codec_info_sbc));
  EXPECT_FALSE(A2D_IsCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2d_uses_rtp_header) {
  EXPECT_TRUE(A2D_UsesRtpHeader(true, codec_info_sbc));
  EXPECT_TRUE(A2D_UsesRtpHeader(false, codec_info_sbc));
  EXPECT_TRUE(A2D_UsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2D_UsesRtpHeader(false, codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2d_vendor) {
  EXPECT_FALSE(A2D_IsVendorCodecSupported(codec_info_non_a2dp));
  EXPECT_EQ(A2D_VendorCodecGetVendorId(codec_info_non_a2dp),
              (uint32_t)0x00000403);
  EXPECT_EQ(A2D_VendorCodecGetCodecId(codec_info_non_a2dp), (uint16_t)0x0807);
  EXPECT_TRUE(A2D_VendorUsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2D_VendorUsesRtpHeader(false, codec_info_non_a2dp));
}
