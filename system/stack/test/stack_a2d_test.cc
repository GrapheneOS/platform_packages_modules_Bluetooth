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
#include "stack/include/a2d_sbc.h"
#include "stack/include/a2d_vendor.h"

namespace {
const uint8_t codec_info_sbc[AVDT_CODEC_SIZE] = {
  6,                    // Length (A2D_SBC_INFO_LEN)
  0,                    // Media Type: A2D_MEDIA_TYPE_AUDIO
  0,                    // Media Codec Type: A2D_MEDIA_CT_SBC
  0x20 | 0x01,          // Sample Frequency: A2D_SBC_IE_SAMP_FREQ_44 |
                        // Channel Mode: A2D_SBC_IE_CH_MD_JOINT
  0x10 | 0x04 | 0x01,   // Block Length: A2D_SBC_IE_BLOCKS_16 |
                        // Subbands: A2D_SBC_IE_SUBBAND_8 |
                        // Allocation Method: A2D_SBC_IE_ALLOC_MD_L
  2,                    // MinimumBitpool Value: A2D_SBC_IE_MIN_BITPOOL
  53,                   // Maxium Bitpool Value: A2D_SBC_MAX_BITPOOL
  7,                    // Dummy
  8,                    // Dummy
  9                     // Dummy
};

const uint8_t codec_info_non_a2dp[AVDT_CODEC_SIZE] = {
  8,                    // Length
  0,                    // Media Type: A2D_MEDIA_TYPE_AUDIO
  0xFF,                 // Media Codec Type: A2D_MEDIA_CT_NON_A2DP
  3, 4, 0, 0,           // Vendor ID: LSB first, upper two octets should be 0
  7, 8,                 // Codec ID: LSB first
  9                     // Dummy
};

} // namespace

TEST(StackA2dpTest, test_a2d_get_codec_type) {
  tA2D_CODEC_TYPE codec_type = A2D_GetCodecType(codec_info_sbc);
  EXPECT_EQ(codec_type, A2D_MEDIA_CT_SBC);

  codec_type = A2D_GetCodecType(codec_info_non_a2dp);
  EXPECT_EQ(codec_type, A2D_MEDIA_CT_NON_A2DP);
}

TEST(StackA2dpTest, test_a2d_is_source_codec_supported) {
  EXPECT_TRUE(A2D_IsSourceCodecSupported(codec_info_sbc));
  EXPECT_FALSE(A2D_IsSourceCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2d_is_sink_codec_supported) {
  EXPECT_TRUE(A2D_IsSinkCodecSupported(codec_info_sbc));
  EXPECT_FALSE(A2D_IsSinkCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2d_is_peer_source_codec_supported) {
  EXPECT_TRUE(A2D_IsPeerSourceCodecSupported(codec_info_sbc));
  EXPECT_FALSE(A2D_IsPeerSourceCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_init_default_codec) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];

  memset(codec_info_result, 0, sizeof(codec_info_result));
  A2D_InitDefaultCodec(codec_info_result);

  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }
}

TEST(StackA2dpTest, test_set_codec) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];

  const tA2D_AV_MEDIA_FEEDINGS feeding = {
    .format = tA2D_AV_CODEC_PCM,
    .cfg = {
      .pcm = {
        .sampling_freq = 44100,
        .num_channel = 2,
        .bit_per_sample = 16
      }
    }
  };

  EXPECT_TRUE(A2D_SetCodec(&feeding, codec_info_result));

  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Test invalid feeding - invalid format
  tA2D_AV_MEDIA_FEEDINGS bad_feeding = feeding;
  bad_feeding.format = 0;
  EXPECT_FALSE(A2D_SetCodec(&bad_feeding, codec_info_result));

  // Test invalid feeding - invalid num_channel
  bad_feeding = feeding;
  bad_feeding.cfg.pcm.num_channel = 3;
  EXPECT_FALSE(A2D_SetCodec(&bad_feeding, codec_info_result));

  // Test invalid feeding - invalid bit_per_sample
  bad_feeding = feeding;
  bad_feeding.cfg.pcm.bit_per_sample = 7;
  EXPECT_FALSE(A2D_SetCodec(&bad_feeding, codec_info_result));

  // Test invalid feeding - invalid sampling_freq
  bad_feeding = feeding;
  bad_feeding.cfg.pcm.sampling_freq = 7999;
  EXPECT_FALSE(A2D_SetCodec(&bad_feeding, codec_info_result));
}

TEST(StackA2dpTest, test_build_src2sink_config) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];

  EXPECT_EQ(A2D_BuildSrc2SinkConfig(codec_info_result, codec_info_sbc),
            A2D_SUCCESS);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Include extra (less preferred) capabilities and test again
  uint8_t codec_info_sbc_test1[AVDT_CODEC_SIZE];
  memset(codec_info_result, 0, sizeof(codec_info_result));
  memcpy(codec_info_sbc_test1, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test1[3] |= (A2D_SBC_IE_CH_MD_STEREO | A2D_SBC_IE_CH_MD_DUAL |
                              A2D_SBC_IE_CH_MD_MONO);
  codec_info_sbc_test1[4] |= (A2D_SBC_IE_BLOCKS_12 | A2D_SBC_IE_BLOCKS_8 |
                              A2D_SBC_IE_BLOCKS_4);
  codec_info_sbc_test1[4] |= A2D_SBC_IE_SUBBAND_4;
  codec_info_sbc_test1[4] |= A2D_SBC_IE_ALLOC_MD_S;
  EXPECT_EQ(A2D_BuildSrc2SinkConfig(codec_info_result, codec_info_sbc_test1),
            A2D_SUCCESS);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Test invalid codec info
  memset(codec_info_result, 0, sizeof(codec_info_result));
  memset(codec_info_sbc_test1, 0, sizeof(codec_info_sbc_test1));
  EXPECT_NE(A2D_BuildSrc2SinkConfig(codec_info_result, codec_info_sbc_test1),
            A2D_SUCCESS);
}

TEST(StackA2dpTest, test_a2d_uses_rtp_header) {
  EXPECT_TRUE(A2D_UsesRtpHeader(true, codec_info_sbc));
  EXPECT_TRUE(A2D_UsesRtpHeader(false, codec_info_sbc));
  EXPECT_TRUE(A2D_UsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2D_UsesRtpHeader(false, codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2d_codec_index_str) {
  // Explicit tests for known codecs
  EXPECT_STREQ(A2D_CodecSepIndexStr(A2D_CODEC_SEP_INDEX_SBC), "SBC");
  EXPECT_STREQ(A2D_CodecSepIndexStr(A2D_CODEC_SEP_INDEX_SBC_SINK), "SBC SINK");

  // Test that the unknown codec string has not changed
  EXPECT_STREQ(A2D_CodecSepIndexStr(A2D_CODEC_SEP_INDEX_MAX),
               "UNKNOWN CODEC SEP INDEX");

  // Test that each codec has a known string
  for (int i = 0; i < A2D_CODEC_SEP_INDEX_MAX; i++) {
    tA2D_CODEC_SEP_INDEX codec_sep_index = static_cast<tA2D_CODEC_SEP_INDEX>(i);
    EXPECT_STRNE(A2D_CodecSepIndexStr(codec_sep_index),
                 "UNKNOWN CODEC SEP INDEX");
  }
}

TEST(StackA2dpTest, test_a2d_vendor) {
  EXPECT_FALSE(A2D_IsVendorSourceCodecSupported(codec_info_non_a2dp));
  EXPECT_EQ(A2D_VendorCodecGetVendorId(codec_info_non_a2dp),
              (uint32_t)0x00000403);
  EXPECT_EQ(A2D_VendorCodecGetCodecId(codec_info_non_a2dp), (uint16_t)0x0807);
  EXPECT_TRUE(A2D_VendorUsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2D_VendorUsesRtpHeader(false, codec_info_non_a2dp));
}
