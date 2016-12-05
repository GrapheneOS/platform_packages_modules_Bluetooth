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

#include "stack/include/a2dp_api.h"
#include "stack/include/a2dp_codec_api.h"
#include "stack/include/a2dp_sbc.h"
#include "stack/include/a2dp_vendor.h"

// TODO(jpawlowski): remove once weird dependency in hci_layer.cc is removed
#include <hardware/bluetooth.h>
bt_bdaddr_t btif_local_bd_addr;

namespace {
const uint8_t codec_info_sbc[AVDT_CODEC_SIZE] = {
    6,                   // Length (A2DP_SBC_INFO_LEN)
    0,                   // Media Type: AVDT_MEDIA_TYPE_AUDIO
    0,                   // Media Codec Type: A2DP_MEDIA_CT_SBC
    0x20 | 0x01,         // Sample Frequency: A2DP_SBC_IE_SAMP_FREQ_44 |
                         // Channel Mode: A2DP_SBC_IE_CH_MD_JOINT
    0x10 | 0x04 | 0x01,  // Block Length: A2DP_SBC_IE_BLOCKS_16 |
                         // Subbands: A2DP_SBC_IE_SUBBAND_8 |
                         // Allocation Method: A2DP_SBC_IE_ALLOC_MD_L
    2,                   // MinimumBitpool Value: A2DP_SBC_IE_MIN_BITPOOL
    53,                  // Maximum Bitpool Value: A2DP_SBC_MAX_BITPOOL
    7,                   // Dummy
    8,                   // Dummy
    9                    // Dummy
};

const uint8_t codec_info_sbc_sink_capability[AVDT_CODEC_SIZE] = {
    6,             // Length (A2DP_SBC_INFO_LEN)
    0,             // Media Type: AVDT_MEDIA_TYPE_AUDIO
    0,             // Media Codec Type: A2DP_MEDIA_CT_SBC
    0x20 | 0x10 |  // Sample Frequency: A2DP_SBC_IE_SAMP_FREQ_44 |
                   // A2DP_SBC_IE_SAMP_FREQ_48 |
        0x08 | 0x04 | 0x02 | 0x01,  // Channel Mode: A2DP_SBC_IE_CH_MD_MONO |
                                    // A2DP_SBC_IE_CH_MD_DUAL |
                                    // A2DP_SBC_IE_CH_MD_STEREO |
                                    // A2DP_SBC_IE_CH_MD_JOINT
    0x80 | 0x40 | 0x20 | 0x10 |     // Block Length: A2DP_SBC_IE_BLOCKS_4 |
                                    // A2DP_SBC_IE_BLOCKS_8 |
                                    // A2DP_SBC_IE_BLOCKS_12 |
                                    // A2DP_SBC_IE_BLOCKS_16 |
        0x08 | 0x04 |               // Subbands: A2DP_SBC_IE_SUBBAND_4 |
                                    // A2DP_SBC_IE_SUBBAND_8 |
        0x02 | 0x01,  // Allocation Method: A2DP_SBC_IE_ALLOC_MD_S |
                      // A2DP_SBC_IE_ALLOC_MD_L
    2,                // MinimumBitpool Value: A2DP_SBC_IE_MIN_BITPOOL
    53,               // Maximum Bitpool Value: A2DP_SBC_MAX_BITPOOL
    7,                // Dummy
    8,                // Dummy
    9                 // Dummy
};

const uint8_t codec_info_non_a2dp[AVDT_CODEC_SIZE] = {
    8,              // Length
    0,              // Media Type: AVDT_MEDIA_TYPE_AUDIO
    0xFF,           // Media Codec Type: A2DP_MEDIA_CT_NON_A2DP
    3,    4, 0, 0,  // Vendor ID: LSB first, upper two octets should be 0
    7,    8,        // Codec ID: LSB first
    9               // Dummy
};

const uint8_t codec_info_non_a2dp_dummy[AVDT_CODEC_SIZE] = {
    8,              // Length
    0,              // Media Type: AVDT_MEDIA_TYPE_AUDIO
    0xFF,           // Media Codec Type: A2DP_MEDIA_CT_NON_A2DP
    3,    4, 0, 0,  // Vendor ID: LSB first, upper two octets should be 0
    7,    8,        // Codec ID: LSB first
    10              // Dummy
};

}  // namespace

TEST(StackA2dpTest, test_a2dp_bits_set) {
  EXPECT_TRUE(A2DP_BitsSet(0x0) == A2DP_SET_ZERO_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x1) == A2DP_SET_ONE_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x2) == A2DP_SET_ONE_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x3) == A2DP_SET_MULTL_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x7f) == A2DP_SET_MULTL_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x80) == A2DP_SET_ONE_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0x81) == A2DP_SET_MULTL_BIT);
  EXPECT_TRUE(A2DP_BitsSet(0xff) == A2DP_SET_MULTL_BIT);
}

TEST(StackA2dpTest, test_a2dp_is_codec_valid) {
  EXPECT_TRUE(A2DP_IsSourceCodecValid(codec_info_sbc));
  EXPECT_TRUE(A2DP_IsPeerSourceCodecValid(codec_info_sbc));

  EXPECT_TRUE(A2DP_IsSinkCodecValid(codec_info_sbc_sink_capability));
  EXPECT_TRUE(A2DP_IsPeerSinkCodecValid(codec_info_sbc_sink_capability));

  EXPECT_FALSE(A2DP_IsSourceCodecValid(codec_info_non_a2dp));
  EXPECT_FALSE(A2DP_IsSinkCodecValid(codec_info_non_a2dp));
  EXPECT_FALSE(A2DP_IsPeerSourceCodecValid(codec_info_non_a2dp));
  EXPECT_FALSE(A2DP_IsPeerSinkCodecValid(codec_info_non_a2dp));

  // Test with invalid SBC codecs
  uint8_t codec_info_sbc_invalid[AVDT_CODEC_SIZE];
  memset(codec_info_sbc_invalid, 0, sizeof(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsSinkCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSinkCodecValid(codec_info_sbc_invalid));

  memcpy(codec_info_sbc_invalid, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_invalid[0] = 0;  // Corrupt the Length field
  EXPECT_FALSE(A2DP_IsSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsSinkCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSinkCodecValid(codec_info_sbc_invalid));

  memcpy(codec_info_sbc_invalid, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_invalid[1] = 0xff;  // Corrupt the Media Type field
  EXPECT_FALSE(A2DP_IsSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsSinkCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSourceCodecValid(codec_info_sbc_invalid));
  EXPECT_FALSE(A2DP_IsPeerSinkCodecValid(codec_info_sbc_invalid));
}

TEST(StackA2dpTest, test_a2dp_get_codec_type) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(codec_info_sbc);
  EXPECT_EQ(codec_type, A2DP_MEDIA_CT_SBC);

  codec_type = A2DP_GetCodecType(codec_info_non_a2dp);
  EXPECT_EQ(codec_type, A2DP_MEDIA_CT_NON_A2DP);
}

TEST(StackA2dpTest, test_a2dp_is_sink_codec_supported) {
  EXPECT_TRUE(A2DP_IsSinkCodecSupported(codec_info_sbc));
  EXPECT_FALSE(A2DP_IsSinkCodecSupported(codec_info_sbc_sink_capability));
  EXPECT_FALSE(A2DP_IsSinkCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2dp_is_peer_source_codec_supported) {
  EXPECT_TRUE(A2DP_IsPeerSourceCodecSupported(codec_info_sbc));
  EXPECT_TRUE(A2DP_IsPeerSourceCodecSupported(codec_info_sbc_sink_capability));
  EXPECT_FALSE(A2DP_IsPeerSourceCodecSupported(codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_init_default_codec) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];

  memset(codec_info_result, 0, sizeof(codec_info_result));
  A2DP_InitDefaultCodec(codec_info_result);

  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }
}

TEST(StackA2dpTest, test_build_src2sink_config) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];

  memset(codec_info_result, 0, sizeof(codec_info_result));
  EXPECT_EQ(A2DP_BuildSrc2SinkConfig(codec_info_sbc, codec_info_result),
            A2DP_SUCCESS);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Include extra (less preferred) capabilities and test again
  uint8_t codec_info_sbc_test1[AVDT_CODEC_SIZE];
  memcpy(codec_info_sbc_test1, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test1[3] |= (A2DP_SBC_IE_CH_MD_STEREO |
                              A2DP_SBC_IE_CH_MD_DUAL | A2DP_SBC_IE_CH_MD_MONO);
  codec_info_sbc_test1[4] |=
      (A2DP_SBC_IE_BLOCKS_12 | A2DP_SBC_IE_BLOCKS_8 | A2DP_SBC_IE_BLOCKS_4);
  codec_info_sbc_test1[4] |= A2DP_SBC_IE_SUBBAND_4;
  codec_info_sbc_test1[4] |= A2DP_SBC_IE_ALLOC_MD_S;
  memset(codec_info_result, 0, sizeof(codec_info_result));
  EXPECT_EQ(A2DP_BuildSrc2SinkConfig(codec_info_sbc_test1, codec_info_result),
            A2DP_SUCCESS);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Test invalid codec info
  memset(codec_info_result, 0, sizeof(codec_info_result));
  memset(codec_info_sbc_test1, 0, sizeof(codec_info_sbc_test1));
  EXPECT_NE(A2DP_BuildSrc2SinkConfig(codec_info_sbc_test1, codec_info_result),
            A2DP_SUCCESS);
}

TEST(StackA2dpTest, test_a2dp_uses_rtp_header) {
  EXPECT_TRUE(A2DP_UsesRtpHeader(true, codec_info_sbc));
  EXPECT_TRUE(A2DP_UsesRtpHeader(false, codec_info_sbc));
  EXPECT_TRUE(A2DP_UsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2DP_UsesRtpHeader(false, codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2dp_get_media_type) {
  uint8_t codec_info_test[AVDT_CODEC_SIZE];

  EXPECT_EQ(A2DP_GetMediaType(codec_info_sbc), AVDT_MEDIA_TYPE_AUDIO);
  EXPECT_EQ(A2DP_GetMediaType(codec_info_non_a2dp), AVDT_MEDIA_TYPE_AUDIO);

  // Prepare dummy codec info for video and for multimedia
  memset(codec_info_test, 0, sizeof(codec_info_test));
  codec_info_test[0] = sizeof(codec_info_test);
  codec_info_test[1] = 0x01 << 4;
  EXPECT_EQ(A2DP_GetMediaType(codec_info_test), AVDT_MEDIA_TYPE_VIDEO);
  codec_info_test[1] = 0x02 << 4;
  EXPECT_EQ(A2DP_GetMediaType(codec_info_test), AVDT_MEDIA_TYPE_MULTI);
}

TEST(StackA2dpTest, test_a2dp_codec_name) {
  uint8_t codec_info_test[AVDT_CODEC_SIZE];

  // Explicit tests for known codecs
  EXPECT_STREQ(A2DP_CodecName(codec_info_sbc), "SBC");
  EXPECT_STREQ(A2DP_CodecName(codec_info_sbc_sink_capability), "SBC");
  EXPECT_STREQ(A2DP_CodecName(codec_info_non_a2dp), "UNKNOWN VENDOR CODEC");

  // Test all unknown codecs
  memcpy(codec_info_test, codec_info_sbc, sizeof(codec_info_sbc));
  for (uint8_t codec_type = A2DP_MEDIA_CT_SBC + 1;
       codec_type < A2DP_MEDIA_CT_NON_A2DP; codec_type++) {
    codec_info_test[2] = codec_type;  // Unknown codec type
    EXPECT_STREQ(A2DP_CodecName(codec_info_test), "UNKNOWN CODEC");
  }
}

TEST(StackA2dpTest, test_a2dp_vendor) {
  EXPECT_EQ(A2DP_VendorCodecGetVendorId(codec_info_non_a2dp),
            (uint32_t)0x00000403);
  EXPECT_EQ(A2DP_VendorCodecGetCodecId(codec_info_non_a2dp), (uint16_t)0x0807);
  EXPECT_TRUE(A2DP_VendorUsesRtpHeader(true, codec_info_non_a2dp));
  EXPECT_TRUE(A2DP_VendorUsesRtpHeader(false, codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2dp_codec_type_equals) {
  EXPECT_TRUE(
      A2DP_CodecTypeEquals(codec_info_sbc, codec_info_sbc_sink_capability));
  EXPECT_TRUE(
      A2DP_CodecTypeEquals(codec_info_non_a2dp, codec_info_non_a2dp_dummy));
  EXPECT_FALSE(A2DP_CodecTypeEquals(codec_info_sbc, codec_info_non_a2dp));
}

TEST(StackA2dpTest, test_a2dp_codec_equals) {
  uint8_t codec_info_sbc_test[AVDT_CODEC_SIZE];
  uint8_t codec_info_non_a2dp_test[AVDT_CODEC_SIZE];

  // Test two identical SBC codecs
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  EXPECT_TRUE(A2DP_CodecEquals(codec_info_sbc, codec_info_sbc_test));

  // Test two identical non-A2DP codecs that are not recognized
  memset(codec_info_non_a2dp_test, 0xAB, sizeof(codec_info_non_a2dp_test));
  memcpy(codec_info_non_a2dp_test, codec_info_non_a2dp,
         sizeof(codec_info_non_a2dp));
  EXPECT_FALSE(A2DP_CodecEquals(codec_info_non_a2dp, codec_info_non_a2dp_test));

  // Test two codecs that have different types
  EXPECT_FALSE(A2DP_CodecEquals(codec_info_sbc, codec_info_non_a2dp));

  // Test two SBC codecs that are slightly different
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test[5] = codec_info_sbc[5] + 1;
  EXPECT_FALSE(A2DP_CodecEquals(codec_info_sbc, codec_info_sbc_test));
  codec_info_sbc_test[5] = codec_info_sbc[5];
  codec_info_sbc_test[6] = codec_info_sbc[6] + 1;
  EXPECT_FALSE(A2DP_CodecEquals(codec_info_sbc, codec_info_sbc_test));

  // Test two SBC codecs that are identical, but with different dummy
  // trailer data.
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test[7] = codec_info_sbc[7] + 1;
  EXPECT_TRUE(A2DP_CodecEquals(codec_info_sbc, codec_info_sbc_test));
}

TEST(StackA2dpTest, test_a2dp_get_track_sample_rate) {
  EXPECT_EQ(A2DP_GetTrackSampleRate(codec_info_sbc), 44100);
  EXPECT_EQ(A2DP_GetTrackSampleRate(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_track_bits_per_sample) {
  EXPECT_EQ(A2DP_GetTrackBitsPerSample(codec_info_sbc), 16);
  EXPECT_EQ(A2DP_GetTrackBitsPerSample(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_track_channel_count) {
  EXPECT_EQ(A2DP_GetTrackChannelCount(codec_info_sbc), 2);
  EXPECT_EQ(A2DP_GetTrackChannelCount(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_number_of_subbands_sbc) {
  EXPECT_EQ(A2DP_GetNumberOfSubbandsSbc(codec_info_sbc), 8);
  EXPECT_EQ(A2DP_GetNumberOfSubbandsSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_number_of_blocks_sbc) {
  EXPECT_EQ(A2DP_GetNumberOfBlocksSbc(codec_info_sbc), 16);
  EXPECT_EQ(A2DP_GetNumberOfBlocksSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_allocation_method_code_sbc) {
  EXPECT_EQ(A2DP_GetAllocationMethodCodeSbc(codec_info_sbc), 0);
  EXPECT_EQ(A2DP_GetAllocationMethodCodeSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_channel_mode_code_sbc) {
  EXPECT_EQ(A2DP_GetChannelModeCodeSbc(codec_info_sbc), 3);
  EXPECT_EQ(A2DP_GetChannelModeCodeSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_sampling_frequency_code_sbc) {
  EXPECT_EQ(A2DP_GetSamplingFrequencyCodeSbc(codec_info_sbc), 2);
  EXPECT_EQ(A2DP_GetSamplingFrequencyCodeSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_min_bitpool_sbc) {
  EXPECT_EQ(A2DP_GetMinBitpoolSbc(codec_info_sbc), 2);
  EXPECT_EQ(A2DP_GetMinBitpoolSbc(codec_info_sbc_sink_capability), 2);
  EXPECT_EQ(A2DP_GetMinBitpoolSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_max_bitpool_sbc) {
  EXPECT_EQ(A2DP_GetMaxBitpoolSbc(codec_info_sbc), 53);
  EXPECT_EQ(A2DP_GetMaxBitpoolSbc(codec_info_sbc_sink_capability), 53);
  EXPECT_EQ(A2DP_GetMaxBitpoolSbc(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_sink_track_channel_type) {
  EXPECT_EQ(A2DP_GetSinkTrackChannelType(codec_info_sbc), 3);
  EXPECT_EQ(A2DP_GetSinkTrackChannelType(codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_sink_frames_count_to_process) {
  EXPECT_EQ(A2DP_GetSinkFramesCountToProcess(20, codec_info_sbc), 7);
  EXPECT_EQ(A2DP_GetSinkFramesCountToProcess(20, codec_info_non_a2dp), -1);
}

TEST(StackA2dpTest, test_a2dp_get_packet_timestamp) {
  uint8_t a2dp_data[1000];
  uint32_t timestamp;
  uint32_t* p_ts = reinterpret_cast<uint32_t*>(a2dp_data);

  memset(a2dp_data, 0xAB, sizeof(a2dp_data));
  *p_ts = 0x12345678;
  timestamp = 0xFFFFFFFF;
  EXPECT_TRUE(A2DP_GetPacketTimestamp(codec_info_sbc, a2dp_data, &timestamp));
  EXPECT_EQ(timestamp, static_cast<uint32_t>(0x12345678));

  memset(a2dp_data, 0xAB, sizeof(a2dp_data));
  *p_ts = 0x12345678;
  timestamp = 0xFFFFFFFF;
  EXPECT_FALSE(
      A2DP_GetPacketTimestamp(codec_info_non_a2dp, a2dp_data, &timestamp));
}

TEST(StackA2dpTest, test_a2dp_build_codec_header) {
  uint8_t a2dp_data[1000];
  BT_HDR* p_buf = reinterpret_cast<BT_HDR*>(a2dp_data);
  const uint16_t BT_HDR_LEN = 500;
  const uint16_t BT_HDR_OFFSET = 50;
  const uint8_t FRAMES_PER_PACKET = 0xCD;

  memset(a2dp_data, 0xAB, sizeof(a2dp_data));
  p_buf->len = BT_HDR_LEN;
  p_buf->offset = BT_HDR_OFFSET;
  EXPECT_TRUE(A2DP_BuildCodecHeader(codec_info_sbc, p_buf, FRAMES_PER_PACKET));
  EXPECT_EQ(p_buf->offset + 1,
            BT_HDR_OFFSET);               // Modified by A2DP_SBC_MPL_HDR_LEN
  EXPECT_EQ(p_buf->len - 1, BT_HDR_LEN);  // Modified by A2DP_SBC_MPL_HDR_LEN
  const uint8_t* p =
      reinterpret_cast<const uint8_t*>(p_buf + 1) + p_buf->offset;
  EXPECT_EQ(
      *p, static_cast<uint8_t>(0x0D));  // 0xCD masked with A2DP_SBC_HDR_NUM_MSK

  memset(a2dp_data, 0xAB, sizeof(a2dp_data));
  p_buf->len = BT_HDR_LEN;
  p_buf->offset = BT_HDR_OFFSET;
  EXPECT_FALSE(
      A2DP_BuildCodecHeader(codec_info_non_a2dp, p_buf, FRAMES_PER_PACKET));
}

TEST(StackA2dpTest, test_a2dp_adjust_codec) {
  uint8_t codec_info_sbc_test[AVDT_CODEC_SIZE];
  uint8_t codec_info_non_a2dp_test[AVDT_CODEC_SIZE];

  // Test updating a valid SBC codec that doesn't need adjustment
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  EXPECT_TRUE(A2DP_AdjustCodec(codec_info_sbc_test));
  EXPECT_TRUE(
      memcmp(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc)) == 0);

  // Test updating a valid SBC codec that needs adjustment
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test[6] = 54;  // A2DP_SBC_MAX_BITPOOL + 1
  EXPECT_TRUE(A2DP_AdjustCodec(codec_info_sbc_test));
  EXPECT_TRUE(
      memcmp(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc)) == 0);

  // Test updating an invalid SBC codec
  memset(codec_info_sbc_test, 0xAB, sizeof(codec_info_sbc_test));
  memcpy(codec_info_sbc_test, codec_info_sbc, sizeof(codec_info_sbc));
  codec_info_sbc_test[6] = 255;  // Invalid MAX_BITPOOL
  EXPECT_FALSE(A2DP_AdjustCodec(codec_info_sbc_test));

  // Test updating a non-A2DP codec that is not recognized
  memset(codec_info_non_a2dp_test, 0xAB, sizeof(codec_info_non_a2dp_test));
  memcpy(codec_info_non_a2dp_test, codec_info_non_a2dp,
         sizeof(codec_info_non_a2dp));
  EXPECT_FALSE(A2DP_AdjustCodec(codec_info_non_a2dp_test));
}

TEST(StackA2dpTest, test_a2dp_source_codec_index) {
  // Explicit tests for known codecs
  EXPECT_EQ(A2DP_SourceCodecIndex(codec_info_sbc),
            BTAV_A2DP_CODEC_INDEX_SOURCE_SBC);
  EXPECT_EQ(A2DP_SourceCodecIndex(codec_info_sbc_sink_capability),
            BTAV_A2DP_CODEC_INDEX_SOURCE_SBC);
  EXPECT_EQ(A2DP_SourceCodecIndex(codec_info_non_a2dp),
            BTAV_A2DP_CODEC_INDEX_MAX);
}

TEST(StackA2dpTest, test_a2dp_codec_index_str) {
  // Explicit tests for known codecs
  EXPECT_STREQ(A2DP_CodecIndexStr(BTAV_A2DP_CODEC_INDEX_SOURCE_SBC), "SBC");
  EXPECT_STREQ(A2DP_CodecIndexStr(BTAV_A2DP_CODEC_INDEX_SINK_SBC), "SBC SINK");

  // Test that the unknown codec string has not changed
  EXPECT_STREQ(A2DP_CodecIndexStr(BTAV_A2DP_CODEC_INDEX_MAX),
               "UNKNOWN CODEC INDEX");

  // Test that each codec has a known string
  for (int i = 0; i < BTAV_A2DP_CODEC_INDEX_MAX; i++) {
    btav_a2dp_codec_index_t codec_index =
        static_cast<btav_a2dp_codec_index_t>(i);
    EXPECT_STRNE(A2DP_CodecIndexStr(codec_index), "UNKNOWN CODEC INDEX");
  }
}

TEST(StackA2dpTest, test_a2dp_init_codec_config) {
  tAVDT_CFG avdt_cfg;

  //
  // Test for SBC Source
  //
  memset(&avdt_cfg, 0, sizeof(avdt_cfg));
  EXPECT_TRUE(
      A2DP_InitCodecConfig(BTAV_A2DP_CODEC_INDEX_SOURCE_SBC, &avdt_cfg));
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(avdt_cfg.codec_info[i], codec_info_sbc[i]);
  }
// Test for content protection
#if (BTA_AV_CO_CP_SCMS_T == TRUE)
  EXPECT_EQ(avdt_cfg.protect_info[0], AVDT_CP_LOSC);
  EXPECT_EQ(avdt_cfg.protect_info[1], (AVDT_CP_SCMS_T_ID & 0xFF));
  EXPECT_EQ(avdt_cfg.protect_info[2], ((AVDT_CP_SCMS_T_ID >> 8) & 0xFF));
  EXPECT_EQ(avdt_cfg.num_protect, 1);
#endif

  //
  // Test for SBC Sink
  //
  memset(&avdt_cfg, 0, sizeof(avdt_cfg));
  EXPECT_TRUE(A2DP_InitCodecConfig(BTAV_A2DP_CODEC_INDEX_SINK_SBC, &avdt_cfg));
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc_sink_capability[0] + 1; i++) {
    EXPECT_EQ(avdt_cfg.codec_info[i], codec_info_sbc_sink_capability[i]);
  }
}

TEST(A2dpCodecConfig, createCodec) {
  for (int i = 0; i < BTAV_A2DP_CODEC_INDEX_MAX; i++) {
    btav_a2dp_codec_index_t codec_index =
        static_cast<btav_a2dp_codec_index_t>(i);
    A2dpCodecConfig* codec_config = A2dpCodecConfig::createCodec(codec_index);
    EXPECT_NE(codec_config, nullptr);
    EXPECT_EQ(codec_config->codecIndex(), codec_index);
    EXPECT_FALSE(codec_config->name().empty());
    EXPECT_GT(codec_config->codecPriority(), 0U);
    delete codec_config;
  }
}

TEST(A2dpCodecConfig, setCodecConfig) {
  uint8_t codec_info_result[AVDT_CODEC_SIZE];
  btav_a2dp_codec_index_t peer_codec_index;
  A2dpCodecs* a2dp_codecs = new A2dpCodecs();
  A2dpCodecConfig* codec_config;

  EXPECT_TRUE(a2dp_codecs->init());

  // Create the codec capability
  memset(codec_info_result, 0, sizeof(codec_info_result));
  peer_codec_index = A2DP_SourceCodecIndex(codec_info_sbc_sink_capability);
  EXPECT_NE(peer_codec_index, BTAV_A2DP_CODEC_INDEX_MAX);
  codec_config =
      a2dp_codecs->findSourceCodecConfig(codec_info_sbc_sink_capability);
  EXPECT_NE(codec_config, nullptr);
  EXPECT_TRUE(a2dp_codecs->setCodecConfig(codec_info_sbc_sink_capability, true,
                                          codec_info_result));
  EXPECT_EQ(a2dp_codecs->getCurrentCodecConfig(), codec_config);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Create the codec config
  memset(codec_info_result, 0, sizeof(codec_info_result));
  peer_codec_index = A2DP_SourceCodecIndex(codec_info_sbc);
  EXPECT_NE(peer_codec_index, BTAV_A2DP_CODEC_INDEX_MAX);
  codec_config = a2dp_codecs->findSourceCodecConfig(codec_info_sbc);
  EXPECT_NE(codec_config, nullptr);
  EXPECT_TRUE(
      a2dp_codecs->setCodecConfig(codec_info_sbc, false, codec_info_result));
  EXPECT_EQ(a2dp_codecs->getCurrentCodecConfig(), codec_config);
  // Compare the result codec with the local test codec info
  for (size_t i = 0; i < codec_info_sbc[0] + 1; i++) {
    EXPECT_EQ(codec_info_result[i], codec_info_sbc[i]);
  }

  // Test invalid codec info
  uint8_t codec_info_sbc_test1[AVDT_CODEC_SIZE];
  memset(codec_info_result, 0, sizeof(codec_info_result));
  memset(codec_info_sbc_test1, 0, sizeof(codec_info_sbc_test1));
  EXPECT_FALSE(a2dp_codecs->setCodecConfig(codec_info_sbc_test1, true,
                                           codec_info_result));
  delete a2dp_codecs;
}

TEST(A2dpCodecs, init) {
  A2dpCodecs codecs;

  EXPECT_TRUE(codecs.init());

  const std::list<A2dpCodecConfig*> orderedSourceCodecs =
      codecs.orderedSourceCodecs();
  EXPECT_FALSE(orderedSourceCodecs.empty());

  const std::list<A2dpCodecConfig*> orderedSinkCodecs =
      codecs.orderedSinkCodecs();
  EXPECT_FALSE(orderedSinkCodecs.empty());
}
