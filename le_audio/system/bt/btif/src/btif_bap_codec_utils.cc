/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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


#include "bta_closure_api.h"
#include "bta_bap_uclient_api.h"
#include "btif_common.h"
#include "btif_storage.h"
#include "osi/include/thread.h"

// Capabilities to be stored on CodecConfig structure :
// Supported_Sampling_Frequencies  ( codec config sampling rate )
// Audio_Channel_Counts ( codec config channel mode )
// Supported_Frame_Durations ( 1st byte of codec specific 1 ) 
// Max_Supported_LC3_Frames_Per_SDU  ( 2nd byte of codec specific 1)
// Preferred_Audio_Contexts ( 3&4 bytes of codec specific 1 )
// Supported_Octets_Per_Codec_Frame ( first 4 bytes codec specific 2 )
/* Vendor_Specific Metadata ( first 4 bytes of codec specific 3)
 *    1st byte conveys LC3Q support,
 *    2nd byte conveys LC3Q version
 */

// Configurations to be stored in CodecConfig structure :
// Sampling_Frequency  ( codec config sampling rate )
// Audio_Channel_Allocation ( codec config channel mode )
// Frame_Duration  ( 5th bye of codec specific 1 ) 
// LC3_Blocks_Per_SDU ( 6th byte of codec specific 1 )
// Preferred_Audio_Contexts ( 7&8 bytes of codec specific 1 )
// Octets_Per_Codec_Frame ( 2 bytes  )  ( 5&6th bytes of codec specific 2 )
// LC3Q preferred (1 byte)  ( 7th byte of codec specific 2 )
/* Vendor_Specific Metadata ( first 4 bytes of codec specific 3)
 *    1st byte conveys LC3Q support,
 *    2nd byte conveys LC3Q version
 */

#include <base/logging.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_pacs_client.h>

using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::CodecChannelMode;

constexpr uint8_t  CAPA_SUP_FRAME_DUR_INDEX           = 0x00; // CS1
constexpr uint8_t  CAPA_MAX_SUP_LC3_FRAMES_INDEX      = 0x01; // CS1
constexpr uint8_t  CAPA_PREF_AUDIO_CONT_INDEX         = 0x02; // CS1
constexpr uint8_t  CAPA_SUP_OCTS_PER_FRAME_INDEX      = 0x00; // CS2

constexpr uint8_t  CAPA_VENDOR_METADATA_LC3Q_PREF_INDEX = 0x00; // CS3
constexpr uint8_t  CAPA_VENDOR_METADATA_LC3Q_VER_INDEX  = 0x01; // CS3

constexpr uint8_t  CONFIG_FRAME_DUR_INDEX           = 0x04; // CS1
constexpr uint8_t  CONFIG_LC3_BLOCKS_INDEX          = 0x05; // CS1
constexpr uint8_t  CONFIG_PREF_AUDIO_CONT_INDEX     = 0x06; // CS1
constexpr uint8_t  CONFIG_OCTS_PER_FRAME_INDEX      = 0x04; // CS2
constexpr uint8_t  CONFIG_LC3Q_PREF_INDEX           = 0x06; // CS2
constexpr uint8_t  CONFIG_VENDOR_METADATA_LC3Q_PREF_INDEX = 0x00; // CS3
constexpr uint8_t  CONFIG_VENDOR_METADATA_LC3Q_VER_INDEX  = 0x01; // CS3

// capabilities
bool UpdateCapaSupFrameDurations(CodecConfig *config , uint8_t sup_frame) {
  config->codec_specific_1 &= ~(0xFF << (CAPA_SUP_FRAME_DUR_INDEX * 8));
  config->codec_specific_1 |= sup_frame << (CAPA_SUP_FRAME_DUR_INDEX * 8);
  return true;
}

bool UpdateCapaMaxSupLc3Frames(CodecConfig *config,
                                uint8_t max_sup_lc3_frames) {
  config->codec_specific_1 &= ~(0xFF << (CAPA_MAX_SUP_LC3_FRAMES_INDEX * 8));
  config->codec_specific_1 |= max_sup_lc3_frames <<
                               (CAPA_MAX_SUP_LC3_FRAMES_INDEX * 8);
  return true;
}

bool UpdateCapaPreferredContexts(CodecConfig *config, uint16_t contexts) {
  config->codec_specific_1 &= ~(0xFFFF << (CAPA_PREF_AUDIO_CONT_INDEX * 8));
  config->codec_specific_1 |= contexts << (CAPA_PREF_AUDIO_CONT_INDEX * 8);
  return true;
}

bool UpdateCapaSupOctsPerFrame(CodecConfig *config,
                              uint32_t octs_per_frame) {
  config->codec_specific_2 &= ~(0xFFFFFFFF <<
                          (CAPA_SUP_OCTS_PER_FRAME_INDEX * 8));
  config->codec_specific_2 |= octs_per_frame <<
                              (CAPA_SUP_OCTS_PER_FRAME_INDEX * 8);
  return true;
}

bool UpdateCapaVendorMetaDataLc3QPref(CodecConfig *config, bool lc3q_pref) {
  config->codec_specific_3 &= ~(0xFF << (CAPA_VENDOR_METADATA_LC3Q_PREF_INDEX * 8));
  config->codec_specific_3 |= lc3q_pref << (CAPA_VENDOR_METADATA_LC3Q_PREF_INDEX * 8);
  return true;
}

bool UpdateCapaVendorMetaDataLc3QVer(CodecConfig *config, uint8_t lc3q_ver) {
  config->codec_specific_3 &= ~(0xFF << (CAPA_VENDOR_METADATA_LC3Q_VER_INDEX * 8));
  config->codec_specific_3 |= lc3q_ver << (CAPA_VENDOR_METADATA_LC3Q_VER_INDEX * 8);
  return true;
}

uint8_t GetCapaSupFrameDurations(CodecConfig *config) {
  return (config->codec_specific_1 >> (8*CAPA_SUP_FRAME_DUR_INDEX)) & 0xff;
}

uint8_t GetCapaMaxSupLc3Frames(CodecConfig *config) {
  if (((config->codec_specific_1 >>
                (8*CAPA_MAX_SUP_LC3_FRAMES_INDEX)) & 0xff) == 0x0) {
    uint8_t max_chnl_count = 0;
    LOG(ERROR) << __func__
               << ": Max Sup LC3 frames is 0, deriving based on chnl count";
    if(static_cast<uint16_t> (config->channel_mode) &
       static_cast<uint16_t> (CodecChannelMode::CODEC_CHANNEL_MODE_STEREO)) {
      max_chnl_count = 2;
    } else if(static_cast<uint16_t> (config->channel_mode) &
           static_cast<uint16_t> (CodecChannelMode::CODEC_CHANNEL_MODE_MONO)) {
      max_chnl_count = 1;
    }
    return max_chnl_count;
  } else {
    return (config->codec_specific_1 >>
               (8*CAPA_MAX_SUP_LC3_FRAMES_INDEX)) & 0xff;
  }
}

uint16_t GetCapaPreferredContexts(CodecConfig *config) {
  return (config->codec_specific_1 >>
                (8*CAPA_PREF_AUDIO_CONT_INDEX)) & 0xffff;
}

uint32_t GetCapaSupOctsPerFrame(CodecConfig *config) {
  return (config->codec_specific_2 >>
                (8*CAPA_SUP_OCTS_PER_FRAME_INDEX)) & 0xffffffff;
}

bool GetCapaVendorMetaDataLc3QPref(CodecConfig *config) {
  if (((config->codec_specific_3 >>
        (8*CAPA_VENDOR_METADATA_LC3Q_PREF_INDEX)) & 0xff) == 0x0) {
    return false;
  } else
    return true;
}

uint8_t GetCapaVendorMetaDataLc3QVer(CodecConfig *config) {
  return (config->codec_specific_3 >>
                (8*CAPA_VENDOR_METADATA_LC3Q_VER_INDEX)) & 0xff;
}

// Configurations
bool UpdateFrameDuration(CodecConfig *config , uint8_t frame_dur) {
  uint64_t value = 0xFF;
  config->codec_specific_1 &= ~(value << (CONFIG_FRAME_DUR_INDEX*8));
  config->codec_specific_1 |=  static_cast<uint64_t>(frame_dur)  <<
                               (CONFIG_FRAME_DUR_INDEX * 8);
  return true;
}

bool UpdateLc3BlocksPerSdu(CodecConfig *config, uint8_t lc3_blocks_per_sdu) {
  uint64_t value = 0xFF;
  config->codec_specific_1 &= ~(value << (CONFIG_LC3_BLOCKS_INDEX * 8));
  config->codec_specific_1 |=  static_cast<uint64_t>(lc3_blocks_per_sdu) <<
                               (CONFIG_LC3_BLOCKS_INDEX * 8);
  return true;
}

bool UpdatePreferredAudioContext(CodecConfig *config ,
                                    uint16_t pref_audio_context) {
  uint64_t value = 0xFFFF;
  config->codec_specific_1 &= ~(value << (CONFIG_PREF_AUDIO_CONT_INDEX*8));
  config->codec_specific_1 |=  static_cast<uint64_t>(pref_audio_context) <<
                               (CONFIG_PREF_AUDIO_CONT_INDEX * 8);
  return true;
}

bool UpdateOctsPerFrame(CodecConfig *config , uint16_t octs_per_frame) {
  uint64_t value = 0xFFFF;
  config->codec_specific_2 &= ~(value << (CONFIG_OCTS_PER_FRAME_INDEX * 8));
  config->codec_specific_2 |=
                    static_cast<uint64_t>(octs_per_frame) <<
                    (CONFIG_OCTS_PER_FRAME_INDEX * 8);
  return true;
}

bool UpdateLc3QPreference(CodecConfig *config , bool lc3q_pref) {
  uint64_t value = 0xFF;
  config->codec_specific_2 &= ~(value << (CONFIG_LC3Q_PREF_INDEX * 8));
  config->codec_specific_2 |=
                    static_cast<uint64_t>(lc3q_pref) <<
                    (CONFIG_LC3Q_PREF_INDEX * 8);
  LOG(WARNING) << __func__
               << ": lc3q_pref cs2: " << loghex(config->codec_specific_2);
  return true;
}


bool UpdateVendorMetaDataLc3QPref(CodecConfig *config, bool lc3q_pref) {
  uint64_t value = 0xFF;
  config->codec_specific_3 &= ~(value << (CONFIG_VENDOR_METADATA_LC3Q_PREF_INDEX * 8));
  config->codec_specific_3 |= static_cast<uint64_t>(lc3q_pref) <<
                                (CONFIG_VENDOR_METADATA_LC3Q_PREF_INDEX * 8);
  return true;
}

bool UpdateVendorMetaDataLc3QVer(CodecConfig *config, uint8_t lc3q_ver) {
  uint64_t value = 0xFF;
  config->codec_specific_3 &= ~(value << (CONFIG_VENDOR_METADATA_LC3Q_VER_INDEX * 8));
  config->codec_specific_3 |= static_cast<uint64_t>(lc3q_ver) <<
                                  (CONFIG_VENDOR_METADATA_LC3Q_VER_INDEX * 8);
  return true;
}

uint8_t GetFrameDuration(CodecConfig *config) {
  return (config->codec_specific_1 >> (8*CONFIG_FRAME_DUR_INDEX)) & 0xff;
}

uint8_t GetLc3BlocksPerSdu(CodecConfig *config) {
  return (config->codec_specific_1 >> (8*CONFIG_LC3_BLOCKS_INDEX)) & 0xff;
}

uint16_t GetPreferredAudioContext(CodecConfig *config) {
  return (config->codec_specific_1 >>
                    (8*CONFIG_PREF_AUDIO_CONT_INDEX)) & 0xffff;
}

uint16_t GetOctsPerFrame(CodecConfig *config) {
  return (config->codec_specific_2 >> (8*CONFIG_OCTS_PER_FRAME_INDEX)) & 0xffff;
}

uint8_t GetLc3QPreference(CodecConfig *config) {
  LOG(WARNING) << __func__ << ": lc3q_pref cs2: "
      << loghex((config->codec_specific_2 >> (8*CONFIG_LC3Q_PREF_INDEX)) & 0xff);
  return (config->codec_specific_2 >>
                (8*CONFIG_LC3Q_PREF_INDEX)) & 0xff;
}

uint8_t GetVendorMetaDataLc3QPref(CodecConfig *config) {
  return (config->codec_specific_3 >>
                (8*CONFIG_VENDOR_METADATA_LC3Q_PREF_INDEX)) & 0xff;
}

uint8_t GetVendorMetaDataLc3QVer(CodecConfig *config) {
  return (config->codec_specific_3 >>
                (8*CONFIG_VENDOR_METADATA_LC3Q_VER_INDEX)) & 0xff;
}

bool IsCodecConfigEqual(CodecConfig *src_config, CodecConfig *dst_config) {
  // first check if passed codec configs are configurations or
  // capabilities using first byte of codec specific 1
  if(src_config == nullptr || dst_config == nullptr) {
    return false;
  }

  bool is_src_capability = src_config->codec_specific_1 & 0XFF;
  bool is_dst_capability = dst_config->codec_specific_1 & 0XFF;

  // check the codec type
  if(src_config->codec_type != dst_config->codec_type) {
    LOG(ERROR) << __func__ << ": No match for codec type ";
    return false;
  }

  // check sample rate
  if(src_config->sample_rate != dst_config->sample_rate) {
    LOG(ERROR) << __func__ << ": No match for sample rate";
    return false;
  }

  // check channel mode
  if(!(static_cast<int>(src_config->channel_mode) &
       static_cast<int>(dst_config->channel_mode))) {
    LOG(ERROR) << __func__ << ": No match for channel mode ";
    return false;
  }

  LOG(WARNING) << __func__
               << ": is_src_capability: " << loghex(is_src_capability)
               << ", is_dst_capability: " << loghex(is_dst_capability);

  if(is_src_capability && is_dst_capability) {
    if(src_config->codec_specific_1 != dst_config->codec_specific_1 ||
       src_config->codec_specific_2 != dst_config->codec_specific_2 ||
       src_config->codec_specific_3 != dst_config->codec_specific_3) {
      LOG(WARNING) << __func__ << ": No match for CS params. ";
      return false;
    }
  } else if (!is_src_capability && !is_dst_capability) {
    LOG(INFO) << __func__ << ": Comparison for both configs ";
    uint8_t src_frame_dur = GetFrameDuration(src_config);
    uint8_t src_lc3_blocks_per_sdu = GetLc3BlocksPerSdu(src_config);
    uint16_t src_octs_per_frame = GetOctsPerFrame(src_config);
    uint8_t src_lc3q_pref = GetLc3QPreference(src_config);
    uint16_t src_pref_audio_context = GetPreferredAudioContext(src_config);

    uint8_t dst_frame_dur = GetFrameDuration(dst_config);
    uint8_t dst_lc3_blocks_per_sdu = GetLc3BlocksPerSdu(dst_config);
    uint16_t dst_octs_per_frame = GetOctsPerFrame(dst_config);
    uint8_t dst_lc3q_pref = GetLc3QPreference(dst_config);
    uint16_t dst_pref_audio_context = GetPreferredAudioContext(dst_config);

    if(src_frame_dur != dst_frame_dur) {
      LOG(ERROR) << __func__ << ": Frame Dur not match with existing config ";
      return false;
    }

    if(src_lc3_blocks_per_sdu != dst_lc3_blocks_per_sdu) {
      LOG(ERROR) << __func__ << ": Lc3 blocks not match with existing config ";
      return false;
    }

    if(src_octs_per_frame != dst_octs_per_frame) {
      LOG(ERROR) << __func__ << ": Octs per frame not match with existing config ";
      return false;
    }

    if(src_lc3q_pref != dst_lc3q_pref) {
      LOG(ERROR) << __func__ << ": Lc3Q pref not match with existing config ";
      return false;
    }

    if (!(src_pref_audio_context & dst_pref_audio_context)) {
      LOG(ERROR) << __func__ << ": pref_audio_context not match with existing config ";
      return false;
    }

  } else if(is_src_capability || is_dst_capability) {
    CodecConfig *capa_config = is_src_capability ? src_config:dst_config;
    CodecConfig *oth_config = is_src_capability ? dst_config:src_config;

    uint8_t capa_sup_frames = GetCapaSupFrameDurations(capa_config);
    uint8_t capa_max_sup_lc3_frames = GetCapaMaxSupLc3Frames(capa_config);
    uint16_t capa_min_sup_octs = GetCapaSupOctsPerFrame(capa_config) & 0xFFFF;
    uint16_t capa_max_sup_octs = (GetCapaSupOctsPerFrame(capa_config)
                             & 0xFFFF0000) >> 16;
    bool capa_lc3q_pref = GetCapaVendorMetaDataLc3QPref(capa_config);
    uint16_t capa_pref_audio_context = GetCapaPreferredContexts(capa_config);

    uint8_t frame_dur = GetFrameDuration(oth_config);
    uint8_t lc3_blocks_per_sdu = GetLc3BlocksPerSdu(oth_config);
    uint16_t octs_per_frame = GetOctsPerFrame(oth_config);
    uint8_t lc3q_pref = GetLc3QPreference(oth_config);
    uint16_t dst_pref_audio_context = GetPreferredAudioContext(oth_config);

    LOG(WARNING) << __func__
                 << ": capa_sup_frames: " << loghex(capa_sup_frames)
                 << ", frame_dur: " << loghex(frame_dur);

    LOG(WARNING) << __func__
                 << ": capa_lc3q_pref: " << capa_lc3q_pref
                 << ", lc3q_pref: " << loghex(lc3q_pref);

    LOG(WARNING) << __func__
                 << ": capa_pref_audio_context: " << capa_pref_audio_context
                 << ", dst_pref_audio_context: " << dst_pref_audio_context;

    if(!(capa_sup_frames & (0x01 << frame_dur))) {
      LOG(ERROR) << __func__ << ": No match for frame duration ";
      return false;
    }

    if(capa_max_sup_lc3_frames && lc3_blocks_per_sdu) {
      if(capa_max_sup_lc3_frames < lc3_blocks_per_sdu *
                      static_cast<uint8_t> (oth_config->channel_mode)) {
        LOG(ERROR) << __func__ << ": blocks per sdu exceeds the capacity ";
        return false;
      }
    }

    if( octs_per_frame < capa_min_sup_octs ||
        octs_per_frame > capa_max_sup_octs) {
      LOG(ERROR) << __func__ << ": octs per frame not in limits ";
      return true;
    }

    if (!(capa_pref_audio_context & dst_pref_audio_context)) {
      LOG(ERROR) << __func__ << ": No Match for Audio context";
      return false;
    }

  }
  return true;
}
