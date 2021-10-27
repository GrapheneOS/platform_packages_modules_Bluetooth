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

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <hardware/bt_pacs_client.h>
#include "bt_types.h"

using bluetooth::bap::pacs::CodecConfig;

bool UpdateCapaSupFrameDurations(CodecConfig *config , uint8_t sup_frame);

bool UpdateCapaMaxSupLc3Frames(CodecConfig *config,
                                uint8_t max_sup_lc3_frames);


bool UpdateCapaPreferredContexts(CodecConfig *config, uint16_t contexts);


bool UpdateCapaSupOctsPerFrame(CodecConfig *config,
                                          uint32_t octs_per_frame);

bool UpdateCapaVendorMetaDataLc3QPref(CodecConfig *config, bool lc3q_pref);

bool UpdateCapaVendorMetaDataLc3QVer(CodecConfig *config, uint8_t lc3q_ver);

uint8_t GetCapaSupFrameDurations(CodecConfig *config);

uint8_t GetCapaMaxSupLc3Frames(CodecConfig *config);

uint16_t GetCapaPreferredContexts(CodecConfig *config);

uint32_t GetCapaSupOctsPerFrame(CodecConfig *config);

bool GetCapaVendorMetaDataLc3QPref(CodecConfig *config);

uint8_t GetCapaVendorMetaDataLc3QVer(CodecConfig *config);

// configurations
bool UpdateFrameDuration(CodecConfig *config , uint8_t frame_dur);

bool UpdateLc3BlocksPerSdu(CodecConfig *config,
                                uint8_t lc3_blocks_per_sdu) ;

bool UpdateOctsPerFrame(CodecConfig *config , uint16_t octs_per_frame);

bool UpdateLc3QPreference(CodecConfig *config , bool lc3q_pref);

bool UpdateVendorMetaDataLc3QPref(CodecConfig *config, bool lc3q_pref);

bool UpdateVendorMetaDataLc3QVer(CodecConfig *config, uint8_t lc3q_ver);

bool UpdatePreferredAudioContext(CodecConfig *config ,
                                    uint16_t pref_audio_context);

uint8_t GetFrameDuration(CodecConfig *config);

uint8_t GetLc3BlocksPerSdu(CodecConfig *config);

uint16_t GetOctsPerFrame(CodecConfig *config);

uint8_t GetLc3QPreference(CodecConfig *config);

uint8_t GetVendorMetaDataLc3QPref(CodecConfig *config);

uint8_t GetVendorMetaDataLc3QVer(CodecConfig *config);

uint16_t GetPreferredAudioContext(CodecConfig *config);

bool IsCodecConfigEqual(CodecConfig *src_config, CodecConfig *dst_config);


