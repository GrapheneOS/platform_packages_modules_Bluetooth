/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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
using bluetooth::bap::pacs::CodecDirection;
using bluetooth::bap::pacs::CodecIndex;

typedef enum {
  REC_TYPE_CAPABILITY = 0x01,
  REC_TYPE_CONFIGURATION
} btif_bap_record_type_t;

const char BTIF_BAP_CONFIG_MODULE[] = "btif_bap_config_module";

typedef struct btif_bap_config_section_iter_t btif_bap_config_section_iter_t;

bool btif_bap_add_record(const RawAddress& bd_addr,
                         btif_bap_record_type_t rec_type,
                         uint16_t context_type,
                         CodecDirection direction,
                         CodecConfig *record);

bool btif_bap_remove_record(const RawAddress& bd_addr,
                            btif_bap_record_type_t rec_type,
                            uint16_t context_type,
                            CodecDirection direction,
                            CodecConfig *record);

bool btif_bap_remove_record_by_context(const RawAddress& bd_addr,
                                       btif_bap_record_type_t rec_type,
                                       uint16_t context_type,
                                       CodecDirection direction);

bool btif_bap_remove_all_records(const RawAddress& bd_addr);

bool btif_bap_get_records(const RawAddress& bd_addr,
                          btif_bap_record_type_t rec_type,
                          uint16_t context_type,
                          CodecDirection direction,
                          std::vector<CodecConfig> *pac_records);

bool btif_bap_add_audio_loc(const RawAddress& bd_addr,
                            CodecDirection direction, uint32_t audio_loc);

bool btif_bap_rem_audio_loc(const RawAddress& bd_addr,
                            CodecDirection direction);

bool btif_bap_add_supp_contexts(const RawAddress& bd_addr,
                                  uint32_t supp_contexts);

bool btif_bap_get_supp_contexts(const RawAddress& bd_addr,
                                 uint32_t *supp_contexts);

bool btif_bap_rem_supp_contexts(const RawAddress& bd_addr);

bool btif_bap_config_clear(void);
