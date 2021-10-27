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

#ifndef BTIF_DM_ADV_AUDIO_H
#define BTIF_DM_ADV_AUDIO_H

extern std::unordered_map<RawAddress, uint32_t> adv_audio_device_db;
extern tBTA_TRANSPORT btif_dm_get_adv_audio_transport(const RawAddress& bd_addr);
extern void btif_dm_lea_search_services_evt(uint16_t event, char* p_param);
extern void btif_register_uuid_srvc_disc(bluetooth::Uuid uuid);
extern bool check_adv_audio_cod(uint32_t cod);
extern bool is_remote_support_adv_audio(const RawAddress p_addr);
extern void bte_dm_adv_audio_search_services_evt(tBTA_DM_SEARCH_EVT event,
    tBTA_DM_SEARCH* p_data);
extern void btif_dm_release_action_uuid(RawAddress bd_addr);

#endif

