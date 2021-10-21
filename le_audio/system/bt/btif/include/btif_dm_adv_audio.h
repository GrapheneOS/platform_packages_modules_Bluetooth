/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */
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

