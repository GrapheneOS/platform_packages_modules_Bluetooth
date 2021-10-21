/******************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 ******************************************************************************/

#if AHIM_ENABLED
void btif_register_cb();
void btif_acm_process_request(tA2DP_CTRL_CMD cmd);
void btif_acm_handle_event(uint16_t event, char* p_param);
bool btif_acm_source_start_session(const RawAddress& peer_address);
bool btif_acm_source_end_session(const RawAddress& peer_address);
bool btif_acm_source_restart_session(const RawAddress& old_peer_address,
                                      const RawAddress& new_peer_address);
void btif_acm_source_command_ack(tA2DP_CTRL_CMD cmd, tA2DP_CTRL_ACK status);
void btif_acm_source_on_stopped(tA2DP_CTRL_ACK status);
void btif_acm_source_on_suspended(tA2DP_CTRL_ACK status);
bool btif_acm_on_started(tA2DP_CTRL_ACK status);
bt_status_t btif_acm_source_setup_codec();
bool btif_acm_update_sink_latency_change(uint16_t sink_latency);

#endif
