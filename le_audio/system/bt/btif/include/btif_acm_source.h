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
