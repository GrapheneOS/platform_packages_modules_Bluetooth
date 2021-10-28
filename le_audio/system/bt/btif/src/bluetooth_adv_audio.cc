/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
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

/*******************************************************************************
 *
 *  Filename:      bluetooth_adv_audio.cc
 *
 *  Description:   Bluetooth LEA HAL implementation
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif_adv_audio"

#include <base/logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <hardware/bluetooth.h>
#include <hardware/bt_csip.h>
#include <hardware/bt_apm.h>
#include <hardware/bt_acm.h>
#include <hardware/bt_pacs_client.h>
#include <hardware/bt_ascs_client.h>
#include <hardware/bt_bap_uclient.h>
#include <hardware/bt_vcp_controller.h>
#include <hardware/bt_mcp.h>
#include <hardware/bluetooth_callcontrol_interface.h>
#include "osi/include/log.h"
#include "btif_bap_config.h"
#include "bta_csip_api.h"
#include "stack_interface.h"
#include "btcore/include/module.h"
#include "btcore/include/osi_module.h"
#include <hardware/bt_bap_ba.h>

/*******************************************************************************
 *  Externs
 ******************************************************************************/

/* list all extended interfaces here */
using bluetooth::bap::pacs::PacsClientInterface;
using bluetooth::bap::ascs::AscsClientInterface;
using bluetooth::bap::ucast::UcastClientInterface;
using bluetooth::vcp_controller::VcpControllerInterface;
using bluetooth::mcp_server::McpServerInterface;
using bluetooth::call_control::CallControllerInterface;
extern PacsClientInterface *btif_pacs_client_get_interface();
extern AscsClientInterface *btif_ascs_client_get_interface();
extern UcastClientInterface *btif_bap_uclient_get_interface();
extern bt_apm_interface_t *btif_apm_get_interface();
extern btacm_initiator_interface_t* btif_acm_initiator_get_interface();
extern btbap_broadcast_interface_t * btif_bap_broadcast_get_interface();
/* Coordinated set identification profile - client */
extern btcsip_interface_t* btif_csip_get_interface();
/*Vcp Controller*/
extern VcpControllerInterface* btif_vcp_get_controller_interface();
/*Mcp server*/
extern McpServerInterface* btif_mcp_server_get_interface();
extern CallControllerInterface* btif_cc_server_get_interface();

/*******************************************************************************
 *  Functions
 ******************************************************************************/

static bool is_profile(const char* p1, const char* p2) {
  CHECK(p1);
  CHECK(p2);
  return strlen(p1) == strlen(p2) && strncmp(p1, p2, strlen(p2)) == 0;
}

/*****************************************************************************
 *
 *   BLUETOOTH LEA HAL INTERFACE FUNCTIONS
 *
 ****************************************************************************/

StackCallbacks *stack_callbacks;

const void* get_adv_audio_profile_interface(const char* profile_id) {
  LOG_INFO(LOG_TAG, "%s: id = %s", __func__, profile_id);

  if (is_profile(profile_id, BT_PROFILE_PACS_CLIENT_ID)) {
    return btif_pacs_client_get_interface();
  }

  if (is_profile(profile_id, BT_APM_MODULE_ID)) {
    return btif_apm_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_ACM_ID)) {
    return btif_acm_initiator_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_BAP_BROADCAST_ID))
    return btif_bap_broadcast_get_interface();

  if (is_profile(profile_id, BT_PROFILE_CSIP_CLIENT_ID)) {
    return btif_csip_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_VOLUME_CONTROL_ID)) {
    return btif_vcp_get_controller_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_MCP_ID)) {
    return btif_mcp_server_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_CC_ID)) {
     return btif_cc_server_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_ASCS_CLIENT_ID)) {
    return btif_ascs_client_get_interface();
  }

  if (is_profile(profile_id, BT_PROFILE_BAP_UCLIENT_ID)) {
    return bluetooth::bap::ucast::btif_bap_uclient_get_interface();
  }
  return NULL;
}

class StackCallbacksImpl : public StackCallbacks {
  public:
    ~StackCallbacksImpl() = default;
    void OnDevUnPaired(const RawAddress& address) override {
      BTA_CsipRemoveUnpairedSetMember(address);
      btif_bap_remove_all_records(address);
    }

    void OnConfigCleared(void)  override {
      btif_bap_config_clear();
    }

    void OnStackState(StackState state) {
      switch(state) {
        case StackState::INITIALIZING:
          module_init(get_module(BTIF_BAP_CONFIG_MODULE));
          break;
        case StackState::TURNING_ON:
          module_start_up(get_module(BTIF_BAP_CONFIG_MODULE));
          break;
        case StackState::TURNING_OFF:
          module_shut_down(get_module(BTIF_BAP_CONFIG_MODULE));
          break;
        case StackState::CLEAND_UP:
          module_clean_up(get_module(BTIF_BAP_CONFIG_MODULE));
          break;
        default:
          break;
      }
    }
};

void init_adv_audio_interfaces() {
  stack_callbacks = new StackCallbacksImpl;
  StackInterface::Initialize(stack_callbacks);
}
