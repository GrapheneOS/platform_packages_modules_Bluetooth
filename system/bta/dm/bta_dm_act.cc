/******************************************************************************
 *
 *  Copyright 2003-2014 Broadcom Corporation
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

/******************************************************************************
 *
 *  This file contains the action functions for device manager state
 *  machine.
 *
 ******************************************************************************/

#define LOG_TAG "bt_bta_dm"

#include <base/location.h>
#include <base/logging.h>
#ifdef __ANDROID__
#include <bta.sysprop.h>
#endif

#include <cstdint>

#include "bta/dm/bta_dm_gatt_client.h"
#include "bta/dm/bta_dm_int.h"
#include "bta/include/bta_dm_ci.h"  // bta_dm_ci_rmt_oob
#include "bta/include/bta_gatt_api.h"
#include "bta/sys/bta_sys.h"
#include "btif/include/btif_dm.h"
#include "btif/include/btif_storage.h"
#include "btif/include/stack_manager.h"
#include "include/bind_helpers.h"
#include "main/shim/acl_api.h"
#include "main/shim/btm_api.h"
#include "main/shim/controller.h"
#include "osi/include/osi.h"  // UNUSED_ATTR
#include "osi/include/properties.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_sec.h"
#include "stack/gatt/connection_manager.h"
#include "stack/include/acl_api.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/btu.h"  // do_in_main_thread
#include "stack/include/sdp_api.h"
#include "types/bluetooth/uuid.h"
#include "types/raw_address.h"

#if (GAP_INCLUDED == TRUE)
#include "gap_api.h"
#endif

using namespace bluetooth::legacy::stack::sdp;
using bluetooth::Uuid;

bool ble_vnd_is_included();
void BTIF_dm_disable();
void BTIF_dm_enable();
void btm_ble_scanner_init(void);

static uint8_t bta_dm_pin_cback(const RawAddress& bd_addr, DEV_CLASS dev_class,
                                const tBTM_BD_NAME bd_name, bool min_16_digit);
static uint8_t bta_dm_new_link_key_cback(const RawAddress& bd_addr,
                                         DEV_CLASS dev_class,
                                         tBTM_BD_NAME bd_name,
                                         const LinkKey& key, uint8_t key_type,
                                         bool is_ctkd);
static void bta_dm_authentication_complete_cback(const RawAddress& bd_addr,
                                                 DEV_CLASS dev_class,
                                                 tBTM_BD_NAME bd_name,
                                                 tHCI_REASON result);
static void bta_dm_local_name_cback(void* p_name);
static void bta_dm_check_av();

void BTA_dm_update_policy(tBTA_SYS_CONN_STATUS status, uint8_t id,
                          uint8_t app_id, const RawAddress& peer_addr);

/* Extended Inquiry Response */
static tBTM_STATUS bta_dm_sp_cback(tBTM_SP_EVT event, tBTM_SP_EVT_DATA* p_data);

static void bta_dm_set_eir(char* local_name);

static void bta_dm_disable_conn_down_timer_cback(void* data);
static void bta_dm_rm_cback(tBTA_SYS_CONN_STATUS status, tBTA_SYS_ID id,
                            uint8_t app_id, const RawAddress& peer_addr);
static void bta_dm_adjust_roles(bool delay_role_switch);
static void bta_dm_bond_cancel_complete_cback(tBTM_STATUS result);

static uint8_t bta_dm_ble_smp_cback(tBTM_LE_EVT event, const RawAddress& bda,
                                    tBTM_LE_EVT_DATA* p_data);
static void bta_dm_ble_id_key_cback(uint8_t key_type,
                                    tBTM_BLE_LOCAL_KEYS* p_key);
static uint8_t bta_dm_sirk_verifiction_cback(const RawAddress& bd_addr);
tBTM_CONTRL_STATE bta_dm_pm_obtain_controller_state(void);
static void bta_dm_ctrl_features_rd_cmpl_cback(tHCI_STATUS result);

#ifndef BTA_DM_BLE_ADV_CHNL_MAP
#define BTA_DM_BLE_ADV_CHNL_MAP \
  (BTM_BLE_ADV_CHNL_37 | BTM_BLE_ADV_CHNL_38 | BTM_BLE_ADV_CHNL_39)
#endif

/* Disable timer interval (in milliseconds) */
#ifndef BTA_DM_DISABLE_TIMER_MS
#define BTA_DM_DISABLE_TIMER_MS (2000)
#endif

/* Disable timer retrial interval (in milliseconds) */
#ifndef BTA_DM_DISABLE_TIMER_RETRIAL_MS
#define BTA_DM_DISABLE_TIMER_RETRIAL_MS 1500
#endif

/* Disable connection down timer (in milliseconds) */
#ifndef BTA_DM_DISABLE_CONN_DOWN_TIMER_MS
#define BTA_DM_DISABLE_CONN_DOWN_TIMER_MS 100
#endif

/* Switch delay timer (in milliseconds) */
#ifndef BTA_DM_SWITCH_DELAY_TIMER_MS
#define BTA_DM_SWITCH_DELAY_TIMER_MS 500
#endif

/* Sysprop path for page timeout */
#ifndef PROPERTY_PAGE_TIMEOUT
#define PROPERTY_PAGE_TIMEOUT "bluetooth.core.classic.page_timeout"
#endif

// Time to wait after receiving shutdown request to delay the actual shutdown
// process. This time may be zero which invokes immediate shutdown.
static uint64_t get_DisableDelayTimerInMs() {
#ifndef __ANDROID__
  return 200;
#else
  static const uint64_t kDisableDelayTimerInMs =
      android::sysprop::bluetooth::Bta::disable_delay().value_or(200);
  return kDisableDelayTimerInMs;
#endif
}

void bta_dm_disc_disable_search_and_disc();
void bta_dm_disc_discover_next_device();
void bta_dm_disc_gatt_cancel_open(const RawAddress& bd_addr);
void bta_dm_disc_gatt_refresh(const RawAddress& bd_addr);
void bta_dm_disc_gattc_register();
void bta_dm_disc_remove_device(const RawAddress& bd_addr);

namespace {

struct WaitForAllAclConnectionsToDrain {
  uint64_t time_to_wait_in_ms;
  unsigned long TimeToWaitInMs() const {
    return static_cast<unsigned long>(time_to_wait_in_ms);
  }
  void* AlarmCallbackData() const {
    return const_cast<void*>(static_cast<const void*>(this));
  }

  static const WaitForAllAclConnectionsToDrain* FromAlarmCallbackData(
      void* data);
  static bool IsFirstPass(const WaitForAllAclConnectionsToDrain*);
} first_pass =
    {
        .time_to_wait_in_ms = static_cast<uint64_t>(BTA_DM_DISABLE_TIMER_MS),
},
  second_pass = {
      .time_to_wait_in_ms =
          static_cast<uint64_t>(BTA_DM_DISABLE_TIMER_RETRIAL_MS),
};

bool WaitForAllAclConnectionsToDrain::IsFirstPass(
    const WaitForAllAclConnectionsToDrain* pass) {
  return pass == &first_pass;
}

const WaitForAllAclConnectionsToDrain*
WaitForAllAclConnectionsToDrain::FromAlarmCallbackData(void* data) {
  return const_cast<const WaitForAllAclConnectionsToDrain*>(
      static_cast<WaitForAllAclConnectionsToDrain*>(data));
}

}  // namespace

static void bta_dm_reset_sec_dev_pending(const RawAddress& remote_bd_addr);
static void bta_dm_remove_sec_dev_entry(const RawAddress& remote_bd_addr);
static void bta_dm_delay_role_switch_cback(void* data);
static void bta_dm_wait_for_acl_to_drain_cback(void* data);

/* bta security callback */
const tBTM_APPL_INFO bta_security = {
    .p_pin_callback = &bta_dm_pin_cback,
    .p_link_key_callback = &bta_dm_new_link_key_cback,
    .p_auth_complete_callback = &bta_dm_authentication_complete_cback,
    .p_bond_cancel_cmpl_callback = &bta_dm_bond_cancel_complete_cback,
    .p_sp_callback = &bta_dm_sp_cback,
    .p_le_callback = &bta_dm_ble_smp_cback,
    .p_le_key_callback = &bta_dm_ble_id_key_cback,
    .p_sirk_verification_callback = &bta_dm_sirk_verifiction_cback};

// Stores the local Input/Output Capabilities of the Bluetooth device.
static uint8_t btm_local_io_caps;

/** Initialises the BT device manager */
void bta_dm_enable(tBTA_DM_SEC_CBACK* p_sec_cback) {
  /* make sure security callback is saved - if no callback, do not erase the
  previous one,
  it could be an error recovery mechanism */
  if (p_sec_cback != NULL) bta_dm_cb.p_sec_cback = p_sec_cback;

  btm_local_io_caps = btif_storage_get_local_io_caps();
}

void bta_dm_ble_sirk_sec_cb_register(tBTA_DM_SEC_CBACK* p_cback) {
  /* Save the callback to be called when a request of member validation will be
   * needed. */
  LOG_DEBUG("");
  bta_dm_cb.p_sec_sirk_cback = p_cback;
}

void bta_dm_ble_sirk_confirm_device_reply(const RawAddress& bd_addr,
                                          bool accept) {
  LOG_DEBUG("");
  get_btm_client_interface().security.BTM_BleSirkConfirmDeviceReply(
      bd_addr, accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED);
}

/*******************************************************************************
 *
 * Function         bta_dm_init_cb
 *
 * Description      Initializes the bta_dm_cb control block
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_init_cb(void) {
  bta_dm_cb = {};
  bta_dm_cb.disable_timer = alarm_new("bta_dm.disable_timer");
  bta_dm_cb.switch_delay_timer = alarm_new("bta_dm.switch_delay_timer");
  for (size_t i = 0; i < BTA_DM_NUM_PM_TIMER; i++) {
    for (size_t j = 0; j < BTA_DM_PM_MODE_TIMER_MAX; j++) {
      bta_dm_cb.pm_timer[i].timer[j] = alarm_new("bta_dm.pm_timer");
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_deinit_cb
 *
 * Description      De-initializes the bta_dm_cb control block
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_deinit_cb(void) {
  /*
   * TODO: Should alarm_free() the bta_dm_cb timers during graceful
   * shutdown.
   */
  alarm_free(bta_dm_cb.disable_timer);
  alarm_free(bta_dm_cb.switch_delay_timer);
  for (size_t i = 0; i < BTA_DM_NUM_PM_TIMER; i++) {
    for (size_t j = 0; j < BTA_DM_PM_MODE_TIMER_MAX; j++) {
      alarm_free(bta_dm_cb.pm_timer[i].timer[j]);
    }
  }
  bta_dm_cb = {};
}

void BTA_dm_on_hw_off() {
  BTIF_dm_disable();

  /* reinitialize the control block */
  bta_dm_deinit_cb();

  /* hw is ready, go on with BTA DM initialization */
  alarm_free(bta_dm_search_cb.search_timer);
  alarm_free(bta_dm_search_cb.gatt_close_timer);
  osi_free_and_reset((void**)&bta_dm_search_cb.p_pending_search);
  fixed_queue_free(bta_dm_search_cb.pending_discovery_queue, osi_free);
  bta_dm_search_cb = {};
}

void BTA_dm_on_hw_on() {
  DEV_CLASS dev_class;
  tBTA_DM_SEC_CBACK* temp_cback;
  uint8_t key_mask = 0;
  tBTA_BLE_LOCAL_ID_KEYS id_key;

  /* save security callback */
  temp_cback = bta_dm_cb.p_sec_cback;
  /* make sure the control block is properly initialized */
  bta_dm_init_cb();
  /* and retrieve the callback */
  bta_dm_cb.p_sec_cback = temp_cback;

  /* hw is ready, go on with BTA DM initialization */
  alarm_free(bta_dm_search_cb.search_timer);
  alarm_free(bta_dm_search_cb.gatt_close_timer);
  osi_free_and_reset((void**)&bta_dm_search_cb.p_pending_search);
  fixed_queue_free(bta_dm_search_cb.pending_discovery_queue, osi_free);
  bta_dm_search_cb = {};
  /*
   * TODO: Should alarm_free() the bta_dm_search_cb timers during
   * graceful shutdown.
   */
  bta_dm_search_cb.search_timer = alarm_new("bta_dm_search.search_timer");
  bool delay_close_gatt =
      osi_property_get_bool("bluetooth.gatt.delay_close.enabled", true);
  bta_dm_search_cb.gatt_close_timer =
      delay_close_gatt ? alarm_new("bta_dm_search.gatt_close_timer") : nullptr;
  bta_dm_search_cb.pending_discovery_queue = fixed_queue_new(SIZE_MAX);

  memset(&bta_dm_conn_srvcs, 0, sizeof(bta_dm_conn_srvcs));
  memset(&bta_dm_di_cb, 0, sizeof(tBTA_DM_DI_CB));

  btif_dm_get_local_class_of_device(dev_class);
  LOG_INFO("%s: Read default class of device {0x%x, 0x%x, 0x%x}", __func__,
      dev_class[0], dev_class[1], dev_class[2]);

  BTM_SetDeviceClass(dev_class);

  /* load BLE local information: ID keys, ER if available */
  Octet16 er;
  btif_dm_get_ble_local_keys(&key_mask, &er, &id_key);

  if (key_mask & BTA_BLE_LOCAL_KEY_TYPE_ER) {
    get_btm_client_interface().ble.BTM_BleLoadLocalKeys(
        BTA_BLE_LOCAL_KEY_TYPE_ER, (tBTM_BLE_LOCAL_KEYS*)&er);
  }
  if (key_mask & BTA_BLE_LOCAL_KEY_TYPE_ID) {
    get_btm_client_interface().ble.BTM_BleLoadLocalKeys(
        BTA_BLE_LOCAL_KEY_TYPE_ID, (tBTM_BLE_LOCAL_KEYS*)&id_key);
  }
  bta_dm_search_cb.conn_id = GATT_INVALID_CONN_ID;

  get_btm_client_interface().security.BTM_SecRegister(&bta_security);

  BTM_WritePageTimeout(osi_property_get_int32(PROPERTY_PAGE_TIMEOUT,
                                              p_bta_dm_cfg->page_timeout));

  if (ble_vnd_is_included()) {
    BTM_BleReadControllerFeatures(bta_dm_ctrl_features_rd_cmpl_cback);
  } else {
    /* Set controller features even if vendor support is not included */
    if (bta_dm_cb.p_sec_cback)
      bta_dm_cb.p_sec_cback(BTA_DM_LE_FEATURES_READ, NULL);
  }

  btm_ble_scanner_init();

  /* Earlier, we used to invoke BTM_ReadLocalAddr which was just copying the
     bd_addr
     from the control block and invoking the callback which was sending the
     DM_ENABLE_EVT.
     But then we have a few HCI commands being invoked above which were still
     in progress
     when the ENABLE_EVT was sent. So modified this to fetch the local name
     which forces
     the DM_ENABLE_EVT to be sent only after all the init steps are complete
     */
  get_btm_client_interface().local.BTM_ReadLocalDeviceNameFromController(
      bta_dm_local_name_cback);

  bta_sys_rm_register(bta_dm_rm_cback);

  /* initialize bluetooth low power manager */
  bta_dm_init_pm();

  bta_dm_disc_gattc_register();
}

/** Disables the BT device manager */
void bta_dm_disable() {
  /* Set l2cap idle timeout to 0 (so BTE immediately disconnects ACL link after
   * last channel is closed) */
  L2CA_SetIdleTimeoutByBdAddr(RawAddress::kAny, 0, BT_TRANSPORT_BR_EDR);
  L2CA_SetIdleTimeoutByBdAddr(RawAddress::kAny, 0, BT_TRANSPORT_LE);

  /* disable all active subsystems */
  bta_sys_disable();

  BTM_SetDiscoverability(BTM_NON_DISCOVERABLE);
  BTM_SetConnectability(BTM_NON_CONNECTABLE);

  bta_dm_disable_pm();
  bta_dm_disc_disable_search_and_disc();
  bta_dm_cb.disabling = true;

  connection_manager::reset(false);

  if (BTM_GetNumAclLinks() == 0) {
    // We can shut down faster if there are no ACL links
    switch (get_DisableDelayTimerInMs()) {
      case 0:
        LOG_DEBUG("Immediately disabling device manager");
        bta_dm_disable_conn_down_timer_cback(nullptr);
        break;
      default:
        LOG_DEBUG("Set timer to delay disable initiation:%lu ms",
                  static_cast<unsigned long>(get_DisableDelayTimerInMs()));
        alarm_set_on_mloop(bta_dm_cb.disable_timer, get_DisableDelayTimerInMs(),
                           bta_dm_disable_conn_down_timer_cback, nullptr);
    }
  } else {
    LOG_DEBUG("Set timer to wait for all ACL connections to close:%lu ms",
              first_pass.TimeToWaitInMs());
    alarm_set_on_mloop(bta_dm_cb.disable_timer, first_pass.time_to_wait_in_ms,
                       bta_dm_wait_for_acl_to_drain_cback,
                       first_pass.AlarmCallbackData());
  }
}

void bta_dm_consolidate(const RawAddress& identity_addr,
                        const RawAddress& rpa) {
  for (auto i = 0; i < bta_dm_cb.device_list.count; i++) {
    if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr != rpa) continue;

    LOG_INFO("consolidating bda_dm_cb record %s -> %s",
             ADDRESS_TO_LOGGABLE_CSTR(rpa),
             ADDRESS_TO_LOGGABLE_CSTR(identity_addr));
    bta_dm_cb.device_list.peer_device[i].peer_bdaddr = identity_addr;
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_wait_for_all_acl_to_drain
 *
 * Description      Called if the disable timer expires
 *                  Used to close ACL connections which are still active
 *
 * Returns          true if there is a device being forcefully disconnected
 *
 ******************************************************************************/
static bool force_disconnect_all_acl_connections() {
  const bool is_force_disconnect_needed = (bta_dm_cb.device_list.count > 0);

  for (auto i = 0; i < bta_dm_cb.device_list.count; i++) {
    btm_remove_acl(bta_dm_cb.device_list.peer_device[i].peer_bdaddr,
                   bta_dm_cb.device_list.peer_device[i].transport);
  }
  return is_force_disconnect_needed;
}

static void bta_dm_wait_for_acl_to_drain_cback(void* data) {
  ASSERT(data != nullptr);
  const WaitForAllAclConnectionsToDrain* pass =
      WaitForAllAclConnectionsToDrain::FromAlarmCallbackData(data);

  if (BTM_GetNumAclLinks() && force_disconnect_all_acl_connections() &&
      WaitForAllAclConnectionsToDrain::IsFirstPass(pass)) {
    /* DISABLE_EVT still need to be sent out to avoid java layer disable timeout
     */
    LOG_DEBUG(
        "Set timer for second pass to wait for all ACL connections to "
        "close:%lu ms ",
        second_pass.TimeToWaitInMs());
    alarm_set_on_mloop(bta_dm_cb.disable_timer, second_pass.time_to_wait_in_ms,
                       bta_dm_wait_for_acl_to_drain_cback,
                       second_pass.AlarmCallbackData());
  } else {
    // No ACL links to close were up or is second pass at ACL closure
    LOG_INFO("Ensuring all ACL connections have been properly flushed");
    bluetooth::shim::ACL_Shutdown();

    bta_dm_cb.disabling = false;

    bta_sys_remove_uuid(UUID_SERVCLASS_PNP_INFORMATION);
    BTIF_dm_disable();
  }
}

/** Sets local device name */
void bta_dm_set_dev_name(const std::vector<uint8_t>& name) {
  BTM_SetLocalDeviceName((const char*)name.data());
  bta_dm_set_eir((char*)name.data());
}

/** Sets discoverability, connectability and pairability */
bool BTA_DmSetVisibility(bt_scan_mode_t mode) {
  tBTA_DM_DISC disc_mode_param;
  tBTA_DM_CONN conn_mode_param;

  switch (mode) {
    case BT_SCAN_MODE_NONE:
      disc_mode_param = BTA_DM_NON_DISC;
      conn_mode_param = BTA_DM_NON_CONN;
      break;

    case BT_SCAN_MODE_CONNECTABLE:
      disc_mode_param = BTA_DM_NON_DISC;
      conn_mode_param = BTA_DM_CONN;
      break;

    case BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE:
      disc_mode_param = BTA_DM_GENERAL_DISC;
      conn_mode_param = BTA_DM_CONN;
      break;

    case BT_SCAN_MODE_CONNECTABLE_LIMITED_DISCOVERABLE:
      disc_mode_param = BTA_DM_LIMITED_DISC;
      conn_mode_param = BTA_DM_CONN;
      break;

    default:
      return false;
  }

  BTM_SetDiscoverability(disc_mode_param);
  BTM_SetConnectability(conn_mode_param);
  return true;
}
static void bta_dm_process_remove_device_no_callback(
    const RawAddress& bd_addr) {
  /* need to remove all pending background connection before unpair */
  bta_dm_disc_gatt_cancel_open(bd_addr);

  BTM_SecDeleteDevice(bd_addr);

  /* remove all cached GATT information */
  bta_dm_disc_gatt_refresh(bd_addr);
}

void bta_dm_process_remove_device(const RawAddress& bd_addr) {
  bta_dm_process_remove_device_no_callback(bd_addr);

  /* Conclude service search if it was pending */
  bta_dm_disc_remove_device(bd_addr);

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC sec_event;
    sec_event.link_down.bd_addr = bd_addr;
    bta_dm_cb.p_sec_cback(BTA_DM_DEV_UNPAIRED_EVT, &sec_event);
  }
}

/** Removes device, disconnects ACL link if required */
void bta_dm_remove_device(const RawAddress& bd_addr) {
  /* If ACL exists for the device in the remove_bond message*/
  bool is_bd_addr_connected =
      BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE) ||
      BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_BR_EDR);

  tBT_TRANSPORT other_transport = BT_TRANSPORT_AUTO;
  if (is_bd_addr_connected) {
    APPL_TRACE_DEBUG("%s: ACL Up count: %d", __func__,
                     bta_dm_cb.device_list.count);

    /* Take the link down first, and mark the device for removal when
     * disconnected */
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      auto& peer_device = bta_dm_cb.device_list.peer_device[i];
      if (peer_device.peer_bdaddr == bd_addr) {
        peer_device.conn_state = BTA_DM_UNPAIRING;

        /* Make sure device is not in acceptlist before we disconnect */
        GATT_CancelConnect(0, bd_addr, false);

        btm_remove_acl(bd_addr, peer_device.transport);
        APPL_TRACE_DEBUG("%s: transport: %d", __func__, peer_device.transport);

        /* save the other transport to check if device is connected on
         * other_transport */
        if (peer_device.transport == BT_TRANSPORT_LE)
          other_transport = BT_TRANSPORT_BR_EDR;
        else
          other_transport = BT_TRANSPORT_LE;

        break;
      }
    }
  }

  RawAddress other_address = bd_addr;
  RawAddress other_address2 = bd_addr;

  // If it is DUMO device and device is paired as different address, unpair that
  // device
  bool other_address_connected =
      (other_transport)
          ? BTM_ReadConnectedTransportAddress(&other_address, other_transport)
          : (BTM_ReadConnectedTransportAddress(&other_address,
                                               BT_TRANSPORT_BR_EDR) ||
             BTM_ReadConnectedTransportAddress(&other_address2,
                                               BT_TRANSPORT_LE));
  if (other_address == bd_addr) other_address = other_address2;

  if (other_address_connected) {
    // Get real transport
    if (other_transport == BT_TRANSPORT_AUTO) {
      bool connected_with_br_edr =
          BTM_IsAclConnectionUp(other_address, BT_TRANSPORT_BR_EDR);
      other_transport =
          connected_with_br_edr ? BT_TRANSPORT_BR_EDR : BT_TRANSPORT_LE;
    }
    LOG_INFO("other_address %s with transport %d connected",
             ADDRESS_TO_LOGGABLE_CSTR(other_address), other_transport);
    /* Take the link down first, and mark the device for removal when
     * disconnected */
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      auto& peer_device = bta_dm_cb.device_list.peer_device[i];
      if (peer_device.peer_bdaddr == other_address &&
          peer_device.transport == other_transport) {
        peer_device.conn_state = BTA_DM_UNPAIRING;
        LOG_INFO("Remove ACL of address %s", ADDRESS_TO_LOGGABLE_CSTR(other_address));

        /* Make sure device is not in acceptlist before we disconnect */
        GATT_CancelConnect(0, bd_addr, false);

        btm_remove_acl(other_address, peer_device.transport);
        break;
      }
    }
  }

  /* Delete the device mentioned in the msg */
  if (!is_bd_addr_connected) {
    bta_dm_process_remove_device(bd_addr);
  }

  /* Delete the other paired device too */
  if (!other_address_connected && !other_address.IsEmpty()) {
    bta_dm_process_remove_device(other_address);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_add_device
 *
 * Description      This function adds a Link Key to an security database entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 ******************************************************************************/
void bta_dm_add_device(std::unique_ptr<tBTA_DM_API_ADD_DEVICE> msg) {
  uint8_t* p_dc = NULL;
  LinkKey* p_lc = NULL;

  /* If not all zeros, the device class has been specified */
  if (msg->dc_known) p_dc = (uint8_t*)msg->dc;

  if (msg->link_key_known) p_lc = &msg->link_key;

    auto add_result =
        BTM_SecAddDevice(msg->bd_addr, p_dc, msg->bd_name, nullptr, p_lc,
                         msg->key_type, msg->pin_length);
    if (!add_result) {
      LOG(ERROR) << "BTA_DM: Error adding device "
                 << ADDRESS_TO_LOGGABLE_STR(msg->bd_addr);
    }
}

/** This function forces to close the connection to a remote device and
 * optionaly remove the device from security database if required. */
void bta_dm_close_acl(const RawAddress& bd_addr, bool remove_dev,
                      tBT_TRANSPORT transport) {
  uint8_t index;

  APPL_TRACE_DEBUG("bta_dm_close_acl");

  if (BTM_IsAclConnectionUp(bd_addr, transport)) {
    for (index = 0; index < bta_dm_cb.device_list.count; index++) {
      if (bta_dm_cb.device_list.peer_device[index].peer_bdaddr == bd_addr)
        break;
    }
    if (index != bta_dm_cb.device_list.count) {
      if (remove_dev) {
        LOG_INFO("Setting remove_dev_pending for %s",
                 ADDRESS_TO_LOGGABLE_CSTR(bd_addr));
        bta_dm_cb.device_list.peer_device[index].remove_dev_pending = true;
      }
    } else {
      APPL_TRACE_ERROR("unknown device, remove ACL failed");
    }

    /* Make sure device is not in acceptlist before we disconnect */
    GATT_CancelConnect(0, bd_addr, false);

    /* Disconnect the ACL link */
    btm_remove_acl(bd_addr, transport);
  }
  /* if to remove the device from security database ? do it now */
  else if (remove_dev) {
    bta_dm_process_remove_device_no_callback(bd_addr);
  }
  /* otherwise, no action needed */
}

/** Bonds with peer device */
void bta_dm_bond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                 tBT_TRANSPORT transport, tBT_DEVICE_TYPE device_type) {
  LOG_INFO("Bonding with peer device:%s type:%s transport:%s type:%s",
           ADDRESS_TO_LOGGABLE_CSTR(bd_addr),
           AddressTypeText(addr_type).c_str(),
           bt_transport_text(transport).c_str(),
           DeviceTypeText(device_type).c_str());

  tBTA_DM_SEC sec_event;
  const char* p_name;

  tBTM_STATUS status =
      BTM_SecBond(bd_addr, addr_type, transport, device_type, 0, NULL);

  if (bta_dm_cb.p_sec_cback && (status != BTM_CMD_STARTED)) {
    memset(&sec_event, 0, sizeof(tBTA_DM_SEC));
    sec_event.auth_cmpl.bd_addr = bd_addr;
    p_name = BTM_SecReadDevName(bd_addr);
    if (p_name != NULL) {
      memcpy(sec_event.auth_cmpl.bd_name, p_name, BD_NAME_LEN);
      sec_event.auth_cmpl.bd_name[BD_NAME_LEN] = 0;
    }

    /*      taken care of by memset [above]
            sec_event.auth_cmpl.key_present = false;
            sec_event.auth_cmpl.success = false;
    */
    sec_event.auth_cmpl.fail_reason = HCI_ERR_ILLEGAL_COMMAND;
    if (status == BTM_SUCCESS) {
      sec_event.auth_cmpl.success = true;
    } else {
      /* delete this device entry from Sec Dev DB */
      bta_dm_remove_sec_dev_entry(bd_addr);
    }
    bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
  }
}

/** Cancels bonding with a peer device */
void bta_dm_bond_cancel(const RawAddress& bd_addr) {
  tBTM_STATUS status;
  tBTA_DM_SEC sec_event;

  APPL_TRACE_EVENT(" bta_dm_bond_cancel ");

  status = BTM_SecBondCancel(bd_addr);

  if (bta_dm_cb.p_sec_cback &&
      (status != BTM_CMD_STARTED && status != BTM_SUCCESS)) {
    sec_event.bond_cancel_cmpl.result = BTA_FAILURE;

    bta_dm_cb.p_sec_cback(BTA_DM_BOND_CANCEL_CMPL_EVT, &sec_event);
  }
}

/** Send the pin_reply to a request from BTM */
void bta_dm_pin_reply(std::unique_ptr<tBTA_DM_API_PIN_REPLY> msg) {
  if (msg->accept) {
    BTM_PINCodeReply(msg->bd_addr, BTM_SUCCESS, msg->pin_len, msg->p_pin);
  } else {
    BTM_PINCodeReply(msg->bd_addr, BTM_NOT_AUTHORIZED, 0, NULL);
  }
}

/** Send the user confirm request reply in response to a request from BTM */
void bta_dm_confirm(const RawAddress& bd_addr, bool accept) {
  BTM_ConfirmReqReply(accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED, bd_addr);
}

/** respond to the OOB data request for the remote device from BTM */
void bta_dm_ci_rmt_oob_act(std::unique_ptr<tBTA_DM_CI_RMT_OOB> msg) {
  BTM_RemoteOobDataReply(msg->accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED,
                         msg->bd_addr, msg->c, msg->r);
}

/*******************************************************************************
 *
 * Function         bta_dm_pinname_cback
 *
 * Description      Callback requesting pin_key
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_pinname_cback(const tBTM_REMOTE_DEV_NAME* p_data) {
  tBTM_REMOTE_DEV_NAME* p_result = (tBTM_REMOTE_DEV_NAME*)p_data;
  tBTA_DM_SEC sec_event;
  uint32_t bytes_to_copy;
  tBTA_DM_SEC_EVT event = bta_dm_cb.pin_evt;

  if (BTA_DM_SP_CFM_REQ_EVT == event) {
    /* Retrieved saved device class and bd_addr */
    sec_event.cfm_req.bd_addr = bta_dm_cb.pin_bd_addr;
    BTA_COPY_DEVICE_CLASS(sec_event.cfm_req.dev_class, bta_dm_cb.pin_dev_class);

    if (p_result && p_result->status == BTM_SUCCESS) {
      bytes_to_copy =
          (p_result->length < BD_NAME_LEN) ? p_result->length : BD_NAME_LEN;
      memcpy(sec_event.cfm_req.bd_name, p_result->remote_bd_name,
             bytes_to_copy);
      sec_event.pin_req.bd_name[BD_NAME_LEN] = 0;
    } else /* No name found */
      sec_event.cfm_req.bd_name[0] = 0;

    sec_event.key_notif.passkey =
        bta_dm_cb.num_val; /* get PIN code numeric number */

    /* 1 additional event data fields for this event */
    sec_event.cfm_req.just_works = bta_dm_cb.just_works;
    /* retrieve the loc and rmt caps */
    sec_event.cfm_req.loc_io_caps = bta_dm_cb.loc_io_caps;
    sec_event.cfm_req.rmt_io_caps = bta_dm_cb.rmt_io_caps;
    sec_event.cfm_req.loc_auth_req = bta_dm_cb.loc_auth_req;
    sec_event.cfm_req.rmt_auth_req = bta_dm_cb.rmt_auth_req;

  } else {
    /* Retrieved saved device class and bd_addr */
    sec_event.pin_req.bd_addr = bta_dm_cb.pin_bd_addr;
    BTA_COPY_DEVICE_CLASS(sec_event.pin_req.dev_class, bta_dm_cb.pin_dev_class);

    if (p_result && p_result->status == BTM_SUCCESS) {
      bytes_to_copy = (p_result->length < BD_NAME_LEN) ? p_result->length
                                                       : (BD_NAME_LEN - 1);
      memcpy(sec_event.pin_req.bd_name, p_result->remote_bd_name,
             bytes_to_copy);
      sec_event.pin_req.bd_name[BD_NAME_LEN] = 0;
    } else /* No name found */
      sec_event.pin_req.bd_name[0] = 0;

    event = bta_dm_cb.pin_evt;
    sec_event.key_notif.passkey =
        bta_dm_cb.num_val; /* get PIN code numeric number */
  }

  if (bta_dm_cb.p_sec_cback) bta_dm_cb.p_sec_cback(event, &sec_event);
}

/*******************************************************************************
 *
 * Function         bta_dm_pin_cback
 *
 * Description      Callback requesting pin_key
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_pin_cback(const RawAddress& bd_addr, DEV_CLASS dev_class,
                                const tBTM_BD_NAME bd_name, bool min_16_digit) {
  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  /* If the device name is not known, save bdaddr and devclass and initiate a
   * name request */
  if (bd_name[0] == 0) {
    bta_dm_cb.pin_evt = BTA_DM_PIN_REQ_EVT;
    bta_dm_cb.pin_bd_addr = bd_addr;
    BTA_COPY_DEVICE_CLASS(bta_dm_cb.pin_dev_class, dev_class);
    if ((BTM_ReadRemoteDeviceName(bd_addr, bta_dm_pinname_cback,
                                  BT_TRANSPORT_BR_EDR)) == BTM_CMD_STARTED)
      return BTM_CMD_STARTED;

    APPL_TRACE_WARNING(
        " bta_dm_pin_cback() -> Failed to start Remote Name Request  ");
  }

  tBTA_DM_SEC sec_event = {.pin_req = {
                               .bd_addr = bd_addr,
                           }};
  BTA_COPY_DEVICE_CLASS(sec_event.pin_req.dev_class, dev_class);
  strlcpy((char*)sec_event.pin_req.bd_name, (char*)bd_name, BD_NAME_LEN + 1);
  sec_event.pin_req.min_16_digit = min_16_digit;

  bta_dm_cb.p_sec_cback(BTA_DM_PIN_REQ_EVT, &sec_event);
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         bta_dm_new_link_key_cback
 *
 * Description      Callback from BTM to notify new link key
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_new_link_key_cback(const RawAddress& bd_addr,
                                         UNUSED_ATTR DEV_CLASS dev_class,
                                         tBTM_BD_NAME bd_name,
                                         const LinkKey& key, uint8_t key_type,
                                         bool is_ctkd) {
  tBTA_DM_SEC sec_event;
  tBTA_DM_AUTH_CMPL* p_auth_cmpl;
  tBTA_DM_SEC_EVT event = BTA_DM_AUTH_CMPL_EVT;

  memset(&sec_event, 0, sizeof(tBTA_DM_SEC));

  p_auth_cmpl = &sec_event.auth_cmpl;

  p_auth_cmpl->bd_addr = bd_addr;

  memcpy(p_auth_cmpl->bd_name, bd_name, BD_NAME_LEN);
  p_auth_cmpl->bd_name[BD_NAME_LEN] = 0;
  p_auth_cmpl->key_present = true;
  p_auth_cmpl->key_type = key_type;
  p_auth_cmpl->success = true;
  p_auth_cmpl->key = key;
  p_auth_cmpl->is_ctkd = is_ctkd;

  sec_event.auth_cmpl.fail_reason = HCI_SUCCESS;

  // Report the BR link key based on the BR/EDR address and type
  BTM_ReadDevInfo(bd_addr, &sec_event.auth_cmpl.dev_type,
                  &sec_event.auth_cmpl.addr_type);
  if (bta_dm_cb.p_sec_cback) bta_dm_cb.p_sec_cback(event, &sec_event);

  // Setting remove_dev_pending flag to false, where it will avoid deleting
  // the
  // security device record when the ACL connection link goes down in case of
  // reconnection.
  if (bta_dm_cb.device_list.count)
    bta_dm_reset_sec_dev_pending(p_auth_cmpl->bd_addr);

  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         bta_dm_authentication_complete_cback
 *
 * Description      Authentication complete callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_authentication_complete_cback(
    const RawAddress& bd_addr, UNUSED_ATTR DEV_CLASS dev_class,
    tBTM_BD_NAME bd_name, tHCI_REASON reason) {
  if (reason != HCI_SUCCESS) {
    if (bta_dm_cb.p_sec_cback) {
      // Build out the security event data structure
      tBTA_DM_SEC sec_event = {
          .auth_cmpl =
              {
                  .bd_addr = bd_addr,
              },
      };
      memcpy(sec_event.auth_cmpl.bd_name, bd_name, BD_NAME_LEN);
      sec_event.auth_cmpl.bd_name[BD_NAME_LEN] = 0;

      // Report the BR link key based on the BR/EDR address and type
      BTM_ReadDevInfo(bd_addr, &sec_event.auth_cmpl.dev_type,
                      &sec_event.auth_cmpl.addr_type);
      sec_event.auth_cmpl.fail_reason = reason;

      bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
    }

    switch (reason) {
      case HCI_ERR_AUTH_FAILURE:
      case HCI_ERR_KEY_MISSING:
      case HCI_ERR_HOST_REJECT_SECURITY:
      case HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE:
        LOG_WARN(
            "Deleting device record as authentication failed entry:%s "
            "reason:%s",
            ADDRESS_TO_LOGGABLE_CSTR(bd_addr), hci_reason_code_text(reason).c_str());
        break;

      default:
        break;
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_sp_cback
 *
 * Description      simple pairing callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static tBTM_STATUS bta_dm_sp_cback(tBTM_SP_EVT event,
                                   tBTM_SP_EVT_DATA* p_data) {
  tBTM_STATUS status = BTM_CMD_STARTED;
  tBTA_DM_SEC sec_event = {};
  tBTA_DM_SEC_EVT pin_evt = BTA_DM_SP_KEY_NOTIF_EVT;

  APPL_TRACE_EVENT("bta_dm_sp_cback: %d", event);
  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  bool sp_rmt_result = false;
  /* TODO_SP */
  switch (event) {
    case BTM_SP_IO_REQ_EVT:
      if (btm_local_io_caps != BTM_IO_CAP_NONE) {
        /* translate auth_req */
        btif_dm_set_oob_for_io_req(&p_data->io_req.oob_data);
        btif_dm_proc_io_req(&p_data->io_req.auth_req, p_data->io_req.is_orig);
      }
      APPL_TRACE_EVENT("io mitm: %d oob_data:%d", p_data->io_req.auth_req,
                       p_data->io_req.oob_data);
      break;
    case BTM_SP_IO_RSP_EVT:
      if (btm_local_io_caps != BTM_IO_CAP_NONE) {
        btif_dm_proc_io_rsp(p_data->io_rsp.bd_addr, p_data->io_rsp.io_cap,
                            p_data->io_rsp.oob_data, p_data->io_rsp.auth_req);
      }
      break;

    case BTM_SP_CFM_REQ_EVT:
      pin_evt = BTA_DM_SP_CFM_REQ_EVT;
      bta_dm_cb.just_works = sec_event.cfm_req.just_works =
          p_data->cfm_req.just_works;
      sec_event.cfm_req.loc_auth_req = p_data->cfm_req.loc_auth_req;
      sec_event.cfm_req.rmt_auth_req = p_data->cfm_req.rmt_auth_req;
      sec_event.cfm_req.loc_io_caps = p_data->cfm_req.loc_io_caps;
      sec_event.cfm_req.rmt_io_caps = p_data->cfm_req.rmt_io_caps;

      [[fallthrough]];
    /* Passkey entry mode, mobile device with output capability is very
        unlikely to receive key request, so skip this event */
    /*case BTM_SP_KEY_REQ_EVT: */
    case BTM_SP_KEY_NOTIF_EVT:
      if (btm_local_io_caps == BTM_IO_CAP_NONE &&
          BTM_SP_KEY_NOTIF_EVT == event) {
        status = BTM_NOT_AUTHORIZED;
        break;
      }

      // TODO PleaseFix: This assignment only works with event
      // BTM_SP_KEY_NOTIF_EVT
      bta_dm_cb.num_val = sec_event.key_notif.passkey =
          p_data->key_notif.passkey;

      if (BTM_SP_CFM_REQ_EVT == event) {
        /* Due to the switch case falling through below to
           BTM_SP_KEY_NOTIF_EVT,
           copy these values into key_notif from cfm_req */
        sec_event.key_notif.bd_addr = p_data->cfm_req.bd_addr;
        dev_class_copy(sec_event.key_notif.dev_class,
                       p_data->cfm_req.dev_class);
        bd_name_copy(sec_event.key_notif.bd_name, p_data->cfm_req.bd_name);
        /* Due to the switch case falling through below to BTM_SP_KEY_NOTIF_EVT,
           call remote name request using values from cfm_req */
        if (p_data->cfm_req.bd_name[0] == 0) {
          bta_dm_cb.pin_evt = pin_evt;
          bta_dm_cb.pin_bd_addr = p_data->cfm_req.bd_addr;
          bta_dm_cb.rmt_io_caps = sec_event.cfm_req.rmt_io_caps;
          bta_dm_cb.loc_io_caps = sec_event.cfm_req.loc_io_caps;
          bta_dm_cb.rmt_auth_req = sec_event.cfm_req.rmt_auth_req;
          bta_dm_cb.loc_auth_req = sec_event.cfm_req.loc_auth_req;

          dev_class_copy(bta_dm_cb.pin_dev_class, p_data->cfm_req.dev_class);
          {
            const tBTM_STATUS btm_status = BTM_ReadRemoteDeviceName(
                p_data->cfm_req.bd_addr, bta_dm_pinname_cback,
                BT_TRANSPORT_BR_EDR);
            switch (btm_status) {
              case BTM_CMD_STARTED:
                return btm_status;
              default:
                // NOTE: This will issue callback on this failure path
                LOG_WARN("Failed to start Remote Name Request btm_status:%s",
                         btm_status_text(btm_status).c_str());
            };
          }
        }
      }

      if (BTM_SP_KEY_NOTIF_EVT == event) {
        /* If the device name is not known, save bdaddr and devclass
           and initiate a name request with values from key_notif */
        if (p_data->key_notif.bd_name[0] == 0) {
          bta_dm_cb.pin_evt = pin_evt;
          bta_dm_cb.pin_bd_addr = p_data->key_notif.bd_addr;
          BTA_COPY_DEVICE_CLASS(bta_dm_cb.pin_dev_class,
                                p_data->key_notif.dev_class);
          if ((BTM_ReadRemoteDeviceName(
                  p_data->key_notif.bd_addr, bta_dm_pinname_cback,
                  BT_TRANSPORT_BR_EDR)) == BTM_CMD_STARTED)
            return BTM_CMD_STARTED;
          APPL_TRACE_WARNING(
              " bta_dm_sp_cback() -> Failed to start Remote Name Request  ");
        } else {
          sec_event.key_notif.bd_addr = p_data->key_notif.bd_addr;
          BTA_COPY_DEVICE_CLASS(sec_event.key_notif.dev_class,
                                p_data->key_notif.dev_class);
          strlcpy((char*)sec_event.key_notif.bd_name,
                  (char*)p_data->key_notif.bd_name, BD_NAME_LEN + 1);
          sec_event.key_notif.bd_name[BD_NAME_LEN] = 0;
        }
      }

      bta_dm_cb.p_sec_cback(pin_evt, &sec_event);

      break;

    case BTM_SP_LOC_OOB_EVT:
#ifdef BTIF_DM_OOB_TEST
      btif_dm_proc_loc_oob(BT_TRANSPORT_BR_EDR,
                           (bool)(p_data->loc_oob.status == BTM_SUCCESS),
                           p_data->loc_oob.c, p_data->loc_oob.r);
#endif
      break;

    case BTM_SP_RMT_OOB_EVT: {
      Octet16 c;
      Octet16 r;
      sp_rmt_result = false;
#ifdef BTIF_DM_OOB_TEST
      sp_rmt_result = btif_dm_proc_rmt_oob(p_data->rmt_oob.bd_addr, &c, &r);
#endif
      BTIF_TRACE_DEBUG("bta_dm_ci_rmt_oob: result=%d", sp_rmt_result);
      bta_dm_ci_rmt_oob(sp_rmt_result, p_data->rmt_oob.bd_addr, c, r);
      break;
    }

    default:
      status = BTM_NOT_AUTHORIZED;
      break;
  }
  APPL_TRACE_EVENT("dm status: %d", status);
  return status;
}

/*******************************************************************************
 *
 * Function         bta_dm_local_name_cback
 *
 * Description      Callback from btm after local name is read
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_local_name_cback(UNUSED_ATTR void* p_name) {
  BTIF_dm_enable();
}

static void handle_role_change(const RawAddress& bd_addr, tHCI_ROLE new_role,
                               tHCI_STATUS hci_status) {
  tBTA_DM_PEER_DEVICE* p_dev = bta_dm_find_peer_device(bd_addr);
  if (!p_dev) {
    LOG_WARN(
        "Unable to find device for role change peer:%s new_role:%s "
        "hci_status:%s",
        ADDRESS_TO_LOGGABLE_CSTR(bd_addr), RoleText(new_role).c_str(),
        hci_error_code_text(hci_status).c_str());
    return;
  }

  LOG_INFO(
      "Role change callback peer:%s info:%s new_role:%s dev count:%d "
      "hci_status:%s",
      ADDRESS_TO_LOGGABLE_CSTR(bd_addr), p_dev->info_text().c_str(),
      RoleText(new_role).c_str(), bta_dm_cb.device_list.count,
      hci_error_code_text(hci_status).c_str());

  if (p_dev->is_av_active()) {
    bool need_policy_change = false;

    /* there's AV activity on this link */
    if (new_role == HCI_ROLE_PERIPHERAL && bta_dm_cb.device_list.count > 1 &&
        hci_status == HCI_SUCCESS) {
      /* more than one connections and the AV connection is role switched
       * to peripheral
       * switch it back to central and remove the switch policy */
      BTM_SwitchRoleToCentral(bd_addr);
      need_policy_change = true;
    } else if (p_bta_dm_cfg->avoid_scatter && (new_role == HCI_ROLE_CENTRAL)) {
      /* if the link updated to be central include AV activities, remove
       * the switch policy */
      need_policy_change = true;
    }

    if (need_policy_change) {
      BTM_block_role_switch_for(p_dev->peer_bdaddr);
    }
  } else {
    /* there's AV no activity on this link and role switch happened
     * check if AV is active
     * if so, make sure the AV link is central */
    bta_dm_check_av();
  }
  bta_sys_notify_role_chg(bd_addr, new_role, hci_status);
}

void BTA_dm_report_role_change(const RawAddress bd_addr, tHCI_ROLE new_role,
                               tHCI_STATUS hci_status) {
  do_in_main_thread(FROM_HERE, base::BindOnce(handle_role_change, bd_addr,
                                              new_role, hci_status));
}

void handle_remote_features_complete(const RawAddress& bd_addr) {
  tBTA_DM_PEER_DEVICE* p_dev = bta_dm_find_peer_device(bd_addr);
  if (!p_dev) {
    LOG_WARN("Unable to find device peer:%s", ADDRESS_TO_LOGGABLE_CSTR(bd_addr));
    return;
  }

  if (controller_get_interface()->supports_sniff_subrating() &&
      acl_peer_supports_sniff_subrating(bd_addr)) {
    LOG_DEBUG("Device supports sniff subrating peer:%s",
              ADDRESS_TO_LOGGABLE_CSTR(bd_addr));
    p_dev->set_both_device_ssr_capable();
  } else {
    LOG_DEBUG("Device does NOT support sniff subrating peer:%s",
              ADDRESS_TO_LOGGABLE_CSTR(bd_addr));
  }
}

void BTA_dm_notify_remote_features_complete(const RawAddress bd_addr) {
  do_in_main_thread(FROM_HERE,
                    base::BindOnce(handle_remote_features_complete, bd_addr));
}

static tBTA_DM_PEER_DEVICE* allocate_device_for(const RawAddress& bd_addr,
                                                tBT_TRANSPORT transport) {
  for (uint8_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    auto device = &bta_dm_cb.device_list.peer_device[i];
    if (device->peer_bdaddr == bd_addr && device->transport == transport) {
      return device;
    }
  }

  if (bta_dm_cb.device_list.count < BTA_DM_NUM_PEER_DEVICE) {
    auto device =
        &bta_dm_cb.device_list.peer_device[bta_dm_cb.device_list.count];
    device->peer_bdaddr = bd_addr;
    bta_dm_cb.device_list.count++;
    if (transport == BT_TRANSPORT_LE) {
      bta_dm_cb.device_list.le_count++;
    }
    return device;
  }
  return nullptr;
}

void bta_dm_acl_up(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                   uint16_t acl_handle) {
  auto device = allocate_device_for(bd_addr, transport);
  if (device == nullptr) {
    LOG_WARN("Unable to allocate device resources for new connection");
    return;
  }
  LOG_INFO("Acl connected peer:%s transport:%s handle:%hu",
           ADDRESS_TO_LOGGABLE_CSTR(bd_addr),
           bt_transport_text(transport).c_str(), acl_handle);
  device->conn_state = BTA_DM_CONNECTED;
  device->pref_role = BTA_ANY_ROLE;
  device->reset_device_info();
  device->transport = transport;

  if (controller_get_interface()->supports_sniff_subrating() &&
      acl_peer_supports_sniff_subrating(bd_addr)) {
    // NOTE: This callback assumes upon ACL connection that
    // the read remote features has completed and is valid.
    // The only guaranteed contract for valid read remote features
    // data is when the BTA_dm_notify_remote_features_complete()
    // callback has completed.  The below assignment is kept for
    // transitional informational purposes only.
    device->set_both_device_ssr_capable();
  }

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC conn;
    memset(&conn, 0, sizeof(tBTA_DM_SEC));
    conn.link_up.bd_addr = bd_addr;
    conn.link_up.transport_link_type = transport;
    conn.link_up.acl_handle = acl_handle;

    bta_dm_cb.p_sec_cback(BTA_DM_LINK_UP_EVT, &conn);
    LOG_DEBUG("Executed security callback for new connection available");
  }
  bta_dm_adjust_roles(true);
}

void BTA_dm_acl_up(const RawAddress bd_addr, tBT_TRANSPORT transport,
                   uint16_t acl_handle) {
  do_in_main_thread(
      FROM_HERE, base::BindOnce(bta_dm_acl_up, bd_addr, transport, acl_handle));
}

static void bta_dm_acl_up_failed(const RawAddress bd_addr,
                                 tBT_TRANSPORT transport, tHCI_STATUS status) {
  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC conn = {};
    conn.link_up_failed.bd_addr = bd_addr;
    conn.link_up_failed.transport_link_type = transport;
    conn.link_up_failed.status = status;
    bta_dm_cb.p_sec_cback(BTA_DM_LINK_UP_FAILED_EVT, &conn);
  }
}

void BTA_dm_acl_up_failed(const RawAddress bd_addr, tBT_TRANSPORT transport,
                          tHCI_STATUS status) {
  do_in_main_thread(FROM_HERE, base::BindOnce(bta_dm_acl_up_failed, bd_addr,
                                              transport, status));
}

static void bta_dm_acl_down(const RawAddress& bd_addr,
                            tBT_TRANSPORT transport) {
  bool issue_unpair_cb = false;
  bool remove_device = false;

  for (uint8_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    auto device = &bta_dm_cb.device_list.peer_device[i];
    if (device->peer_bdaddr != bd_addr || device->transport != transport)
      continue;

    if (device->conn_state == BTA_DM_UNPAIRING) {
      issue_unpair_cb = BTM_SecDeleteDevice(device->peer_bdaddr);

      /* remove all cached GATT information */
      get_gatt_interface().BTA_GATTC_Refresh(bd_addr);

      APPL_TRACE_DEBUG("%s: Unpairing: issue unpair CB = %d ", __func__,
                       issue_unpair_cb);
    }

    remove_device = device->remove_dev_pending;

    // Iterate to the one before the last when shrinking the list,
    // otherwise we memcpy garbage data into the record.
    // Then clear out the last item in the list since we are shrinking.
    for (; i < bta_dm_cb.device_list.count - 1; i++) {
      memcpy(&bta_dm_cb.device_list.peer_device[i],
             &bta_dm_cb.device_list.peer_device[i + 1],
             sizeof(bta_dm_cb.device_list.peer_device[i]));
    }
    if (bta_dm_cb.device_list.count > 0) {
      int clear_index = bta_dm_cb.device_list.count - 1;
      memset(&bta_dm_cb.device_list.peer_device[clear_index], 0,
             sizeof(bta_dm_cb.device_list.peer_device[clear_index]));
    }
    break;
  }
  if (bta_dm_cb.device_list.count) bta_dm_cb.device_list.count--;
  if ((transport == BT_TRANSPORT_LE) && (bta_dm_cb.device_list.le_count)) {
    bta_dm_cb.device_list.le_count--;
  }

  if ((transport == BT_TRANSPORT_BR_EDR) &&
      (bta_dm_search_cb.wait_disc && bta_dm_search_cb.peer_bdaddr == bd_addr)) {
    bta_dm_search_cb.wait_disc = false;

    if (bta_dm_search_cb.sdp_results) {
      APPL_TRACE_EVENT(" timer stopped  ");
      alarm_cancel(bta_dm_search_cb.search_timer);
      bta_dm_disc_discover_next_device();
    }
  }

  if (bta_dm_cb.disabling) {
    if (!BTM_GetNumAclLinks()) {
      /*
       * Start a timer to make sure that the profiles
       * get the disconnect event.
       */
      alarm_set_on_mloop(bta_dm_cb.disable_timer,
                         BTA_DM_DISABLE_CONN_DOWN_TIMER_MS,
                         bta_dm_disable_conn_down_timer_cback, NULL);
    }
  }
  if (remove_device) {
    LOG_INFO("remove_dev_pending actually removing %s",
             ADDRESS_TO_LOGGABLE_CSTR(bd_addr));
    bta_dm_process_remove_device_no_callback(bd_addr);
  }

  if (bta_dm_cb.p_sec_cback) {
    tBTA_DM_SEC conn;
    memset(&conn, 0, sizeof(tBTA_DM_SEC));
    conn.link_down.bd_addr = bd_addr;
    conn.link_down.transport_link_type = transport;

    bta_dm_cb.p_sec_cback(BTA_DM_LINK_DOWN_EVT, &conn);
    if (issue_unpair_cb) bta_dm_cb.p_sec_cback(BTA_DM_DEV_UNPAIRED_EVT, &conn);
  }

  bta_dm_adjust_roles(true);
}

void BTA_dm_acl_down(const RawAddress bd_addr, tBT_TRANSPORT transport) {
  do_in_main_thread(FROM_HERE,
                    base::BindOnce(bta_dm_acl_down, bd_addr, transport));
}

/*******************************************************************************
 *
 * Function         bta_dm_check_av
 *
 * Description      This function checks if AV is active
 *                  if yes, make sure the AV link is central
 *
 ******************************************************************************/
static void bta_dm_check_av() {
  uint8_t i;
  tBTA_DM_PEER_DEVICE* p_dev;

  if (bta_dm_cb.cur_av_count) {
    LOG_INFO("av_count:%d", bta_dm_cb.cur_av_count);
    for (i = 0; i < bta_dm_cb.device_list.count; i++) {
      p_dev = &bta_dm_cb.device_list.peer_device[i];
      APPL_TRACE_WARNING("[%d]: state:%d, info:%s", i, p_dev->conn_state,
                         p_dev->info_text().c_str());
      if ((p_dev->conn_state == BTA_DM_CONNECTED) && p_dev->is_av_active()) {
        /* make central and take away the role switch policy */
        BTM_SwitchRoleToCentral(p_dev->peer_bdaddr);
        /* else either already central or can not switch for some reasons */
        BTM_block_role_switch_for(p_dev->peer_bdaddr);
        break;
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_disable_conn_down_timer_cback
 *
 * Description      Sends disable event to application
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_disable_conn_down_timer_cback(UNUSED_ATTR void* data) {
  /* disable the power managment module */
  bta_dm_disable_pm();

  bta_dm_cb.disabling = false;
  LOG_INFO("Stack device manager shutdown completed");
  future_ready(stack_manager_get_hack_future(), FUTURE_SUCCESS);
}

/*******************************************************************************
 *
 * Function         bta_dm_rm_cback
 *
 * Description      Role management callback from sys
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_rm_cback(tBTA_SYS_CONN_STATUS status, tBTA_SYS_ID id,
                            uint8_t app_id, const RawAddress& peer_addr) {
  uint8_t j;
  tBTA_PREF_ROLES role;
  tBTA_DM_PEER_DEVICE* p_dev;

  LOG_DEBUG("BTA Role management callback count:%d status:%s peer:%s",
            bta_dm_cb.cur_av_count, bta_sys_conn_status_text(status).c_str(),
            ADDRESS_TO_LOGGABLE_CSTR(peer_addr));

  p_dev = bta_dm_find_peer_device(peer_addr);
  if (status == BTA_SYS_CONN_OPEN) {
    if (p_dev) {
      /* Do not set to connected if we are in the middle of unpairing. When AV
       * stream is
       * started it fakes out a SYS_CONN_OPEN to potentially trigger a role
       * switch command.
       * But this should not be done if we are in the middle of unpairing.
       */
      if (p_dev->conn_state != BTA_DM_UNPAIRING)
        p_dev->conn_state = BTA_DM_CONNECTED;

      for (j = 1; j <= p_bta_dm_rm_cfg[0].app_id; j++) {
        if (((p_bta_dm_rm_cfg[j].app_id == app_id) ||
             (p_bta_dm_rm_cfg[j].app_id == BTA_ALL_APP_ID)) &&
            (p_bta_dm_rm_cfg[j].id == id)) {
          ASSERT_LOG(p_bta_dm_rm_cfg[j].cfg <= BTA_PERIPHERAL_ROLE_ONLY,
                     "Passing illegal preferred role:0x%02x [0x%02x<=>0x%02x]",
                     p_bta_dm_rm_cfg[j].cfg, BTA_ANY_ROLE,
                     BTA_PERIPHERAL_ROLE_ONLY);
          role = static_cast<tBTA_PREF_ROLES>(p_bta_dm_rm_cfg[j].cfg);
          if (role > p_dev->pref_role) p_dev->pref_role = role;
          break;
        }
      }
    }
  }

  if (BTA_ID_AV == id) {
    if (status == BTA_SYS_CONN_BUSY) {
      if (p_dev) p_dev->set_av_active();
      /* AV calls bta_sys_conn_open with the A2DP stream count as app_id */
      if (BTA_ID_AV == id) bta_dm_cb.cur_av_count = bta_dm_get_av_count();
    } else if (status == BTA_SYS_CONN_IDLE) {
      if (p_dev) p_dev->reset_av_active();

      /* get cur_av_count from connected services */
      if (BTA_ID_AV == id) bta_dm_cb.cur_av_count = bta_dm_get_av_count();
    }
  }

  /* Don't adjust roles for each busy/idle state transition to avoid
     excessive switch requests when individual profile busy/idle status
     changes */
  if ((status != BTA_SYS_CONN_BUSY) && (status != BTA_SYS_CONN_IDLE))
    bta_dm_adjust_roles(false);
}

/*******************************************************************************
 *
 * Function         bta_dm_delay_role_switch_cback
 *
 * Description      Callback from btm to delay a role switch
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_delay_role_switch_cback(UNUSED_ATTR void* data) {
  APPL_TRACE_EVENT("%s: initiating Delayed RS", __func__);
  bta_dm_adjust_roles(false);
}

/*******************************************************************************
 *
 * Function         bta_dm_reset_sec_dev_pending
 *
 * Description      Setting the remove device pending status to false from
 *                  security device DB, when the link key notification
 *                  event comes.
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_reset_sec_dev_pending(const RawAddress& remote_bd_addr) {
  for (size_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    auto& dev = bta_dm_cb.device_list.peer_device[i];
    if (dev.peer_bdaddr == remote_bd_addr) {
      if (dev.remove_dev_pending) {
        LOG_INFO("Clearing remove_dev_pending for %s",
                 ADDRESS_TO_LOGGABLE_CSTR(dev.peer_bdaddr));
        dev.remove_dev_pending = false;
      }
      return;
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_remove_sec_dev_entry
 *
 * Description      Removes device entry from Security device DB if ACL
 connection with
 *                  remtoe device does not exist, else schedule for dev entry
 removal upon
                     ACL close
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_remove_sec_dev_entry(const RawAddress& remote_bd_addr) {
  if (BTM_IsAclConnectionUp(remote_bd_addr, BT_TRANSPORT_LE) ||
      BTM_IsAclConnectionUp(remote_bd_addr, BT_TRANSPORT_BR_EDR)) {
    APPL_TRACE_DEBUG(
        "%s ACL is not down. Schedule for  Dev Removal when ACL closes",
        __func__);
    BTM_SecClearSecurityFlags(remote_bd_addr);
    for (int i = 0; i < bta_dm_cb.device_list.count; i++) {
      auto& dev = bta_dm_cb.device_list.peer_device[i];
      if (dev.peer_bdaddr == remote_bd_addr) {
        LOG_INFO("Setting remove_dev_pending for %s",
                 ADDRESS_TO_LOGGABLE_CSTR(dev.peer_bdaddr));
        dev.remove_dev_pending = TRUE;
        break;
      }
    }
  } else {
    // remote_bd_addr comes from security record, which is removed in
    // BTM_SecDeleteDevice.
    RawAddress addr_copy = remote_bd_addr;
    bta_dm_process_remove_device_no_callback(addr_copy);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_adjust_roles
 *
 * Description      Adjust roles
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_adjust_roles(bool delay_role_switch) {
  uint8_t i;
  uint8_t link_count = bta_dm_cb.device_list.count;
  if (link_count) {
    for (i = 0; i < bta_dm_cb.device_list.count; i++) {
      if (bta_dm_cb.device_list.peer_device[i].conn_state == BTA_DM_CONNECTED &&
          bta_dm_cb.device_list.peer_device[i].transport ==
              BT_TRANSPORT_BR_EDR) {
        if ((bta_dm_cb.device_list.peer_device[i].pref_role ==
             BTA_CENTRAL_ROLE_ONLY) ||
            (link_count > 1)) {
          /* Initiating immediate role switch with certain remote devices
            has caused issues due to role  switch colliding with link encryption
            setup and
            causing encryption (and in turn the link) to fail .  These device .
            Firmware
            versions are stored in a rejectlist and role switch with these
            devices are
            delayed to avoid the collision with link encryption setup */

          if (bta_dm_cb.device_list.peer_device[i].pref_role !=
                  BTA_PERIPHERAL_ROLE_ONLY &&
              !delay_role_switch) {
            BTM_SwitchRoleToCentral(
                bta_dm_cb.device_list.peer_device[i].peer_bdaddr);
          } else {
            alarm_set_on_mloop(bta_dm_cb.switch_delay_timer,
                               BTA_DM_SWITCH_DELAY_TIMER_MS,
                               bta_dm_delay_role_switch_cback, NULL);
          }
        }
      }
    }
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_get_remname
 *
 * Description      Returns a pointer to the remote name stored in the DM
 *                  control block if it exists, or from the BTM memory.
 *
 * Returns          char * - Pointer to the remote device name
 ******************************************************************************/
static const char* bta_dm_get_remname(void) {
  const char* p_name = (const char*)bta_dm_search_cb.peer_name;

  /* If the name isn't already stored, try retrieving from BTM */
  if (*p_name == '\0') {
    const char* p_temp = get_btm_client_interface().security.BTM_SecReadDevName(
        bta_dm_search_cb.peer_bdaddr);
    if (p_temp != NULL) p_name = (const char*)p_temp;
  }

  return p_name;
}

/*******************************************************************************
 *
 * Function         bta_dm_bond_cancel_complete_cback
 *
 * Description      Authentication complete callback from BTM
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_bond_cancel_complete_cback(tBTM_STATUS result) {
  tBTA_DM_SEC sec_event;

  if (result == BTM_SUCCESS)
    sec_event.bond_cancel_cmpl.result = BTA_SUCCESS;
  else
    sec_event.bond_cancel_cmpl.result = BTA_FAILURE;

  if (bta_dm_cb.p_sec_cback) {
    bta_dm_cb.p_sec_cback(BTA_DM_BOND_CANCEL_CMPL_EVT, &sec_event);
  }
}

/*******************************************************************************
 *
 * Function         find_utf8_char_boundary
 *
 * Description      This function checks a UTF8 string |utf8str| starting at
 *                  |offset|, moving backwards and returns the offset of the
 *                  next valid UTF8 character boundary found.
 *
 * Returns          Offset of UTF8 character boundary
 *
 ******************************************************************************/
static size_t find_utf8_char_boundary(const char* utf8str, size_t offset) {
  CHECK(utf8str);
  CHECK(offset > 0);

  while (--offset) {
    uint8_t ch = (uint8_t)utf8str[offset];
    if ((ch & 0x80) == 0x00)  // ASCII
      return offset + 1;
    if ((ch & 0xC0) == 0xC0)  // Multi-byte sequence start
      return offset;
  }

  return 0;
}

/*******************************************************************************
 *
 * Function         bta_dm_set_eir
 *
 * Description      This function creates EIR tagged data and writes it to
 *                  controller.
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_dm_set_eir(char* local_name) {
  uint8_t* p;
  uint8_t* p_length;
#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
  uint8_t* p_type;
  uint8_t max_num_uuid;
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t custom_uuid_idx;
#endif  // BTA_EIR_SERVER_NUM_CUSTOM_UUID
#endif  // BTA_EIR_CANNED_UUID_LIST
#if (BTM_EIR_DEFAULT_FEC_REQUIRED == FALSE)
  uint8_t free_eir_length = HCI_EXT_INQ_RESPONSE_LEN;
#else  // BTM_EIR_DEFAULT_FEC_REQUIRED
  uint8_t free_eir_length = HCI_DM5_PACKET_SIZE;
#endif  // BTM_EIR_DEFAULT_FEC_REQUIRED
  uint8_t num_uuid;
  uint8_t data_type;
  uint8_t local_name_len;

  /* wait until complete to disable */
  if (alarm_is_scheduled(bta_dm_cb.disable_timer)) return;

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
  /* if local name is not provided, get it from controller */
  if (local_name == NULL) {
    if (BTM_ReadLocalDeviceName((const char**)&local_name) != BTM_SUCCESS) {
      APPL_TRACE_ERROR("Fail to read local device name for EIR");
    }
  }
#endif  // BTA_EIR_CANNED_UUID_LIST

  /* Allocate a buffer to hold HCI command */
  BT_HDR* p_buf = (BT_HDR*)osi_malloc(BTM_CMD_BUF_SIZE);
  ASSERT(p_buf != nullptr);
  p = (uint8_t*)p_buf + BTM_HCI_EIR_OFFSET;

  memset(p, 0x00, HCI_EXT_INQ_RESPONSE_LEN);

  LOG_INFO("Generating extended inquiry response packet EIR");

  if (local_name)
    local_name_len = strlen(local_name);
  else
    local_name_len = 0;

  data_type = HCI_EIR_COMPLETE_LOCAL_NAME_TYPE;
  /* if local name is longer than minimum length of shortened name */
  /* check whether it needs to be shortened or not */
  if (local_name_len > p_bta_dm_eir_cfg->bta_dm_eir_min_name_len) {
/* get number of UUID 16-bit list */
#if (BTA_EIR_CANNED_UUID_LIST == TRUE)
    num_uuid = p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len / Uuid::kNumBytes16;
#else   // BTA_EIR_CANNED_UUID_LIST
    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes16;
    data_type = get_btm_client_interface().eir.BTM_GetEirSupportedServices(
        bta_dm_cb.eir_uuid, &p, max_num_uuid, &num_uuid);
    p = (uint8_t*)p_buf + BTM_HCI_EIR_OFFSET; /* reset p */
#endif  // BTA_EIR_CANNED_UUID_LIST

    /* if UUID doesn't fit remaing space, shorten local name */
    if (local_name_len > (free_eir_length - 4 - num_uuid * Uuid::kNumBytes16)) {
      local_name_len = find_utf8_char_boundary(
          local_name, p_bta_dm_eir_cfg->bta_dm_eir_min_name_len);
      APPL_TRACE_WARNING("%s local name is shortened (%d)", __func__,
                         local_name_len);
      data_type = HCI_EIR_SHORTENED_LOCAL_NAME_TYPE;
    } else {
      data_type = HCI_EIR_COMPLETE_LOCAL_NAME_TYPE;
    }
  }

  UINT8_TO_STREAM(p, local_name_len + 1);
  UINT8_TO_STREAM(p, data_type);

  if (local_name != NULL) {
    memcpy(p, local_name, local_name_len);
    p += local_name_len;
  }
  free_eir_length -= local_name_len + 2;

#if (BTA_EIR_CANNED_UUID_LIST == TRUE)
  /* if UUID list is provided as static data in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_uuid16)) {
    if (free_eir_length > Uuid::kNumBytes16 + 2) {
      free_eir_length -= 2;

      if (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len) {
        num_uuid = p_bta_dm_eir_cfg->bta_dm_eir_uuid16_len / Uuid::kNumBytes16;
        data_type = HCI_EIR_COMPLETE_16BITS_UUID_TYPE;
      } else /* not enough room for all UUIDs */
      {
        APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
        num_uuid = free_eir_length / Uuid::kNumBytes16;
        data_type = HCI_EIR_MORE_16BITS_UUID_TYPE;
      }
      UINT8_TO_STREAM(p, num_uuid * Uuid::kNumBytes16 + 1);
      UINT8_TO_STREAM(p, data_type);
      memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_uuid16,
             num_uuid * Uuid::kNumBytes16);
      p += num_uuid * Uuid::kNumBytes16;
      free_eir_length -= num_uuid * Uuid::kNumBytes16;
    }
  }
#else /* (BTA_EIR_CANNED_UUID_LIST == TRUE) */
  /* if UUID list is dynamic */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes16;
    data_type = get_btm_client_interface().eir.BTM_GetEirSupportedServices(
        bta_dm_cb.eir_uuid, &p, max_num_uuid, &num_uuid);

    if (data_type == HCI_EIR_MORE_16BITS_UUID_TYPE) {
      APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
    }
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
    else {
      for (custom_uuid_idx = 0;
           custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
           custom_uuid_idx++) {
        const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
        if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes16) {
          if (num_uuid < max_num_uuid) {
            UINT16_TO_STREAM(p, curr.As16Bit());
            num_uuid++;
          } else {
            data_type = HCI_EIR_MORE_16BITS_UUID_TYPE;
            APPL_TRACE_WARNING("BTA EIR: UUID 16-bit list is truncated");
            break;
          }
        }
      }
    }
#endif /* (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0) */

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes16 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes16 + 2;
  }
#endif /* (BTA_EIR_CANNED_UUID_LIST == TRUE) */

#if (BTA_EIR_CANNED_UUID_LIST != TRUE && BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  /* Adding 32-bit UUID list */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;
    data_type = HCI_EIR_COMPLETE_32BITS_UUID_TYPE;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes32;

    for (custom_uuid_idx = 0; custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
         custom_uuid_idx++) {
      const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
      if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes32) {
        if (num_uuid < max_num_uuid) {
          UINT32_TO_STREAM(p, curr.As32Bit());
          num_uuid++;
        } else {
          data_type = HCI_EIR_MORE_32BITS_UUID_TYPE;
          APPL_TRACE_WARNING("BTA EIR: UUID 32-bit list is truncated");
          break;
        }
      }
    }

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes32 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes32 + 2;
  }

  /* Adding 128-bit UUID list */
  if (free_eir_length >= 2) {
    p_length = p++;
    p_type = p++;
    num_uuid = 0;
    data_type = HCI_EIR_COMPLETE_128BITS_UUID_TYPE;

    max_num_uuid = (free_eir_length - 2) / Uuid::kNumBytes128;

    for (custom_uuid_idx = 0; custom_uuid_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID;
         custom_uuid_idx++) {
      const Uuid& curr = bta_dm_cb.bta_custom_uuid[custom_uuid_idx].custom_uuid;
      if (curr.GetShortestRepresentationSize() == Uuid::kNumBytes128) {
        if (num_uuid < max_num_uuid) {
          ARRAY16_TO_STREAM(p, curr.To128BitBE().data());
          num_uuid++;
        } else {
          data_type = HCI_EIR_MORE_128BITS_UUID_TYPE;
          APPL_TRACE_WARNING("BTA EIR: UUID 128-bit list is truncated");
          break;
        }
      }
    }

    UINT8_TO_STREAM(p_length, num_uuid * Uuid::kNumBytes128 + 1);
    UINT8_TO_STREAM(p_type, data_type);
    free_eir_length -= num_uuid * Uuid::kNumBytes128 + 2;
  }
#endif /* ( BTA_EIR_CANNED_UUID_LIST != TRUE \
          )&&(BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0) */

  /* if Flags are provided in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_flag_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_flags) &&
      (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 2)) {
    UINT8_TO_STREAM(p, p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 1);
    UINT8_TO_STREAM(p, HCI_EIR_FLAGS_TYPE);
    memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_flags,
           p_bta_dm_eir_cfg->bta_dm_eir_flag_len);
    p += p_bta_dm_eir_cfg->bta_dm_eir_flag_len;
    free_eir_length -= p_bta_dm_eir_cfg->bta_dm_eir_flag_len + 2;
  }

  /* if Manufacturer Specific are provided in configuration */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len > 0) &&
      (p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec) &&
      (free_eir_length >= p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 2)) {
    p_length = p;

    UINT8_TO_STREAM(p, p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 1);
    UINT8_TO_STREAM(p, HCI_EIR_MANUFACTURER_SPECIFIC_TYPE);
    memcpy(p, p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec,
           p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len);
    p += p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len;
    free_eir_length -= p_bta_dm_eir_cfg->bta_dm_eir_manufac_spec_len + 2;

  } else {
    p_length = NULL;
  }

  /* if Inquiry Tx Resp Power compiled */
  if ((p_bta_dm_eir_cfg->bta_dm_eir_inq_tx_power) && (free_eir_length >= 3)) {
    UINT8_TO_STREAM(p, 2); /* Length field */
    UINT8_TO_STREAM(p, HCI_EIR_TX_POWER_LEVEL_TYPE);
    UINT8_TO_STREAM(p, *(p_bta_dm_eir_cfg->bta_dm_eir_inq_tx_power));
    free_eir_length -= 3;
  }

  if (free_eir_length)
    UINT8_TO_STREAM(p, 0); /* terminator of significant part */

  get_btm_client_interface().eir.BTM_WriteEIR(p_buf);
}

#if (BTA_EIR_CANNED_UUID_LIST != TRUE)
/*******************************************************************************
 *
 * Function         bta_dm_get_cust_uuid_index
 *
 * Description      Get index of custom uuid from list
 *                  Note, handle equals to 0 means to find a vacant
 *                  from list.
 *
 * Returns          Index of array
 *                  bta_dm_cb.bta_custom_uuid[BTA_EIR_SERVER_NUM_CUSTOM_UUID]
 *
 ******************************************************************************/
static uint8_t bta_dm_get_cust_uuid_index(uint32_t handle) {
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t c_uu_idx = 0;

  while(c_uu_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID &&
      bta_dm_cb.bta_custom_uuid[c_uu_idx].handle != handle) {
    c_uu_idx++;
  }

  return c_uu_idx;
#else
  return 0;
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_update_cust_uuid
 *
 * Description      Update custom uuid with given value
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_dm_update_cust_uuid(uint8_t c_uu_idx, const Uuid& uuid, uint32_t handle) {
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  if (c_uu_idx < BTA_EIR_SERVER_NUM_CUSTOM_UUID) {
    tBTA_CUSTOM_UUID& curr = bta_dm_cb.bta_custom_uuid[c_uu_idx];
    curr.custom_uuid.UpdateUuid(uuid);
    curr.handle = handle;
  } else {
    APPL_TRACE_ERROR("%s invalid uuid index %d", __func__, c_uu_idx);
  }
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_eir_update_cust_uuid
 *
 * Description      This function adds or removes custom service UUID in EIR database.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_dm_eir_update_cust_uuid(const tBTA_CUSTOM_UUID& curr, bool adding) {
  APPL_TRACE_DEBUG("%s", __func__);
#if (BTA_EIR_SERVER_NUM_CUSTOM_UUID > 0)
  uint8_t c_uu_idx = 0;
  if (adding) {
    c_uu_idx = bta_dm_get_cust_uuid_index(0); /* find a vacant from uuid list */
    bta_dm_update_cust_uuid(c_uu_idx, curr.custom_uuid, curr.handle);
  } else {
    c_uu_idx = bta_dm_get_cust_uuid_index(curr.handle); /* find the uuid from uuid list */
    bta_dm_update_cust_uuid(c_uu_idx, curr.custom_uuid, 0);
  }

  /* Update EIR when UUIDs are changed */
  if (c_uu_idx <= BTA_EIR_SERVER_NUM_CUSTOM_UUID) {
    bta_dm_set_eir(NULL);
  }
#endif
}

/*******************************************************************************
 *
 * Function         bta_dm_eir_update_uuid
 *
 * Description      This function adds or removes service UUID in EIR database.
 *
 * Returns          None
 *
 ******************************************************************************/
void bta_dm_eir_update_uuid(uint16_t uuid16, bool adding) {
  /* if this UUID is not advertised in EIR */
  if (!BTM_HasEirService(p_bta_dm_eir_cfg->uuid_mask, uuid16)) return;

  if (adding) {
    LOG_INFO("EIR Adding UUID=0x%04X into extended inquiry response", uuid16);

    BTM_AddEirService(bta_dm_cb.eir_uuid, uuid16);
  } else {
    LOG_INFO("EIR Removing UUID=0x%04X from extended inquiry response", uuid16);

    get_btm_client_interface().eir.BTM_RemoveEirService(bta_dm_cb.eir_uuid,
                                                        uuid16);
  }

  bta_dm_set_eir(NULL);
}
#endif

static tBTA_DM_PEER_DEVICE* find_connected_device(
    const RawAddress& bd_addr, UNUSED_ATTR tBT_TRANSPORT transport) {
  for (uint8_t i = 0; i < bta_dm_cb.device_list.count; i++) {
    if (bta_dm_cb.device_list.peer_device[i].peer_bdaddr == bd_addr &&
        bta_dm_cb.device_list.peer_device[i].conn_state == BTA_DM_CONNECTED)
      return &bta_dm_cb.device_list.peer_device[i];
  }
  return nullptr;
}

/*******************************************************************************
 *
 * Function         bta_dm_encrypt_cback
 *
 * Description      link encryption complete callback.
 *
 * Returns         None
 *
 ******************************************************************************/
void bta_dm_encrypt_cback(const RawAddress* bd_addr, tBT_TRANSPORT transport,
                          UNUSED_ATTR void* p_ref_data, tBTM_STATUS result) {
  tBTA_DM_ENCRYPT_CBACK* p_callback = nullptr;
  tBTA_DM_PEER_DEVICE* device = find_connected_device(*bd_addr, transport);
  if (device != nullptr) {
    p_callback = device->p_encrypt_cback;
    device->p_encrypt_cback = nullptr;
  }

  tBTA_STATUS bta_status = BTA_SUCCESS;
  switch (result) {
    case BTM_SUCCESS:
      LOG_WARN("Encrypted link peer:%s transport:%s status:%s callback:%c",
               ADDRESS_TO_LOGGABLE_CSTR((*bd_addr)),
               bt_transport_text(transport).c_str(),
               btm_status_text(result).c_str(), (p_callback) ? 'T' : 'F');
      break;
    case BTM_WRONG_MODE:
      LOG_WARN(
          "Unable to encrypt link peer:%s transport:%s status:%s callback:%c",
          ADDRESS_TO_LOGGABLE_CSTR((*bd_addr)), bt_transport_text(transport).c_str(),
          btm_status_text(result).c_str(), (p_callback) ? 'T' : 'F');
      bta_status = BTA_WRONG_MODE;
      break;
    case BTM_NO_RESOURCES:
      LOG_WARN(
          "Unable to encrypt link peer:%s transport:%s status:%s callback:%c",
          ADDRESS_TO_LOGGABLE_CSTR((*bd_addr)), bt_transport_text(transport).c_str(),
          btm_status_text(result).c_str(), (p_callback) ? 'T' : 'F');
      bta_status = BTA_NO_RESOURCES;
      break;
    case BTM_BUSY:
      LOG_WARN(
          "Unable to encrypt link peer:%s transport:%s status:%s callback:%c",
          ADDRESS_TO_LOGGABLE_CSTR((*bd_addr)), bt_transport_text(transport).c_str(),
          btm_status_text(result).c_str(), (p_callback) ? 'T' : 'F');
      bta_status = BTA_BUSY;
      break;
    default:
      LOG_ERROR(
          "Failed to encrypt link peer:%s transport:%s status:%s callback:%c",
          ADDRESS_TO_LOGGABLE_CSTR((*bd_addr)), bt_transport_text(transport).c_str(),
          btm_status_text(result).c_str(), (p_callback) ? 'T' : 'F');
      bta_status = BTA_FAILURE;
      break;
  }
  if (p_callback) {
    (*p_callback)(*bd_addr, transport, bta_status);
  }
}

/**This function to encrypt the link */
void bta_dm_set_encryption(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                           tBTA_DM_ENCRYPT_CBACK* p_callback,
                           tBTM_BLE_SEC_ACT sec_act) {
  if (p_callback == nullptr) {
    LOG_ERROR("bta_dm_set_encryption callback is not provided");
    return;
  }

  tBTA_DM_PEER_DEVICE* device = find_connected_device(bd_addr, transport);
  if (device == nullptr) {
    LOG_ERROR("Unable to find active ACL connection device:%s transport:%s",
              ADDRESS_TO_LOGGABLE_CSTR(bd_addr), bt_transport_text(transport).c_str());
    return;
  }

  if (device->p_encrypt_cback) {
    LOG_ERROR(
        "Unable to start encryption as already in progress peer:%s "
        "transport:%s",
        ADDRESS_TO_LOGGABLE_CSTR(bd_addr), bt_transport_text(transport).c_str());
    (*p_callback)(bd_addr, transport, BTA_BUSY);
    return;
  }

  if (BTM_SetEncryption(bd_addr, transport, bta_dm_encrypt_cback, NULL,
                        sec_act) == BTM_CMD_STARTED) {
    device->p_encrypt_cback = p_callback;
    LOG_DEBUG("Started encryption peer:%s transport:%s",
              ADDRESS_TO_LOGGABLE_CSTR(bd_addr), bt_transport_text(transport).c_str());
  } else {
    LOG_ERROR("Unable to start encryption process peer:%s transport:%s",
              ADDRESS_TO_LOGGABLE_CSTR(bd_addr), bt_transport_text(transport).c_str());
  }
}

bool bta_dm_check_if_only_hd_connected(const RawAddress& peer_addr) {
  APPL_TRACE_DEBUG("%s: count(%d)", __func__, bta_dm_conn_srvcs.count);

  for (uint8_t j = 0; j < bta_dm_conn_srvcs.count; j++) {
    // Check if profiles other than hid are connected
    if ((bta_dm_conn_srvcs.conn_srvc[j].id != BTA_ID_HD) &&
        bta_dm_conn_srvcs.conn_srvc[j].peer_bdaddr == peer_addr) {
      APPL_TRACE_DEBUG("%s: Another profile (id=%d) is connected", __func__,
                       bta_dm_conn_srvcs.conn_srvc[j].id);
      return false;
    }
  }

  return true;
}

static void ble_io_req(const RawAddress& bd_addr, tBTM_IO_CAP* p_io_cap,
                       tBTM_OOB_DATA* p_oob_data, tBTM_LE_AUTH_REQ* p_auth_req,
                       uint8_t* p_max_key_size, tBTM_LE_KEY_TYPE* p_init_key,
                       tBTM_LE_KEY_TYPE* p_resp_key) {
  /* Retrieve the properties from file system if possible */
  tBTE_APPL_CFG nv_config;
  if (btif_dm_get_smp_config(&nv_config)) bte_appl_cfg = nv_config;

  /* *p_auth_req by default is false for devices with NoInputNoOutput; true for
   * other devices. */

  if (bte_appl_cfg.ble_auth_req)
    *p_auth_req = bte_appl_cfg.ble_auth_req |
                  (bte_appl_cfg.ble_auth_req & 0x04) | ((*p_auth_req) & 0x04);

  /* if OOB is not supported, this call-out function does not need to do
   * anything
   * otherwise, look for the OOB data associated with the address and set
   * *p_oob_data accordingly.
   * If the answer can not be obtained right away,
   * set *p_oob_data to BTA_OOB_UNKNOWN and call bta_dm_ci_io_req() when the
   * answer is available.
   */

  btif_dm_set_oob_for_le_io_req(bd_addr, p_oob_data, p_auth_req);

  if (bte_appl_cfg.ble_io_cap <= 4)
    *p_io_cap = static_cast<tBTM_IO_CAP>(bte_appl_cfg.ble_io_cap);

  if (bte_appl_cfg.ble_init_key <= BTM_BLE_INITIATOR_KEY_SIZE)
    *p_init_key = bte_appl_cfg.ble_init_key;

  if (bte_appl_cfg.ble_resp_key <= BTM_BLE_RESPONDER_KEY_SIZE)
    *p_resp_key = bte_appl_cfg.ble_resp_key;

  if (bte_appl_cfg.ble_max_key_size > 7 && bte_appl_cfg.ble_max_key_size <= 16)
    *p_max_key_size = bte_appl_cfg.ble_max_key_size;
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_smp_cback
 *
 * Description      Callback for BLE SMP
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_ble_smp_cback(tBTM_LE_EVT event, const RawAddress& bda,
                                    tBTM_LE_EVT_DATA* p_data) {
  tBTM_STATUS status = BTM_SUCCESS;
  tBTA_DM_SEC sec_event;
  const char* p_name = NULL;

  if (!bta_dm_cb.p_sec_cback) return BTM_NOT_AUTHORIZED;

  memset(&sec_event, 0, sizeof(tBTA_DM_SEC));
  switch (event) {
    case BTM_LE_IO_REQ_EVT:
      ble_io_req(bda, &p_data->io_req.io_cap, &p_data->io_req.oob_data,
                 &p_data->io_req.auth_req, &p_data->io_req.max_key_size,
                 &p_data->io_req.init_keys, &p_data->io_req.resp_keys);
      APPL_TRACE_EVENT("io mitm: %d oob_data:%d", p_data->io_req.auth_req,
                       p_data->io_req.oob_data);
      break;

    case BTM_LE_CONSENT_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      p_name = BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.ble_req.bd_name, p_name, BD_NAME_LEN);
      else
        sec_event.ble_req.bd_name[0] = 0;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_CONSENT_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SEC_REQUEST_EVT:
      sec_event.ble_req.bd_addr = bda;
      p_name = BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.ble_req.bd_name, p_name, BD_NAME_LEN + 1);
      else
        sec_event.ble_req.bd_name[0] = 0;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SEC_REQ_EVT, &sec_event);
      break;

    case BTM_LE_KEY_NOTIF_EVT:
      sec_event.key_notif.bd_addr = bda;
      p_name = BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.key_notif.bd_name, p_name, BD_NAME_LEN + 1);
      else
        sec_event.key_notif.bd_name[0] = 0;
      sec_event.key_notif.passkey = p_data->key_notif;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_PASSKEY_NOTIF_EVT, &sec_event);
      break;

    case BTM_LE_KEY_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_PASSKEY_REQ_EVT, &sec_event);
      break;

    case BTM_LE_OOB_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_OOB_REQ_EVT, &sec_event);
      break;

    case BTM_LE_NC_REQ_EVT:
      sec_event.key_notif.bd_addr = bda;
      strlcpy((char*)sec_event.key_notif.bd_name, bta_dm_get_remname(),
              (BD_NAME_LEN + 1));
      sec_event.key_notif.passkey = p_data->key_notif;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_NC_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SC_OOB_REQ_EVT:
      sec_event.ble_req.bd_addr = bda;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SC_OOB_REQ_EVT, &sec_event);
      break;

    case BTM_LE_SC_LOC_OOB_EVT:
      tBTA_DM_LOC_OOB_DATA local_oob_data;
      local_oob_data.local_oob_c = p_data->local_oob_data.commitment;
      local_oob_data.local_oob_r = p_data->local_oob_data.randomizer;
      sec_event.local_oob_data = local_oob_data;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_SC_CR_LOC_OOB_EVT, &sec_event);
      break;

    case BTM_LE_KEY_EVT:
      sec_event.ble_key.bd_addr = bda;
      sec_event.ble_key.key_type = p_data->key.key_type;
      sec_event.ble_key.p_key_value = p_data->key.p_key_value;
      bta_dm_cb.p_sec_cback(BTA_DM_BLE_KEY_EVT, &sec_event);

      // Setting remove_dev_pending flag to false, where it will avoid deleting
      // the security device record when the ACL connection link goes down in
      // case of reconnection.
      if (bta_dm_cb.device_list.count) bta_dm_reset_sec_dev_pending(bda);

      break;

    case BTM_LE_COMPLT_EVT:
      sec_event.auth_cmpl.bd_addr = bda;
      BTM_ReadDevInfo(bda, &sec_event.auth_cmpl.dev_type,
                      &sec_event.auth_cmpl.addr_type);
      p_name = BTM_SecReadDevName(bda);
      if (p_name != NULL)
        strlcpy((char*)sec_event.auth_cmpl.bd_name, p_name, (BD_NAME_LEN + 1));
      else
        sec_event.auth_cmpl.bd_name[0] = 0;

      if (p_data->complt.reason != HCI_SUCCESS) {
        // TODO This is not a proper use of this type
        sec_event.auth_cmpl.fail_reason =
            static_cast<tHCI_STATUS>(BTA_DM_AUTH_CONVERT_SMP_CODE(
                (static_cast<uint8_t>(p_data->complt.reason))));

        if (btm_sec_is_a_bonded_dev(bda) &&
            p_data->complt.reason == SMP_CONN_TOUT &&
            !p_data->complt.smp_over_br) {
          // Bonded device failed to encrypt - to test this remove battery from
          // HID device right after connection, but before encryption is
          // established
          LOG(INFO) << __func__
                    << ": bonded device disconnected when encrypting - no "
                       "reason to unbond";
        } else {
          /* delete this device entry from Sec Dev DB */
          bta_dm_remove_sec_dev_entry(bda);
        }

      } else {
        sec_event.auth_cmpl.success = true;
        if (!p_data->complt.smp_over_br)
          GATT_ConfigServiceChangeCCC(bda, true, BT_TRANSPORT_LE);
      }

      if (bta_dm_cb.p_sec_cback) {
        // bta_dm_cb.p_sec_cback(BTA_DM_AUTH_CMPL_EVT, &sec_event);
        bta_dm_cb.p_sec_cback(BTA_DM_BLE_AUTH_CMPL_EVT, &sec_event);
      }
      break;

    case BTM_LE_ADDR_ASSOC_EVT:
      sec_event.proc_id_addr.pairing_bda = bda;
      sec_event.proc_id_addr.id_addr = p_data->id_addr;
      bta_dm_cb.p_sec_cback(BTA_DM_LE_ADDR_ASSOC_EVT, &sec_event);
      break;

    default:
      status = BTM_NOT_AUTHORIZED;
      break;
  }
  return status;
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_id_key_cback
 *
 * Description      Callback for BLE local ID keys
 *
 *
 * Returns          void
 *
 ******************************************************************************/
static void bta_dm_ble_id_key_cback(uint8_t key_type,
                                    tBTM_BLE_LOCAL_KEYS* p_key) {
  switch (key_type) {
    case BTM_BLE_KEY_TYPE_ID:
    case BTM_BLE_KEY_TYPE_ER:
      if (bta_dm_cb.p_sec_cback) {
        tBTA_DM_SEC dm_key = {
            .ble_id_keys = {},
        };
        memcpy(&dm_key.ble_id_keys, p_key, sizeof(tBTM_BLE_LOCAL_KEYS));

        tBTA_DM_SEC_EVT evt = (key_type == BTM_BLE_KEY_TYPE_ID)
                                  ? BTA_DM_BLE_LOCAL_IR_EVT
                                  : BTA_DM_BLE_LOCAL_ER_EVT;
        bta_dm_cb.p_sec_cback(evt, &dm_key);
      }
      break;

    default:
      APPL_TRACE_DEBUG("Unknown key type %d", key_type);
      break;
  }
  return;
}

/*******************************************************************************
 *
 * Function         bta_dm_sirk_verifiction_cback
 *
 * Description      SIRK verification when pairing CSIP set member.
 *
 * Returns          void
 *
 ******************************************************************************/
static uint8_t bta_dm_sirk_verifiction_cback(const RawAddress& bd_addr) {
  tBTA_DM_SEC sec_event = {.ble_req = {
                               .bd_addr = bd_addr,
                           }};

  if (bta_dm_cb.p_sec_sirk_cback) {
    LOG_DEBUG("callback called");
    bta_dm_cb.p_sec_sirk_cback(BTA_DM_SIRK_VERIFICATION_REQ_EVT, &sec_event);
    return BTM_CMD_STARTED;
  }

  LOG_DEBUG("no callback registered");

  return BTM_SUCCESS_NO_SECURITY;
}

/*******************************************************************************
 *
 * Function         bta_dm_add_blekey
 *
 * Description      This function adds an BLE Key to an security database entry.
 *                  This function shall only be called AFTER BTA_DmAddBleDevice
 *                  has been called.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_add_blekey(const RawAddress& bd_addr, tBTA_LE_KEY_VALUE blekey,
                       tBTM_LE_KEY_TYPE key_type) {
  BTM_SecAddBleKey(bd_addr, (tBTM_LE_KEY_VALUE*)&blekey, key_type);
}

/*******************************************************************************
 *
 * Function         bta_dm_add_ble_device
 *
 * Description      This function adds an BLE device to an security database
 *                  entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_add_ble_device(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                           tBT_DEVICE_TYPE dev_type) {
  BTM_SecAddBleDevice(bd_addr, dev_type, addr_type);
}

/*******************************************************************************
 *
 * Function         bta_dm_add_ble_device
 *
 * Description      This function adds an BLE device to an security database
 *                  entry.
 *                  It is normally called during host startup to restore all
 *                  required information stored in the NVRAM.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_ble_passkey_reply(const RawAddress& bd_addr, bool accept,
                              uint32_t passkey) {
  BTM_BlePasskeyReply(bd_addr, accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED,
                      passkey);
}

/** This is response to SM numeric comparison request submitted to application.
 */
void bta_dm_ble_confirm_reply(const RawAddress& bd_addr, bool accept) {
  BTM_BleConfirmReply(bd_addr, accept ? BTM_SUCCESS : BTM_NOT_AUTHORIZED);
}

/** This function set the preferred connection parameters */
void bta_dm_ble_set_conn_params(const RawAddress& bd_addr,
                                uint16_t conn_int_min, uint16_t conn_int_max,
                                uint16_t peripheral_latency,
                                uint16_t supervision_tout) {
  L2CA_AdjustConnectionIntervals(&conn_int_min, &conn_int_max,
                                 BTM_BLE_CONN_INT_MIN);

  BTM_BleSetPrefConnParams(bd_addr, conn_int_min, conn_int_max,
                           peripheral_latency, supervision_tout);
}

/** This function update LE connection parameters */
void bta_dm_ble_update_conn_params(const RawAddress& bd_addr, uint16_t min_int,
                                   uint16_t max_int, uint16_t latency,
                                   uint16_t timeout, uint16_t min_ce_len,
                                   uint16_t max_ce_len) {
  L2CA_AdjustConnectionIntervals(&min_int, &max_int, BTM_BLE_CONN_INT_MIN);

  if (!L2CA_UpdateBleConnParams(bd_addr, min_int, max_int, latency, timeout,
                                min_ce_len, max_ce_len)) {
    APPL_TRACE_ERROR("Update connection parameters failed!");
  }
}

/** This function set the local device LE privacy settings. */
void bta_dm_ble_config_local_privacy(bool privacy_enable) {
  BTM_BleConfigPrivacy(privacy_enable);
}

/** This function set the maximum transmission packet size */
void bta_dm_ble_set_data_length(const RawAddress& bd_addr) {
  const controller_t* controller = controller_get_interface();
  uint16_t max_len = controller->get_ble_maximum_tx_data_length();

  if (BTM_SetBleDataLength(bd_addr, max_len) != BTM_SUCCESS) {
    LOG_INFO("Unable to set ble data length:%hu", max_len);
  }
}

/*******************************************************************************
 *
 * Function         bta_ble_enable_scan_cmpl
 *
 * Description      ADV payload filtering enable / disable complete callback
 *
 *
 * Returns          None
 *
 ******************************************************************************/
static void bta_ble_energy_info_cmpl(tBTM_BLE_TX_TIME_MS tx_time,
                                     tBTM_BLE_RX_TIME_MS rx_time,
                                     tBTM_BLE_IDLE_TIME_MS idle_time,
                                     tBTM_BLE_ENERGY_USED energy_used,
                                     tHCI_STATUS status) {
  tBTA_STATUS st = (status == HCI_SUCCESS) ? BTA_SUCCESS : BTA_FAILURE;
  tBTM_CONTRL_STATE ctrl_state = BTM_CONTRL_UNKNOWN;

  if (BTA_SUCCESS == st) ctrl_state = bta_dm_pm_obtain_controller_state();

  if (bta_dm_cb.p_energy_info_cback)
    bta_dm_cb.p_energy_info_cback(tx_time, rx_time, idle_time, energy_used,
                                  ctrl_state, st);
}

/** This function obtains the energy info */
void bta_dm_ble_get_energy_info(
    tBTA_BLE_ENERGY_INFO_CBACK* p_energy_info_cback) {
  bta_dm_cb.p_energy_info_cback = p_energy_info_cback;
  tBTM_STATUS btm_status = BTM_BleGetEnergyInfo(bta_ble_energy_info_cmpl);
  if (btm_status != BTM_CMD_STARTED)
    bta_ble_energy_info_cmpl(0, 0, 0, 0, HCI_ERR_UNSPECIFIED);
}

/*******************************************************************************
 *
 * Function         bta_dm_clear_event_filter
 *
 * Description      clears out the event filter.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_clear_event_filter(void) {
  VLOG(1) << "bta_dm_clear_event_filter in bta_dm_act";
  bluetooth::shim::BTM_ClearEventFilter();
}

/*******************************************************************************
 *
 * Function         bta_dm_clear_event_mask
 *
 * Description      Clears out the event mask in the controller.
 *
 ******************************************************************************/
void bta_dm_clear_event_mask(void) {
  VLOG(1) << "bta_dm_clear_event_mask in bta_dm_act";
  bluetooth::shim::BTM_ClearEventMask();
}

/*******************************************************************************
 *
 * Function         bta_dm_clear_filter_accept_list
 *
 * Description      Clears out the connect list in the controller.
 *
 ******************************************************************************/
void bta_dm_clear_filter_accept_list(void) {
  VLOG(1) << "bta_dm_clear_filter_accept_list in bta_dm_act";
  bluetooth::shim::BTM_ClearFilterAcceptList();
}

/*******************************************************************************
 *
 * Function         bta_dm_disconnect_all_acls
 *
 * Description      Disconnects all ACL connections.
 *
 ******************************************************************************/
void bta_dm_disconnect_all_acls(void) {
  VLOG(1) << "bta_dm_disconnect_all_acls in bta_dm_act";
  bluetooth::shim::BTM_DisconnectAllAcls();
}

/*******************************************************************************
 *
 * Function         bta_dm_le_rand
 *
 * Description      Generates a random number from the controller.
 *
 * Parameters:      |cb| Callback to receive the random number.
 *
 ******************************************************************************/
void bta_dm_le_rand(LeRandCallback cb) {
  VLOG(1) << "bta_dm_le_rand in bta_dm_act";
  bluetooth::shim::BTM_LeRand(std::move(cb));
}

/*******************************************************************************
 *
 * Function        BTA_DmSetEventFilterConnectionSetupAllDevices
 *
 * Description    Tell the controller to allow all devices
 *
 * Parameters
 *
 *******************************************************************************/
void bta_dm_set_event_filter_connection_setup_all_devices() {
  // Autoplumbed
  bluetooth::shim::BTM_SetEventFilterConnectionSetupAllDevices();
}

/*******************************************************************************
 *
 * Function        BTA_DmAllowWakeByHid
 *
 * Description     Allow the device to be woken by HID devices
 *
 * Parameters      std::vector of Classic Address and LE (Address, Address Type)
 *
 *******************************************************************************/
void bta_dm_allow_wake_by_hid(
    std::vector<RawAddress> classic_hid_devices,
    std::vector<std::pair<RawAddress, uint8_t>> le_hid_devices) {
  // If there are any entries in the classic hid list, we should also make
  // the adapter connectable for classic.
  if (classic_hid_devices.size() > 0) {
    BTM_SetConnectability(BTA_DM_CONN);
  }

  bluetooth::shim::BTM_AllowWakeByHid(std::move(classic_hid_devices),
                                      std::move(le_hid_devices));
}

/*******************************************************************************
 *
 * Function        BTA_DmRestoreFilterAcceptList
 *
 * Description    Floss: Restore the state of the for the filter accept list
 *
 * Parameters
 *
 *******************************************************************************/
void bta_dm_restore_filter_accept_list(
    std::vector<std::pair<RawAddress, uint8_t>> le_devices) {
  // Autoplumbed
  bluetooth::shim::BTM_RestoreFilterAcceptList(le_devices);
}

/*******************************************************************************
 *
 * Function       BTA_DmSetDefaultEventMaskExcept
 *
 * Description    Floss: Set the default event mask for Classic and LE except
 *                the given values (they will be disabled in the final set
 *                mask).
 *
 * Parameters     Bits set for event mask and le event mask that should be
 *                disabled in the final value.
 *
 *******************************************************************************/
void bta_dm_set_default_event_mask_except(uint64_t mask, uint64_t le_mask) {
  // Autoplumbed
  bluetooth::shim::BTM_SetDefaultEventMaskExcept(mask, le_mask);
}

/*******************************************************************************
 *
 * Function        BTA_DmSetEventFilterInquiryResultAllDevices
 *
 * Description    Floss: Set the event filter to inquiry result device all
 *
 * Parameters
 *
 *******************************************************************************/
void bta_dm_set_event_filter_inquiry_result_all_devices() {
  // Autoplumbed
  bluetooth::shim::BTM_SetEventFilterInquiryResultAllDevices();
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_reset_id
 *
 * Description      Reset the local adapter BLE keys.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_ble_reset_id(void) {
  VLOG(1) << "bta_dm_ble_reset_id in bta_dm_act";
  bluetooth::shim::BTM_BleResetId();
}

/*******************************************************************************
 *
 * Function         bta_dm_ctrl_features_rd_cmpl_cback
 *
 * Description      callback to handle controller feature read complete
 *
 * Parameters:
 *
 ******************************************************************************/
static void bta_dm_ctrl_features_rd_cmpl_cback(tHCI_STATUS result) {
  APPL_TRACE_DEBUG("%s  status = %d ", __func__, result);
  if (result == HCI_SUCCESS) {
    if (bta_dm_cb.p_sec_cback)
      bta_dm_cb.p_sec_cback(BTA_DM_LE_FEATURES_READ, NULL);
  } else {
    APPL_TRACE_ERROR("%s Ctrl BLE feature read failed: status :%d", __func__,
                     result);
  }
}

/*******************************************************************************
 *
 * Function         bta_dm_ble_subrate_request
 *
 * Description      This function requests BLE subrate procedure.
 *
 * Parameters:
 *
 ******************************************************************************/
void bta_dm_ble_subrate_request(const RawAddress& bd_addr, uint16_t subrate_min,
                                uint16_t subrate_max, uint16_t max_latency,
                                uint16_t cont_num, uint16_t timeout) {
    // Logging done in l2c_ble.cc
    L2CA_SubrateRequest(bd_addr, subrate_min, subrate_max, max_latency,
                        cont_num, timeout);
}

namespace bluetooth {
namespace legacy {
namespace testing {
tBTA_DM_PEER_DEVICE* allocate_device_for(const RawAddress& bd_addr,
                                         tBT_TRANSPORT transport) {
  return ::allocate_device_for(bd_addr, transport);
}

tBTM_STATUS bta_dm_sp_cback(tBTM_SP_EVT event, tBTM_SP_EVT_DATA* p_data) {
  return ::bta_dm_sp_cback(event, p_data);
}

void btm_set_local_io_caps(uint8_t io_caps) { ::btm_local_io_caps = io_caps; }

void bta_dm_init_cb() { ::bta_dm_init_cb(); }
void bta_dm_deinit_cb() { ::bta_dm_deinit_cb(); }

}  // namespace testing
}  // namespace legacy
}  // namespace bluetooth
