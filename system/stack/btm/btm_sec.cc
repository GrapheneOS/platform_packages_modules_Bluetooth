/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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
 *  This file contains functions for the Bluetooth Security Manager
 *
 ******************************************************************************/

#include "bluetooth/types/bt_octets.h"
#define LOG_TAG "bt_btm_sec"

#include <android_bluetooth_sysprop.h>
#include <base/functional/bind.h>
#include <bluetooth/log.h>
#include <bluetooth/metrics/bluetooth_event.h>
#include <bluetooth/metrics/os_metrics.h>
#include <bluetooth/types/address.h>
#include <bluetooth/types/bt_transport.h>
#include <bluetooth/types/remote_version.h>
#include <com_android_bluetooth_flags.h>
#include <frameworks/proto_logging/stats/enums/bluetooth/enums.pb.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include "bta/dm/bta_dm_act.h"
#include "bta/dm/bta_dm_sec_int.h"
#include "btif/include/btif_config.h"
#include "btif/include/btif_dm.h"
#include "btif/include/btif_storage.h"
#include "btm_sec_utils.h"
#include "common/time_util.h"
#include "device/include/device_iot_config.h"
#include "device/include/interop.h"
#include "hci/controller.h"
#include "internal_include/bt_target.h"
#include "main/shim/acl_api.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "osi/include/properties.h"
#include "stack/btm/btm_ble_sec.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_device_record.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/btm_sec.h"
#include "stack/btm/btm_sec_int_types.h"
#include "stack/btm/btm_security.h"
#include "stack/btm/internal/btm_api.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_dev_class.h"
#include "stack/include/bt_psm_types.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_ble_addr.h"
#include "stack/include/btm_ble_api.h"
#include "stack/include/btm_ble_privacy.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/btm_log_history.h"
#include "stack/include/btm_status.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcidefs.h"
#include "stack/include/l2cap_interface.h"
#include "stack/include/l2cap_security_interface.h"
#include "stack/include/l2cdefs.h"
#include "stack/include/main_thread.h"
#include "stack/include/rnr_interface.h"
#include "stack/include/smp_api.h"
#include "stack/include/smp_status.h"

namespace {
constexpr char kBtmLogTag[] = "SEC";
}

using namespace bluetooth;

#define BTM_SEC_MAX_COLLISION_DELAY (5000)
#define BTM_SEC_START_AUTH_DELAY (200)
#define BTM_SEC_LK_REQ_TIMEOUT_MS 1000 /* 1 second */

#define BTM_SEC_IS_SM4(sm) ((bool)(BTM_SM4_TRUE == ((sm) & BTM_SM4_TRUE)))
#define BTM_SEC_IS_SM4_LEGACY(sm) ((bool)(BTM_SM4_KNOWN == ((sm) & BTM_SM4_TRUE)))
#define BTM_SEC_IS_SM4_UNKNOWN(sm) ((bool)(BTM_SM4_UNKNOWN == ((sm) & BTM_SM4_TRUE)))

#define BTM_SEC_LE_MASK                                                          \
  (BTM_SEC_LE_AUTHENTICATED | BTM_SEC_LE_ENCRYPTED | BTM_SEC_LE_LINK_KEY_KNOWN | \
   BTM_SEC_LE_LINK_KEY_AUTHED)

static tBTM_STATUS btm_sec_execute_procedure(BtmDevice* p_device);
static bool btm_sec_start_get_name(BtmDevice* p_device);
static void btm_sec_wait_and_start_authentication(BtmDevice* p_device);
static void btm_sec_auth_timer_timeout(RawAddress bd_addr);
static void btm_sec_collision_timeout(void* data);
static void btm_restore_mode(void);
static void btm_sec_pairing_timeout(void* data);
static tBTM_STATUS btm_sec_dd_create_conn(BtmDevice* p_device);
static void btm_sec_link_key_request_reply(const RawAddress& bda, const LinkKey& link_key);

static void btm_sec_check_pending_reqs(void);
static bool btm_sec_queue_service_access_request(const RawAddress& bd_addr, uint16_t psm,
                                                 bool is_orig, uint16_t security_required,
                                                 tBTM_SEC_CALLBACK* p_callback, void* p_ref_data);
static void btm_sec_bond_cancel_complete(void);
static void btm_send_link_key_notif(BtmDevice* p_device);
static bool btm_sec_check_prefetch_pin(BtmDevice* p_device);

static tBTM_STATUS btm_sec_send_hci_disconnect(BtmDevice* p_device, tHCI_STATUS reason,
                                               uint16_t conn_handle, std::string comment);

static uint16_t btm_sec_set_serv_level4_flags(uint16_t cur_security, bool outgoing);

static void btm_sec_queue_encrypt_request(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                                          tBTM_BLE_SEC_ACT sec_act, tBTM_SEC_CALLBACK* callback,
                                          void* ref);
static void btm_sec_check_pending_enc_req(BtmDevice* p_device, tBT_TRANSPORT transport,
                                          bool encrypted);

static bool btm_sec_use_smp_br_chnl(BtmDevice* p_device);

/* true - authenticated link key is possible */
static const bool btm_sec_io_map[kBtIoCapClassicMax + 1][kBtIoCapClassicMax + 1] = {
        /*   OUT,    IO,     IN,     NONE */
        /* OUT  */ {false, false, true, false},
        /* IO   */ {false, true, true, false},
        /* IN   */ {true, true, true, false},
        /* NONE */ {false, false, false, false}};
/*  BTM_IO_CAP_OUT      0   DisplayOnly */
/*  BTM_IO_CAP_IO       1   DisplayYesNo */
/*  BTM_IO_CAP_IN       2   KeyboardOnly */
/*  BTM_IO_CAP_NONE     3   NoInputNoOutput */

/**
 * Returns GAP IO capabilities if defined from system property, to be used for BREDR Pairing.
 *
 * For backwards compatibility, defaults to BtIoCap::DISPLAY_YES_NO if the system property value
 * is invalid or undefined.
 */
static BtIoCap btm_sec_get_local_iocaps() {
  if (!com_android_bluetooth_flags_btm_iocaps_sysprop_override()) {
    return BtIoCap::DISPLAY_YES_NO;
  }

  std::optional<android::sysprop::bluetooth::Core::gap_io_capabilities_values> sysprop_value =
          android::sysprop::bluetooth::Core::gap_io_capabilities();
  if (!sysprop_value.has_value()) {
    return BtIoCap::DISPLAY_YES_NO;
  }

  switch (sysprop_value.value()) {
    case android::sysprop::bluetooth::Core::gap_io_capabilities_values::NONE:
      return BtIoCap::NO_INPUT_NO_OUTPUT;
    case android::sysprop::bluetooth::Core::gap_io_capabilities_values::DISPLAY_ONLY:
      return BtIoCap::DISPLAY_ONLY;
    case android::sysprop::bluetooth::Core::gap_io_capabilities_values::DISPLAY_YESNO:
      return BtIoCap::DISPLAY_YES_NO;
    case android::sysprop::bluetooth::Core::gap_io_capabilities_values::KEYBOARD_ONLY:
      return BtIoCap::KEYBOARD_ONLY;
    case android::sysprop::bluetooth::Core::gap_io_capabilities_values::KEYBOARD_DISPLAY:
      // BT Classic does not support KEYBOARD_DISPLAY, fall back to default.
    default:
      return BtIoCap::DISPLAY_YES_NO;
  }
}

static void NotifyBondingChange(BtmDevice& p_device, tHCI_STATUS status) {
  (BtmSecurity::Get().app_->auth_complete_callback)(p_device.bd_addr, p_device.sec_bd_name, status);
}

static bool is_sec_state_equal(void* data, void* context) {
  BtmDevice* p_device = static_cast<BtmDevice*>(data);
  tSECURITY_STATE* state = static_cast<tSECURITY_STATE*>(context);

  if (p_device->sec_rec.classic_link == *state) {
    return false;
  }

  return true;
}

/*******************************************************************************
 *
 * Function         btm_sec_find_dev_by_sec_state
 *
 * Description      Look for the record in the device database for the device
 *                  which is being authenticated or encrypted
 *
 * Returns          Pointer to the record or NULL
 *
 ******************************************************************************/
static BtmDevice* btm_sec_find_dev_by_sec_state(tSECURITY_STATE state) {
  if (!com_android_bluetooth_flags_use_array_instead_list_in_sec_dev_rec()) {
    list_node_t* n = list_foreach(BtmSecurity::Get().sec_dev_rec_, is_sec_state_equal, &state);
    if (n) {
      return static_cast<BtmDevice*>(list_node(n));
    }

    return nullptr;
  }

  return BtmSecurity::Get().for_each_dev_rec(is_sec_state_equal, &state);
}

static tBTM_STATUS btm_sec_report_bond_loss(BtmDevice* p_device, tBT_TRANSPORT transport,
                                            tBTM_KEY_MISSING_REASON reason) {
  RawAddress bd_addr;
  uint16_t handle;
  std::string disc_reason = "Key missing";

  if (reason == BTM_KEY_MISSING_BREDR_AUTH_FAILURE) {
    disc_reason = "auth_cmpl KEY_MISSING for bonded device";
  } else if (reason == BTM_KEY_MISSING_BREDR_INCOMING_PAIRING) {
    disc_reason = "btm_io_capabilities_req for bonded device";
  } else if (reason == BTM_KEY_MISSING_LE_ENCRYPT_FAILURE) {
    disc_reason = "encryption_change:key_missing";
  } else if (reason == BTM_KEY_MISSING_LE_INCOMING_PAIRING) {
    disc_reason = "Bonded unencrypted central wants to pair";
  }

  // Mark this device as bond lost
  if (is_autonomous_repairing_supported()) {
    p_device->bond_lost = true;
  }

  if (transport == BT_TRANSPORT_LE) {
    bd_addr = p_device->ble.pseudo_addr;
    handle = p_device->ble_hci_handle;
  } else {
    bd_addr = p_device->bd_addr;
    handle = p_device->hci_handle;
  }

  log::warn("Bond loss detected for {}({}) reason: {}", bd_addr, transport, disc_reason);
  bta_dm_remote_key_missing(bd_addr, reason);

  if (handle == HCI_INVALID_HANDLE) {
    log::warn("Already disconnected {}({})", bd_addr, transport);
    return tBTM_STATUS::BTM_SUCCESS;
  }

  if (!is_autonomous_repairing_supported()) {
    btm_sec_disconnect(handle, HCI_ERR_AUTH_FAILURE, disc_reason.c_str());
  }

  return tBTM_STATUS::BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_sec_register
 *
 * Description      Application manager calls this function to register for
 *                  security services.  There can be one and only one
 *                  application saving link keys.  BTM allows only first
 *                  registration.
 *
 * Returns          true if registered OK, else false
 *
 ******************************************************************************/
bool btm_sec_register(const BtmAppReg& app_reg) {
  log::verbose("SMP_Register(btm_proc_smp_cback)");
  SMP_Register(btm_proc_smp_cback);

  BtmSecurity::Get().app_ = &app_reg;

  /* if no IR is loaded, need to regenerate all the keys */
  if (BtmSecurity::Get().devcb_.id_keys.ir == ZERO_OCTET16) {
    btm_ble_reset_id();
  }

  return true;
}

bool btm_is_encrypted(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  return BtmSecurity::Get().IsDeviceEncrypted(bd_addr, transport);
}

bool btm_is_link_key_authed(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  return BtmSecurity::Get().IsLinkKeyAuthenticated(bd_addr, transport);
}

bool btm_is_bonded(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  return BtmSecurity::Get().IsDeviceBonded(bd_addr, transport);
}

bool btm_is_authenticated(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  return BtmSecurity::Get().IsDeviceAuthenticated(bd_addr, transport);
}

/*******************************************************************************
 *
 * Function         btm_set_pin_type
 *
 * Description      Set PIN type for the device.
 *
 * Returns          void
 *
 ******************************************************************************/
// TODO : Remove when the flag local_pin_key_type is shipped
void btm_set_pin_type(uint8_t pin_type, PinCode pin_code, uint8_t pin_code_len) {
  log::verbose("btm_set_pin_type: pin type {} [variable-0, fixed-1], code {}, length {}", pin_type,
               (char*)pin_code.data(), pin_code_len);

  /* If device is not up security mode will be set as a part of startup */
  if ((BtmSecurity::Get().cfg_.pin_type != pin_type) &&
      bluetooth::shim::GetController() != nullptr) {
    btsnd_hcic_write_pin_type(pin_type);
  }

  BtmSecurity::Get().cfg_.pin_type = pin_type;
  BtmSecurity::Get().cfg_.pin_code_len = pin_code_len;
  BtmSecurity::Get().cfg_.pin_code = pin_code;
}

/*******************************************************************************
 *
 * Function         btm_set_security_level
 *
 * Description      Register service security level with Security Manager
 *
 * Parameters:      outgoing    - true if originating the connection
 *                  p_name      - Name of the service relevant only if
 *                                authorization will show this name to user.
 *                                Ignored if BT_MAX_SERVICE_NAME_LEN is 0.
 *                  service_id  - service ID for the service passed to
 *                                authorization callback
 *                  sec_level   - bit mask of the security features
 *                  psm         - L2CAP PSM
 *                  mx_proto_id - protocol ID of multiplexing proto below
 *                  mx_chan_id  - channel ID of multiplexing proto below
 *
 * Returns          true if registered OK, else false
 *
 ******************************************************************************/
bool btm_set_security_level(bool outgoing, const char* p_name, uint8_t service_id,
                            uint16_t sec_level, uint16_t psm, uint32_t mx_proto_id,
                            uint32_t mx_chan_id) {
  return BtmSecurity::Get().AddService(outgoing, p_name, service_id, sec_level, psm, mx_proto_id,
                                       mx_chan_id);
}

/*******************************************************************************
 *
 * Function         btm_sec_clr_service
 *
 * Description      Removes specified service record(s) from the security
 *                  database. All service records with the specified name are
 *                  removed. Typically used only by devices with limited RAM so
 *                  that it can reuse an old security service record.
 *
 *                  Note: Unpredictable results may occur if a service is
 *                      cleared that is still in use by an application/profile.
 *
 * Parameters       Service ID - Id of the service to remove. '0' removes all
 *                          service records (except SDP).
 *
 * Returns          Number of records that were freed.
 *
 ******************************************************************************/
uint8_t btm_sec_clr_service(uint8_t service_id) {
  return BtmSecurity::Get().RemoveServiceById(service_id);
}

/*******************************************************************************
 *
 * Function         btm_sec_clr_service_by_psm
 *
 * Description      Removes specified service record from the security database.
 *                  All service records with the specified psm are removed.
 *                  Typically used by L2CAP to free up the service record used
 *                  by dynamic PSM clients when the channel is closed.
 *                  The given psm must be a virtual psm.
 *
 * Parameters       Service ID - Id of the service to remove. '0' removes all
 *                          service records (except SDP).
 *
 * Returns          Number of records that were freed.
 *
 ******************************************************************************/
uint8_t btm_sec_clr_service_by_psm(uint16_t psm) {
  return BtmSecurity::Get().RemoveServiceByPsm(psm);
}

// TODO (b/460502961): Remove once the flag security_mode_3_pairing is shipped.
static void PinCodeReply(const RawAddress& bd_addr, tBTM_STATUS res, uint8_t pin_len,
                         PinCode pin_code) {
  if (bd_addr != BtmSecurity::Get().link_spec_.addrt.bda) {
    log::error("Requested addr {} does not match pairing device {}", bd_addr,
               BtmSecurity::Get().link_spec_);
    return;
  }

  /* If timeout already expired or has been canceled, ignore the reply */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_LOCAL_PIN) {
    log::warn("{} wrong state:{}", bd_addr, BtmSecurity::Get().pairing_state_);
    return;
  }

  log::verbose("PairState:{}  PairFlags:0x{:02x}  PinLen:{} Result:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
               BtmSecurity::Get().pairing_flags_, pin_len, res);

  BtmDevice* p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("Unknown device {}", bd_addr);
    return;
  }

  if (pin_len > kOctet16Length || pin_len == 0) {
    res = tBTM_STATUS::BTM_ILLEGAL_VALUE;
  }

  if (res != tBTM_STATUS::BTM_SUCCESS) {
    log::warn("Pairing with {} rejected: {}", bd_addr, res);
    /* If peer started dd OR we started dd and pre-fetch pin was not used send negative reply */
    if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_PEER_STARTED_DD) ||
        ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
         (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE))) {
      /* use BTM_PAIR_STATE_WAIT_AUTH_COMPLETE to report authentication failed
       * event */
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
      acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);

      btsnd_hcic_pin_code_neg_reply(bd_addr);
    } else {
      p_device->sec_rec.security_required = BTM_SEC_NONE;
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
    }
    return;
  }

  p_device->sec_rec.sec_flags |= BTM_SEC_LINK_KEY_AUTHED;
  p_device->sec_rec.pin_code_length = pin_len;
  if (pin_len >= kOctet16Length) {
    p_device->sec_rec.sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
  }

  if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
      (p_device->hci_handle == HCI_INVALID_HANDLE) &&
      (!BtmSecurity::Get().security_mode_changed_)) {
    /* This is start of the dedicated bonding if local device is 2.0 */
    BtmSecurity::Get().pin_code_len_ = pin_len;
    BtmSecurity::Get().pin_code_ = pin_code;

    BtmSecurity::Get().security_mode_changed_ = true;
    btsnd_hcic_write_auth_enable(true);

    acl_set_disconnect_reason(HCI_ERR_UNDEFINED);

    /* if we rejected incoming connection request, we have to wait
     * HCI_Connection_Complete event */
    /*  before originating  */
    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_REJECTED_CONNECT) {
      log::warn("Waiting for connection complete after rejecting incoming connection {}", bd_addr);
      /* we change state little bit early so btm_sec_connected() will originate
       * connection */
      /*   when existing ACL link is down completely */
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);
    } else if (p_device->sm4 & BTM_SM4_CONN_PEND) {
      /* if we already accepted incoming connection from pairing device */
      log::warn("Link is connecting so wait pin code request from {}", bd_addr);
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);
    } else {
      auto status = btm_sec_dd_create_conn(p_device);
      if (status != tBTM_STATUS::BTM_CMD_STARTED) {
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
        p_device->sec_rec.sec_flags &= ~BTM_SEC_LINK_KEY_AUTHED;

        NotifyBondingChange(*p_device, HCI_ERR_AUTH_FAILURE);
      }
    }
    return;
  }

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
  acl_set_disconnect_reason(HCI_SUCCESS);

  btsnd_hcic_pin_code_req_reply(bd_addr, pin_len, pin_code);
}

/*******************************************************************************
 *
 * Function         btm_pin_code_reply
 *
 * Description      This function is called after Security Manager submitted
 *                  PIN code request to the UI.
 *
 * Parameters:      bd_addr      - Address of the device for which PIN was
 *                                 requested
 *                  res          - result of the operation tBTM_STATUS::BTM_SUCCESS
 *                                 if success
 *                  pin_len      - length in bytes of the PIN Code
 *                  pin_code     - Array with the PIN Code
 *
 ******************************************************************************/
void btm_pin_code_reply(const RawAddress& bd_addr, tBTM_STATUS res, uint8_t pin_len,
                        PinCode pin_code) {
  if (!com_android_bluetooth_flags_security_mode_3_pairing()) {
    PinCodeReply(bd_addr, res, pin_len, pin_code);
    return;
  }

  if (bd_addr != BtmSecurity::Get().link_spec_.addrt.bda) {
    log::error("Requested addr {} does not match pairing device {}", bd_addr,
               BtmSecurity::Get().link_spec_);
    return;
  }

  /* If timeout already expired or has been canceled, ignore the reply */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_LOCAL_PIN) {
    log::warn("{} wrong state:{}", bd_addr, BtmSecurity::Get().pairing_state_);
    return;
  }

  BtmDevice* p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("Unknown device {}", bd_addr);
    return;
  }

  if (pin_len > kOctet16Length || pin_len == 0) {
    res = tBTM_STATUS::BTM_ILLEGAL_VALUE;
  }

  if (res != tBTM_STATUS::BTM_SUCCESS) {
    log::warn("Pairing with {} rejected: {}", bd_addr, res);
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
    acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
    btsnd_hcic_pin_code_neg_reply(bd_addr);
    return;
  }

  if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
      (p_device->hci_handle == HCI_INVALID_HANDLE)) {  // Remote device in security mode 3
    acl_set_disconnect_reason(HCI_ERR_UNDEFINED);
    // If we rejected incoming connection request, we have to wait HCI_Connection_Complete event
    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_REJECTED_CONNECT) {
      log::warn("Waiting for connection complete after rejecting incoming connection {}", bd_addr);
      /* Change state little bit early so btm_sec_connected() will originate connection when
       * existing ACL link is down completely */
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);
      return;
    }
  }

  log::verbose("Device:{} flags:0x{:02x} pin_len:{}", bd_addr, BtmSecurity::Get().pairing_flags_,
               pin_len);

  p_device->sec_rec.sec_flags |= BTM_SEC_LINK_KEY_AUTHED;
  p_device->sec_rec.pin_code_length = pin_len;
  if (pin_len >= kOctet16Length) {
    p_device->sec_rec.sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
  }
  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
  acl_set_disconnect_reason(HCI_SUCCESS);

  btsnd_hcic_pin_code_req_reply(bd_addr, pin_len, pin_code);
}

/*******************************************************************************
 *
 * Function         btm_sec_bond_by_transport
 *
 * Description      this is the bond function that will start either SSP or SMP.
 *
 * Parameters:      bd_addr      - Address of the device to bond
 *                  addr_type    - type of the address
 *                  transport    - transport on which to create bond
 ******************************************************************************/
tBTM_STATUS btm_sec_bond_by_transport(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                                      tBT_TRANSPORT transport) {
  BtmDevice* p_device;
  tBTM_STATUS status;
  log::info("Transport used {}, bd_addr={}", transport, bd_addr);

  /* Other security process is in progress */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE) {
    if (BtmSecurity::Get().link_spec_.addrt.bda == bd_addr) {
      log::warn("Already pairing with {}", BtmSecurity::Get().link_spec_);
      return tBTM_STATUS::BTM_CMD_STARTED;
    } else {
      log::error("Busy ({}) pairing with {}",
                 btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
                 BtmSecurity::Get().link_spec_);
      return tBTM_STATUS::BTM_WRONG_MODE;
    }
  }

  p_device = btm_find_or_alloc_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  if (bluetooth::shim::GetController() == nullptr) {
    log::error("controller module is not ready");
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  /* Finished if connection is active and already paired */
  if (!com_android_bluetooth_flags_check_bond_status_before_pairing()) {
    if (transport == BT_TRANSPORT_BR_EDR && p_device->hci_handle != HCI_INVALID_HANDLE &&
        p_device->sec_rec.bond_type == BOND_TYPE_PERSISTENT &&
        (p_device->sec_rec.sec_flags & BTM_SEC_AUTHENTICATED)) {
      log::warn("Already Paired");
      return tBTM_STATUS::BTM_SUCCESS;
    }

    if (transport == BT_TRANSPORT_LE && p_device->ble_hci_handle != HCI_INVALID_HANDLE &&
        (p_device->sec_rec.sec_flags & BTM_SEC_LE_AUTHENTICATED)) {
      log::warn("Already Paired");
      return tBTM_STATUS::BTM_SUCCESS;
    }
  } else if (p_device->sec_rec.is_bonded(transport) && !p_device->bond_lost) {
    log::info("{} already paired over transport {}", bd_addr, transport);
    return tBTM_STATUS::BTM_SUCCESS;
  }

  log::verbose("before update sec_flags=0x{:x}", p_device->sec_rec.sec_flags);

  /* Tell controller to get rid of the link key if it has one stored */
  btm_sec_hci_delete_stored_link_key(bd_addr);

  BtmSecurity::Get().link_spec_ = {.addrt = {.type = addr_type, .bda = bd_addr},
                                   .transport = transport};

  BtmSecurity::Get().pairing_flags_ = BTM_PAIR_FLAGS_WE_STARTED_DD;

  p_device->sec_rec.security_required = BTM_SEC_OUT_AUTHENTICATE;
  p_device->outgoing = true;

  BTM_LogHistory(kBtmLogTag, bd_addr, "Bonding initiated", bt_transport_text(transport));

  if (transport == BT_TRANSPORT_LE) {
    btm_ble_init_pseudo_addr(p_device, bd_addr);
    p_device->sec_rec.sec_flags &= ~BTM_SEC_LE_MASK;

    tSMP_STATUS smp_status = SMP_Pair(bd_addr, addr_type);
    if (smp_status == SMP_STARTED) {
      BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_LE_ACTIVE;
      p_device->sec_rec.le_link = tSECURITY_STATE::AUTHENTICATING;
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
      return tBTM_STATUS::BTM_CMD_STARTED;
    }

    BtmSecurity::Get().pairing_flags_ = 0;
    log::error("SMP_Pair: failed, status:{}", smp_status);
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  p_device->sec_rec.sec_flags &=
          ~(BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED |
            BTM_SEC_ROLE_SWITCHED | BTM_SEC_LINK_KEY_AUTHED);

  log::verbose("after update sec_flags=0x{:x}", p_device->sec_rec.sec_flags);
  if (!com_android_bluetooth_flags_local_pin_key_type() &&
      !bluetooth::shim::GetController()->SupportsSimplePairing()) {
    /* The special case when we authenticate keyboard.  Set pin type to fixed */
    /* It would be probably better to do it from the application, but it is */
    /* complicated */
    if (((p_device->dev_class[1] & BTM_COD_MAJOR_CLASS_MASK) == BTM_COD_MAJOR_PERIPHERAL) &&
        (p_device->dev_class[2] & BTM_COD_MINOR_KEYBOARD) &&
        (BtmSecurity::Get().cfg_.pin_type != HCI_PIN_TYPE_FIXED)) {
      BtmSecurity::Get().pin_type_changed_ = true;
      btsnd_hcic_write_pin_type(HCI_PIN_TYPE_FIXED);
    }
  }

  log::verbose("Remote sm4: 0x{:x}  HCI Handle: 0x{:04x}", p_device->sm4, p_device->hci_handle);

  /* If connection already exists... */
  if (get_btm_client_interface().peer.BTM_IsAclConnectionUpAndHandleValid(bd_addr, transport)) {
    log::debug("An ACL connection currently exists peer:{} transport:{}", bd_addr,
               bt_transport_text(transport));
    btm_sec_wait_and_start_authentication(p_device);

    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);

    /* Mark lcb as bonding */
    l2cu_update_lcb_4_bonding(bd_addr, true);
    return tBTM_STATUS::BTM_CMD_STARTED;
  }
  log::debug("An ACL connection does not currently exist peer:{} transport:{}", bd_addr,
             bt_transport_text(transport));

  log::verbose("sec mode: {} sm4:x{:x}", BtmSecurity::Get().security_mode_, p_device->sm4);

  if (!com_android_bluetooth_flags_security_mode_3_pairing() &&
      (!bluetooth::shim::GetController()->SupportsSimplePairing() ||
       (p_device->sm4 == BTM_SM4_KNOWN))) {
    if (btm_sec_check_prefetch_pin(p_device)) {
      log::debug("Class of device used to check for pin peer:{} transport:{}", bd_addr,
                 bt_transport_text(transport));
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
  }

  if ((BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SP ||
       BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) &&
      BTM_SEC_IS_SM4_UNKNOWN(p_device->sm4)) {
    /* local is 2.1 and peer is unknown */
    if ((p_device->sm4 & BTM_SM4_CONN_PEND) == 0) {
      if (com_android_bluetooth_flags_skip_excess_name_discovery() &&
          btif_storage_get_stored_remote_name(bd_addr,
                                              reinterpret_cast<char*>(&p_device->sec_bd_name))) {
        /* Skip name discovery if the name is already known */
        p_device->sec_rec.sec_flags |= BTM_SEC_NAME_KNOWN;
        status = btm_sec_dd_create_conn(p_device);
      } else {
        /* we are not accepting connection request from peer
         * -> RNR (to learn if peer is 2.1)
         * RNR when no ACL causes HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT */
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_GET_REM_NAME);
        status = get_stack_rnr_interface().BTM_ReadRemoteDeviceName(bd_addr, NULL,
                                                                    BT_TRANSPORT_BR_EDR);
      }
    } else {
      /* We are accepting connection request from peer */
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);
      status = tBTM_STATUS::BTM_CMD_STARTED;
    }
    log::verbose("State:{} sm4: 0x{:x} le_link_state:{} classic_link_state:{}",
                 btm_pair_state_descr(BtmSecurity::Get().pairing_state_), p_device->sm4,
                 p_device->sec_rec.le_link, p_device->sec_rec.classic_link);
  } else {
    /* both local and peer are 2.1  */
    status = btm_sec_dd_create_conn(p_device);
  }

  if (status != tBTM_STATUS::BTM_CMD_STARTED) {
    log::error("BTM_ReadRemoteDeviceName or btm_sec_dd_create_conn error: 0x{:x}", (int)status);
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
  }

  return status;
}

/*******************************************************************************
 *
 * Function         btm_sec_bond
 *
 * Description      This function is called to perform bonding with peer device.
 *                  If the connection is already up, but not secure, pairing
 *                  is attempted.  If already paired tBTM_STATUS::BTM_SUCCESS is returned.
 *
 * Parameters:      bd_addr      - Address of the device to bond
 *                  addr_type    - Address type of the device to bond
 *                  transport    - doing SSP over BR/EDR or SMP over LE
 ******************************************************************************/
tBTM_STATUS btm_sec_bond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                         tBT_TRANSPORT transport) {
  if (transport == BT_TRANSPORT_AUTO) {
    if (addr_type == BLE_ADDR_PUBLIC) {
      transport = get_btm_client_interface().ble.BTM_UseLeLink(bd_addr) ? BT_TRANSPORT_LE
                                                                        : BT_TRANSPORT_BR_EDR;
    } else {
      log::info("Forcing transport LE (was auto) because of the address type");
      transport = BT_TRANSPORT_LE;
    }
  }

  auto dev_info = BTM_ReadDevInfo(bd_addr);
  /* LE device, do SMP pairing */
  if ((transport == BT_TRANSPORT_LE && (dev_info.device_type & BT_DEVICE_TYPE_BLE) == 0) ||
      (transport == BT_TRANSPORT_BR_EDR && (dev_info.device_type & BT_DEVICE_TYPE_BREDR) == 0)) {
    log::warn("Requested transport and supported transport don't match");
    bluetooth::metrics::LogBluetoothEvent(bd_addr, bluetooth::metrics::EventType::TRANSPORT_MATCH,
                                          bluetooth::metrics::State::FAIL);
  }

  bluetooth::metrics::LogBluetoothEvent(bd_addr, bluetooth::metrics::EventType::TRANSPORT,
                                        transport == BT_TRANSPORT_LE
                                                ? bluetooth::metrics::State::LE
                                                : bluetooth::metrics::State::CLASSIC);

  return btm_sec_bond_by_transport(bd_addr, addr_type, transport);
}

/*******************************************************************************
 *
 * Function         btm_sec_bond_cancel
 *
 * Description      This function is called to cancel ongoing bonding process
 *                  with peer device.
 *
 * Parameters:      bd_addr      - Address of the peer device
 *                  transport    - false for BR/EDR link; true for LE link
 *
 ******************************************************************************/
tBTM_STATUS btm_sec_bond_cancel(const RawAddress& bd_addr) {
  BtmDevice* p_device;

  log::verbose("btm_sec_bond_cancel()  State: {} flags:0x{:x}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
               BtmSecurity::Get().pairing_flags_);
  p_device = btm_get_dev(bd_addr);
  if (!p_device || BtmSecurity::Get().link_spec_.addrt.bda != bd_addr) {
    return tBTM_STATUS::BTM_UNKNOWN_ADDR;
  }

  if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_LE_ACTIVE) {
    if (p_device->sec_rec.le_link == tSECURITY_STATE::AUTHENTICATING) {
      log::verbose("Cancel LE pairing");
      if (SMP_PairCancel(bd_addr)) {
        return tBTM_STATUS::BTM_CMD_STARTED;
      }
    }
    return tBTM_STATUS::BTM_WRONG_MODE;
  }

  log::verbose("hci_handle:0x{:x} le_link:{} classic_link:{}", p_device->hci_handle,
               p_device->sec_rec.le_link, p_device->sec_rec.classic_link);

  if (!com_android_bluetooth_flags_security_mode_3_pairing() &&
      BTM_PAIR_STATE_WAIT_LOCAL_PIN == BtmSecurity::Get().pairing_state_ &&
      BTM_PAIR_FLAGS_WE_STARTED_DD & BtmSecurity::Get().pairing_flags_) {
    /* pre-fetching pin for dedicated bonding */
    btm_sec_bond_cancel_complete();
    return tBTM_STATUS::BTM_SUCCESS;
  }

  /* If this BDA is in a bonding procedure */
  if ((BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE) &&
      (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD)) {
    /* If the HCI link is up */
    if (p_device->hci_handle != HCI_INVALID_HANDLE) {
      /* If some other thread disconnecting, we do not send second command */
      if (p_device->sec_rec.classic_link == tSECURITY_STATE::DISCONNECTING) {
        return tBTM_STATUS::BTM_CMD_STARTED;
      }

      /* If the HCI link was set up by Bonding process */
      if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE) {
        return btm_sec_send_hci_disconnect(p_device, HCI_ERR_PEER_USER, p_device->hci_handle,
                                           "stack::btm::btm_sec::btm_sec_bond_cancel");
      } else {
        l2cu_update_lcb_4_bonding(bd_addr, false);
      }

      return tBTM_STATUS::BTM_NOT_AUTHORIZED;
    } else /*HCI link is not up */
    {
      /* If the HCI link creation was started by Bonding process */
      if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE) {
        btsnd_hcic_create_conn_cancel(bd_addr);
        return tBTM_STATUS::BTM_CMD_STARTED;
      }
      if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_GET_REM_NAME) {
        if (get_stack_rnr_interface().BTM_CancelRemoteDeviceName() != tBTM_STATUS::BTM_SUCCESS) {
          log::warn("Unable to cancel RNR");
        }
        BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_WE_CANCEL_DD;
        return tBTM_STATUS::BTM_CMD_STARTED;
      }
      return tBTM_STATUS::BTM_NOT_AUTHORIZED;
    }
  }

  return tBTM_STATUS::BTM_WRONG_MODE;
}

/*******************************************************************************
 *
 * Function         btm_sec_get_device_link_key_type
 *
 * Description      This function is called to obtain link key type for the
 *                  device.
 *                  it returns tBTM_STATUS::BTM_SUCCESS if link key is available, or
 *                  tBTM_STATUS::BTM_UNKNOWN_ADDR if Security Manager does not know about
 *                  the device or device record does not contain link key info
 *
 * Returns          BTM_LKEY_TYPE_IGNORE if link key is unknown, link type
 *                  otherwise.
 *
 ******************************************************************************/
tBTM_LINK_KEY_TYPE btm_sec_get_device_link_key_type(const RawAddress& bd_addr) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);

  if ((p_device != NULL) && (p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN)) {
    return p_device->sec_rec.link_key_type;
  }
  return BTM_LKEY_TYPE_IGNORE;
}

/*******************************************************************************
 *
 * Function         btm_set_encryption
 *
 * Description      This function is called to ensure that connection is
 *                  encrypted.  Should be called only on an open connection.
 *                  Typically only needed for connections that first want to
 *                  bring up unencrypted links, then later encrypt them.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  transport     - Link transport
 *                  p_callback    - Pointer to callback function called after
 *                                  required procedures are completed. Can be
 *                                  set to NULL if status is not desired.
 *                  p_ref_data    - pointer to any data the caller wishes to
 *                                  receive in the callback function upon
 *                                  completion. can be set to NULL if not used.
 *                  sec_act       - LE security action, unused for BR/EDR
 *
 * Returns          tBTM_STATUS::BTM_SUCCESS   - already encrypted
 *                  BTM_PENDING   - command will be returned in the callback
 *                  tBTM_STATUS::BTM_WRONG_MODE- connection not up.
 *                  tBTM_STATUS::BTM_BUSY      - security procedures are currently active
 *                  tBTM_STATUS::BTM_MODE_UNSUPPORTED - if security manager not linked in.
 *
 ******************************************************************************/
tBTM_STATUS btm_set_encryption(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                               tBTM_SEC_CALLBACK* p_callback, void* p_ref_data,
                               tBTM_BLE_SEC_ACT sec_act) {
  BtmDevice* p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("Unknown device {}", bd_addr);
    return tBTM_STATUS::BTM_WRONG_MODE;
  }

  switch (transport) {
    case BT_TRANSPORT_BR_EDR:
      if (p_device->hci_handle == HCI_INVALID_HANDLE) {
        log::warn("Not connected over BR/EDR addr:{}", bd_addr);
        if (p_callback) {
          do_in_main_thread(base::BindOnce(p_callback, bd_addr, transport, p_ref_data,
                                           tBTM_STATUS::BTM_WRONG_MODE));
        }
        return tBTM_STATUS::BTM_WRONG_MODE;
      }

      if (p_device->sec_rec.sec_flags & BTM_SEC_ENCRYPTED) {
        log::debug("Already encrypted over BR/EDR addr:{}", bd_addr);
        if (p_callback) {
          do_in_main_thread(base::BindOnce(p_callback, bd_addr, transport, p_ref_data,
                                           tBTM_STATUS::BTM_SUCCESS));
        }
        return tBTM_STATUS::BTM_SUCCESS;
      }
      break;

    case BT_TRANSPORT_LE:
      if (p_device->ble_hci_handle == HCI_INVALID_HANDLE) {
        log::warn("Not connected over LE addr:{}", bd_addr);
        if (p_callback) {
          do_in_main_thread(base::BindOnce(p_callback, bd_addr, transport, p_ref_data,
                                           tBTM_STATUS::BTM_WRONG_MODE));
        }
        return tBTM_STATUS::BTM_WRONG_MODE;
      }

      if (p_device->sec_rec.sec_flags & BTM_SEC_LE_ENCRYPTED) {
        log::debug("Already encrypted over LE addr:{}", bd_addr);
        if (p_callback) {
          do_in_main_thread(base::BindOnce(p_callback, bd_addr, transport, p_ref_data,
                                           tBTM_STATUS::BTM_SUCCESS));
        }
        return tBTM_STATUS::BTM_SUCCESS;
      }
      break;

    default:
      log::error("Unknown transport");
      break;
  }

  tSECURITY_STATE& state = (transport == BT_TRANSPORT_LE) ? p_device->sec_rec.le_link
                                                          : p_device->sec_rec.classic_link;

  if (com_android_bluetooth_flags_force_encryption_post_successful_pairing()) {
    // Always push the encryption request, so that .callback and .ref will be used while processing
    // btm_sec_check_pending_enc_req() when encryption is completed.
    btm_sec_queue_encrypt_request(bd_addr, transport, sec_act, p_callback, p_ref_data);
    if (p_device->sec_rec.is_security_state_encrypting() || state != tSECURITY_STATE::IDLE) {
      log::warn(
              "Encryption already in progress, pushing this encryption request, bd_addr: {}, "
              "state: {}",
              bd_addr, security_state_text(state));
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
  } else {
    /* Enqueue security request if security is active */
    if (p_device->sec_rec.p_callback || state != tSECURITY_STATE::IDLE) {
      log::warn("Request enqueued, state: {}", security_state_text(state));
      btm_sec_queue_encrypt_request(bd_addr, transport, sec_act, p_callback, p_ref_data);
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
    p_device->sec_rec.p_callback = p_callback;
    p_device->sec_rec.p_ref_data = p_ref_data;
  }
  p_device->sec_rec.security_required |= (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT);
  p_device->outgoing = false;

  log::debug(
          "classic_handle:0x{:04x} ble_handle:0x{:04x} le_link:{} classic_link:{} flags:0x{:x} "
          "required:0x{:x} p_callback={:c}",
          p_device->hci_handle, p_device->ble_hci_handle, p_device->sec_rec.le_link,
          p_device->sec_rec.classic_link, p_device->sec_rec.sec_flags,
          p_device->sec_rec.security_required, (p_callback) ? 'T' : 'F');

  tBTM_STATUS rc = tBTM_STATUS::BTM_SUCCESS;
  switch (transport) {
    case BT_TRANSPORT_LE:
      if (get_btm_client_interface().peer.BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
        rc = btm_ble_set_encryption(bd_addr, sec_act,
                                    stack::l2cap::get_interface().L2CA_GetBleConnRole(bd_addr));
      } else {
        rc = tBTM_STATUS::BTM_WRONG_MODE;
        log::warn("Not connected over LE, addr:{}", bd_addr);
      }
      break;

    case BT_TRANSPORT_BR_EDR:
      rc = btm_sec_execute_procedure(p_device);
      break;

    default:
      log::error("Unknown transport");
      break;
  }

  switch (rc) {
    case tBTM_STATUS::BTM_CMD_STARTED:
    case tBTM_STATUS::BTM_BUSY:
      break;

    default:
      if (p_callback) {
        log::debug("Executing encryption callback peer:{} transport:{}", bd_addr,
                   bt_transport_text(transport));
        if (com_android_bluetooth_flags_force_encryption_post_successful_pairing()) {
          do_in_main_thread(base::BindOnce(p_callback, bd_addr, transport, p_ref_data, rc));
          break;
        }
        p_device->sec_rec.p_callback = nullptr;
        do_in_main_thread(
                base::BindOnce(p_callback, bd_addr, transport, p_device->sec_rec.p_ref_data, rc));
      }
      break;
  }
  return rc;
}

bool btm_sec_is_le_security_pending(const RawAddress& bd_addr) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);
  return p_device && (p_device->sec_rec.is_security_state_le_encrypting() ||
                      p_device->sec_rec.le_link == tSECURITY_STATE::AUTHENTICATING);
}

tBTM_STATUS btm_sec_report_bond_loss(const RawAddress& bd_addr, tBT_TRANSPORT transport) {
  BtmDevice* p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("No record found for {}", bd_addr);
    return tBTM_STATUS::BTM_UNKNOWN_ADDR;
  }

  return btm_sec_report_bond_loss(p_device, transport, BTM_KEY_MISSING_LE_INCOMING_PAIRING);
}

/*******************************************************************************
 * disconnect the ACL link, if it's not done yet.
 ******************************************************************************/
static tBTM_STATUS btm_sec_send_hci_disconnect(BtmDevice* p_device, tHCI_STATUS reason,
                                               uint16_t conn_handle, std::string comment) {
  if (conn_handle == p_device->hci_handle) {
    if (p_device->sec_rec.classic_link == tSECURITY_STATE::DISCONNECTING) {
      // Already sent classic disconnect
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
    p_device->sec_rec.classic_link = tSECURITY_STATE::DISCONNECTING;
  } else if (conn_handle == p_device->ble_hci_handle) {
    if (p_device->sec_rec.le_link == tSECURITY_STATE::DISCONNECTING) {
      // Already sent ble disconnect
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
    p_device->sec_rec.le_link = tSECURITY_STATE::DISCONNECTING;
  } else {
    log::error(
            "Handle doesn't match security record! classic_handle: {}  ble_handle: {}, "
            "requested_handle: {}",
            p_device->hci_handle, p_device->ble_hci_handle, conn_handle);
  }

  log::debug("Send hci disconnect handle:0x{:04x} reason:{}", conn_handle,
             hci_reason_code_text(reason));
  acl_disconnect_after_role_switch(conn_handle, reason, comment);

  return tBTM_STATUS::BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_confirm_req_reply
 *
 * Description      This function is called to confirm the numeric value for
 *                  Simple Pairing in response to BTM_SP_CFM_REQ_EVT
 *
 * Parameters:      res           - result of the operation tBTM_STATUS::BTM_SUCCESS if
 *                                  success
 *                  bd_addr       - Address of the peer device
 *
 ******************************************************************************/
void btm_confirm_req_reply(tBTM_STATUS res, const RawAddress& bd_addr) {
  log::verbose("btm_confirm_req_reply() State: {}  Res: {}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_), res);

  /* If timeout already expired or has been canceled, ignore the reply */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_NUMERIC_CONFIRM ||
      BtmSecurity::Get().link_spec_.addrt.bda != bd_addr) {
    log::warn("Unexpected pairing confirm for {}, pairing_state: {}, pairing device: {}", bd_addr,
              btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
              BtmSecurity::Get().link_spec_);
    return;
  }

  BTM_LogHistory(kBtmLogTag, bd_addr, "Confirm reply",
                 std::format("status:{}", btm_status_text(res)));

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);

  if ((res == tBTM_STATUS::BTM_SUCCESS) || (res == tBTM_STATUS::BTM_SUCCESS_NO_SECURITY)) {
    acl_set_disconnect_reason(HCI_SUCCESS);

    btsnd_hcic_user_conf_reply(bd_addr, true);
  } else {
    /* Report authentication failed event from state
     * BTM_PAIR_STATE_WAIT_AUTH_COMPLETE */
    acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
    btsnd_hcic_user_conf_reply(bd_addr, false);
  }
}

/*******************************************************************************
 *
 * Function         btm_passkey_req_reply
 *
 * Description      This function is called to provide the passkey for
 *                  Simple Pairing in response to BTM_SP_KEY_REQ_EVT
 *
 * Parameters:      res     - result of the operation tBTM_STATUS::BTM_SUCCESS if success
 *                  bd_addr - Address of the peer device
 *                  passkey - numeric value in the range of
 *                  BTM_MIN_PASSKEY_VAL(0) -
 *                  BTM_MAX_PASSKEY_VAL(999999(0xF423F)).
 *
 ******************************************************************************/
void btm_passkey_req_reply(tBTM_STATUS res, const RawAddress& bd_addr, uint32_t passkey) {
  log::verbose("btm_passkey_req_reply: State: {}  res:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_), res);

  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_IDLE ||
      BtmSecurity::Get().link_spec_.addrt.bda != bd_addr) {
    return;
  }

  /* If timeout already expired or has been canceled, ignore the reply */
  if ((BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_WAIT_AUTH_COMPLETE) &&
      (res != tBTM_STATUS::BTM_SUCCESS)) {
    BtmDevice* p_device = btm_get_dev(bd_addr);
    if (p_device != NULL) {
      acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);

      if (p_device->hci_handle != HCI_INVALID_HANDLE) {
        btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, p_device->hci_handle,
                                    "stack::btm::btm_sec::btm_passkey_req_reply Invalid handle");
      } else {
        btm_sec_bond_cancel(bd_addr);
      }

      p_device->sec_rec.sec_flags &= ~(BTM_SEC_LINK_KEY_AUTHED | BTM_SEC_LINK_KEY_KNOWN);

      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      return;
    }
  } else if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_KEY_ENTRY) {
    return;
  }

  if (passkey > BTM_MAX_PASSKEY_VAL) {
    res = tBTM_STATUS::BTM_ILLEGAL_VALUE;
  }

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);

  if (res != tBTM_STATUS::BTM_SUCCESS) {
    /* use BTM_PAIR_STATE_WAIT_AUTH_COMPLETE to report authentication failed
     * event */
    acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
    btsnd_hcic_user_passkey_neg_reply(bd_addr);
  } else {
    acl_set_disconnect_reason(HCI_SUCCESS);
    btsnd_hcic_user_passkey_reply(bd_addr, passkey);
  }
}

/*******************************************************************************
 *
 * Function         btm_read_local_oob_data
 *
 * Description      This function is called to read the local OOB data from
 *                  LM
 *
 ******************************************************************************/
void btm_read_local_oob_data(void) {
  if (bluetooth::shim::GetController()->SupportsSecureConnections()) {
    btsnd_hcic_read_local_oob_extended_data();
  } else {
    btsnd_hcic_read_local_oob_data();
  }
}

/*******************************************************************************
 *
 * Function         btm_remote_oob_data_reply
 *
 * Description      This function is called to provide the remote OOB data for
 *                  Simple Pairing in response to BTM_SP_RMT_OOB_EVT
 *
 * Parameters:      bd_addr     - Address of the peer device
 *                  c           - simple pairing Hash C.
 *                  r           - simple pairing Randomizer  C.
 *
 ******************************************************************************/
void btm_remote_oob_data_reply(tBTM_STATUS res, const RawAddress& bd_addr, const Octet16& c,
                               const Octet16& r) {
  log::verbose("State: {} res: {}", btm_pair_state_descr(BtmSecurity::Get().pairing_state_), res);

  /* If timeout already expired or has been canceled, ignore the reply */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_LOCAL_OOB_RSP) {
    return;
  }

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);

  if (res != tBTM_STATUS::BTM_SUCCESS) {
    /* use BTM_PAIR_STATE_WAIT_AUTH_COMPLETE to report authentication failed
     * event */
    acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
    btsnd_hcic_rem_oob_neg_reply(bd_addr);
  } else {
    acl_set_disconnect_reason(HCI_SUCCESS);
    btsnd_hcic_rem_oob_reply(bd_addr, c, r);
  }
}

/*******************************************************************************
 *
 * Function         btm_peer_supports_secure_connections
 *
 * Description      This function is called to check if the peer supports
 *                  BR/EDR Secure Connections.
 *
 * Parameters:      bd_addr - address of the peer
 *
 * Returns          true if BR/EDR Secure Connections are supported by the peer,
 *                  else false.
 *
 ******************************************************************************/
bool btm_peer_supports_secure_connections(const RawAddress& bd_addr) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);
  if (p_device == nullptr) {
    log::warn("unknown BDA: {}", bd_addr);
    return false;
  }

  return p_device->SupportsSecureConnections();
}

/*******************************************************************************
 *
 * Function         BTM_GetPeerDeviceTypeFromFeatures
 *
 * Description      This function is called to retrieve the peer device type
 *                  by referencing the remote features.
 *
 * Parameters:      bd_addr - address of the peer
 *
 * Returns          BT_DEVICE_TYPE_DUMO if both BR/EDR and BLE transports are
 *                  supported by the peer,
 *                  BT_DEVICE_TYPE_BREDR if only BR/EDR transport is supported,
 *                  BT_DEVICE_TYPE_BLE if only BLE transport is supported.
 *
 ******************************************************************************/
tBT_DEVICE_TYPE BTM_GetPeerDeviceTypeFromFeatures(const RawAddress& bd_addr) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);
  if (p_device == nullptr) {
    log::warn("Unknown BDA:{}", bd_addr);
  } else {
    if (p_device->remote_supports_ble && p_device->remote_supports_bredr) {
      return BT_DEVICE_TYPE_DUMO;
    } else if (p_device->remote_supports_bredr) {
      return BT_DEVICE_TYPE_BREDR;
    } else if (p_device->remote_supports_ble) {
      return BT_DEVICE_TYPE_BLE;
    } else {
      log::warn("Device features does not support BR/EDR and BLE:{}", bd_addr);
    }
  }
  return BT_DEVICE_TYPE_BREDR;
}

/*******************************************************************************
 *
 * Function         BTM_GetInitialSecurityMode
 *
 * Description      This function is called to retrieve the configured
 *                  security mode.
 *
 ******************************************************************************/
uint8_t btm_get_security_mode() { return BtmSecurity::Get().security_mode_; }

/************************************************************************
 *              I N T E R N A L     F U N C T I O N S
 ************************************************************************/
/*******************************************************************************
 *
 * Function         security_upgrade_possible
 *
 * Description      This function returns true if the link security can be upgraded.
 *
 * Returns          bool
 *
 ******************************************************************************/
static bool security_upgrade_possible(const BtmDevice* p_device, bool outgoing) {
  const BtmSecurityRecord& sec_rec = p_device->sec_rec;

  if ((sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) != BTM_SEC_LINK_KEY_KNOWN) {
    // Not paired yet, so upgrade is possible
    log::debug("Not paired, upgrade is possible sec_flags: 0x{:04x}", sec_rec.sec_flags);
    return true;
  }

  uint16_t bond_check = outgoing ? BTM_SEC_OUT_AUTHENTICATE : BTM_SEC_IN_AUTHENTICATE;
  bool bonding_required = sec_rec.security_required & bond_check;

  if (bonding_required && !sec_rec.is_bond_type_persistent()) {
    log::debug("Not bonded, upgrade is possible sec_flags: 0x{:x}", sec_rec.sec_flags);
    return true;
  }

  uint16_t mitm_check = outgoing ? BTM_SEC_OUT_MITM : BTM_SEC_IN_MITM;
  bool mitm_protection_required = sec_rec.security_required & mitm_check;
  bool mitm_protected = sec_rec.link_key_type != BTM_LKEY_TYPE_UNAUTH_COMB &&
                        sec_rec.link_key_type != BTM_LKEY_TYPE_UNAUTH_COMB_P_256;
  const BtIoCap local_io_caps = btm_sec_get_local_iocaps();
  bool mitm_protection_supported =
          sec_rec.rmt_io_caps <= kBtIoCapClassicMax &&
          btm_sec_io_map[sec_rec.rmt_io_caps][static_cast<uint8_t>(local_io_caps)];

  if (mitm_protection_required && !mitm_protected && mitm_protection_supported) {
    log::debug("Not MITM protected, upgrade is possible sec_flags: 0x{:x}", sec_rec.sec_flags);
    return true;
  }

  log::verbose("Security upgrade not possible sec_flags: 0x{:x}", sec_rec.sec_flags);
  return false;
}

/*******************************************************************************
 *
 * Function         btm_sec_check_upgrade
 *
 * Description      This function is called to check if the existing link key
 *                  needs to be upgraded.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_check_upgrade(BtmDevice* p_device, bool outgoing) {
  if ((p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) != BTM_SEC_LINK_KEY_KNOWN) {
    log::verbose("{} not paired at all", p_device->bd_addr);
    return;
  }

  if (!security_upgrade_possible(p_device, outgoing)) {
    log::verbose("Upgrade not possible for {}", p_device->bd_addr);
    return;
  }

  p_device->sm4 |= BTM_SM4_UPGRADE;

  /* Clear the link key known to go through authentication/pairing again */
  auto sec_flags = p_device->sec_rec.sec_flags;
  p_device->sec_rec.sec_flags &= ~(BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_LINK_KEY_AUTHED);
  p_device->sec_rec.sec_flags &= ~BTM_SEC_AUTHENTICATED;
  log::verbose("{} need upgrade! sec_flags:0x{:x} -> 0x{:x}", p_device->bd_addr, sec_flags,
               p_device->sec_rec.sec_flags);
}

tBTM_STATUS btm_sec_l2cap_access_req_by_requirement(const RawAddress& bd_addr,
                                                    uint16_t security_required, bool outgoing,
                                                    tBTM_SEC_CALLBACK* p_callback,
                                                    void* p_ref_data) {
  log::debug(
          "Checking l2cap access requirements peer:{} security:0x{:x} "
          "is_initiator:{}",
          bd_addr, security_required, outgoing);

  tBTM_STATUS rc = tBTM_STATUS::BTM_SUCCESS;
  bool chk_acp_auth_done = false;
  /* should check PSM range in LE connection oriented L2CAP connection */
  constexpr tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;

  /* Find or get oldest record */
  BtmDevice* p_device = btm_find_or_alloc_dev(bd_addr);

  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  p_device->hci_handle =
          get_btm_client_interface().peer.BTM_GetHCIConnHandle(bd_addr, BT_TRANSPORT_BR_EDR);

  if ((!outgoing) && (security_required & BTM_SEC_MODE4_LEVEL4)) {
    bool local_supports_sc = bluetooth::shim::GetController()->SupportsSecureConnections();
    /* acceptor receives L2CAP Channel Connect Request for Secure Connections
     * Only service */
    if (!local_supports_sc || !p_device->SupportsSecureConnections()) {
      log::warn(
              "Policy requires mode 4 level 4, but local_support_for_sc={}, "
              "rmt_support_for_sc={}, failing connection",
              local_supports_sc, p_device->SupportsSecureConnections());
      if (p_callback) {
        (*p_callback)(bd_addr, transport, (void*)p_ref_data,
                      tBTM_STATUS::BTM_MODE4_LEVEL4_NOT_SUPPORTED);
      }
      return tBTM_STATUS::BTM_MODE4_LEVEL4_NOT_SUPPORTED;
    }
  }

  /* there are some devices (moto KRZR) which connects to several services at
   * the same time */
  /* we will process one after another */
  if ((p_device->sec_rec.p_callback) ||
      (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE)) {
    log::debug("security_flags:x{:x}, sec_flags:x{:x}", security_required,
               p_device->sec_rec.sec_flags);
    rc = tBTM_STATUS::BTM_CMD_STARTED;
    if ((BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SERVICE) ||
        (BTM_SM4_KNOWN == p_device->sm4) ||
        (BTM_SEC_IS_SM4(p_device->sm4) && (!security_upgrade_possible(p_device, outgoing)))) {
      /* legacy mode - local is legacy or local is lisbon/peer is legacy
       * or SM4 with no possibility of link key upgrade */
      if (outgoing) {
        if (((security_required & BTM_SEC_OUT_FLAGS) == 0) ||
            (((security_required & BTM_SEC_OUT_FLAGS) == BTM_SEC_OUT_AUTHENTICATE) &&
             btm_dev_authenticated(p_device)) ||
            (((security_required & BTM_SEC_OUT_FLAGS) ==
              (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT)) &&
             btm_dev_encrypted(p_device))) {
          rc = tBTM_STATUS::BTM_SUCCESS;
        }
      } else {
        if (((security_required & BTM_SEC_IN_FLAGS) == 0) ||
            (((security_required & BTM_SEC_IN_FLAGS) == BTM_SEC_IN_AUTHENTICATE) &&
             btm_dev_authenticated(p_device)) ||
            (((security_required & BTM_SEC_IN_FLAGS) ==
              (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT)) &&
             btm_dev_encrypted(p_device))) {
          // Check for 16 digits (or MITM)
          if (((security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN) == 0) ||
              (((security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN) == BTM_SEC_IN_MIN_16_DIGIT_PIN) &&
               btm_dev_16_digit_authenticated(p_device))) {
            rc = tBTM_STATUS::BTM_SUCCESS;
          }
        }
      }

      if ((rc == tBTM_STATUS::BTM_SUCCESS) && (security_required & BTM_SEC_MODE4_LEVEL4) &&
          (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
        rc = tBTM_STATUS::BTM_CMD_STARTED;
      }

      if (rc == tBTM_STATUS::BTM_SUCCESS) {
        if (access_secure_service_from_temp_bond(p_device, outgoing, security_required)) {
          log::error(
                  "Trying to access a secure service from a temp bonding, "
                  "rejecting");
          rc = tBTM_STATUS::BTM_FAILED_ON_SECURITY;
        }

        if (p_callback) {
          (*p_callback)(bd_addr, transport, (void*)p_ref_data, rc);
        }
        return rc;
      }
    }

    BtmSecurity::Get().l2c_service_access_pending_ = true;
    return tBTM_STATUS::BTM_CMD_STARTED;
  }

  /* Save the security requirements in case a pairing is needed */
  p_device->sec_rec.required_security_flags_for_pairing = security_required;

  /* Modify security_required in btm_sec_l2cap_access_req for Lisbon */
  if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SP ||
      BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
    if (BTM_SEC_IS_SM4(p_device->sm4)) {
      if (outgoing) {
        /* SM4 to SM4 -> always encrypt */
        security_required |= BTM_SEC_OUT_ENCRYPT;
      } else /* acceptor */
      {
        /* SM4 to SM4: the acceptor needs to make sure the authentication is
         * already done */
        chk_acp_auth_done = true;
        /* SM4 to SM4 -> always encrypt */
        security_required |= BTM_SEC_IN_ENCRYPT;
      }
    } else if (!(BTM_SM4_KNOWN & p_device->sm4)) {
      /* the remote features are not known yet */
      log::debug("Remote features have not yet been received sec_flags:0x{:02x} {}",
                 p_device->sec_rec.sec_flags, (outgoing) ? "initiator" : "acceptor");

      p_device->sm4 |= BTM_SM4_REQ_PEND;
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
  }

  log::verbose("sm4:0x{:x}, sec_flags:0x{:x}, security_required:0x{:x} chk:{}", p_device->sm4,
               p_device->sec_rec.sec_flags, security_required, chk_acp_auth_done);

  p_device->sec_rec.security_required = security_required;
  p_device->sec_rec.p_ref_data = p_ref_data;
  p_device->outgoing = outgoing;

  if (chk_acp_auth_done) {
    log::verbose(
            "(SM4 to SM4) btm_sec_l2cap_access_req rspd. authenticated: x{:x}, "
            "enc: x{:x}",
            p_device->sec_rec.sec_flags & BTM_SEC_AUTHENTICATED,
            p_device->sec_rec.sec_flags & BTM_SEC_ENCRYPTED);

    if (!com_android_bluetooth_flags_trigger_sec_proc_on_inc_access_req()) {
      /* SM4, but we do not know for sure which level of security we need.
       * as long as we have a link key, it's OK */
      if ((0 == (p_device->sec_rec.sec_flags & BTM_SEC_AUTHENTICATED)) ||
          (0 == (p_device->sec_rec.sec_flags & BTM_SEC_ENCRYPTED))) {
        rc = tBTM_STATUS::BTM_DELAY_CHECK;
        /*
        2046 may report HCI_Encryption_Change and L2C Connection Request out of
        sequence
        because of data path issues. Delay this disconnect a little bit
        */
        log::info("peer should have initiated security process by now (SM4 to SM4)");
        p_device->sec_rec.p_callback = p_callback;
        p_device->sec_rec.classic_link = tSECURITY_STATE::DELAY_FOR_ENC;
        (*p_callback)(bd_addr, transport, p_ref_data, rc);

        return tBTM_STATUS::BTM_SUCCESS;
      }
    } else {
      log::debug("force fallthrough to trigger sec proceudure");
    }
  }

  p_device->sec_rec.p_callback = p_callback;

  if (BTM_SEC_IS_SM4(p_device->sm4)) {
    if ((p_device->sec_rec.security_required & BTM_SEC_MODE4_LEVEL4) &&
        (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
      /* BTM_LKEY_TYPE_AUTH_COMB_P_256 is the only acceptable key in this case
       */
      if ((p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) != 0) {
        p_device->sm4 |= BTM_SM4_UPGRADE;
      }
      p_device->sec_rec.sec_flags &=
              ~(BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_LINK_KEY_AUTHED | BTM_SEC_AUTHENTICATED);
      log::verbose("sec_flags:0x{:x}", p_device->sec_rec.sec_flags);
    } else {
      /* If we already have a link key to the connected peer, is it secure
       * enough? */
      btm_sec_check_upgrade(p_device, outgoing);
    }
  }

  rc = btm_sec_execute_procedure(p_device);
  if (rc != tBTM_STATUS::BTM_CMD_STARTED) {
    log::verbose("p_device={}, clearing callback. old p_callback={}", std::format_ptr(p_device),
                 std::format_ptr(p_device->sec_rec.p_callback));
    p_device->sec_rec.p_callback = NULL;
    (*p_callback)(bd_addr, transport, p_device->sec_rec.p_ref_data, rc);
  }

  return rc;
}

/*******************************************************************************
 *
 * Function         btm_sec_l2cap_access_req
 *
 * Description      This function is called by the L2CAP to grant permission to
 *                  establish L2CAP connection to or from the peer device.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  psm           - L2CAP PSM
 *                  outgoing - true if protocol above L2CAP originates
 *                                  connection
 *                  p_callback    - Pointer to callback function called if
 *                                  this function returns PENDING after required
 *                                  procedures are complete. MUST NOT BE NULL.
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
tBTM_STATUS btm_sec_l2cap_access_req(const RawAddress& bd_addr, uint16_t psm, bool outgoing,
                                     tBTM_SEC_CALLBACK* p_callback, void* p_ref_data) {
  // should check PSM range in LE connection oriented L2CAP connection
  constexpr tBT_TRANSPORT transport = BT_TRANSPORT_BR_EDR;

  log::debug("outgoing:{}, psm=0x{:04x}", outgoing, psm);

  // Find the service record for the PSM
  tBTM_SEC_SERV_REC* p_serv_rec = BtmSecurity::Get().find_first_serv_rec(outgoing, psm);

  // If there is no application registered with this PSM do not allow connection
  if (!p_serv_rec) {
    log::warn("PSM: 0x{:04x} no application registered", psm);
    (*p_callback)(bd_addr, transport, p_ref_data, tBTM_STATUS::BTM_MODE_UNSUPPORTED);
    return tBTM_STATUS::BTM_MODE_UNSUPPORTED;
  }

  /* Services level0 by default have no security */
  if (psm == BT_PSM_SDP) {
    log::debug("No security required for SDP");
    (*p_callback)(bd_addr, transport, p_ref_data, tBTM_STATUS::BTM_SUCCESS_NO_SECURITY);
    return tBTM_STATUS::BTM_SUCCESS;
  }

  uint16_t security_required;
  if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
    security_required = btm_sec_set_serv_level4_flags(p_serv_rec->security_flags, outgoing);
  } else {
    security_required = p_serv_rec->security_flags;
  }

  return btm_sec_l2cap_access_req_by_requirement(bd_addr, security_required, outgoing, p_callback,
                                                 p_ref_data);
}

/*******************************************************************************
 *
 * Function         btm_sec_service_access_request
 *
 * Description      This function is called by all Multiplexing Protocols during
 *                  establishing connection to or from peer device to grant
 *                  permission to establish application connection.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  outgoing - true if protocol above L2CAP originates
 *                                  connection
 *                  p_callback    - Pointer to callback function called if
 *                                  this function returns PENDING after required
 *                                  procedures are completed
 *                  p_ref_data    - Pointer to any reference data needed by the
 *                                  the callback function.
 *
 * Returns          tBTM_STATUS::BTM_CMD_STARTED when the security procedure is
 *                  started.
 *                  tBTM_STATUS::BTM_CMD_STORED when the security procedure is
 *                  stored in the queue.
 *                  tBTM_STATUS::BTM_SUCCESS when the security procedure is
 *                  completed.
 *
 ******************************************************************************/
tBTM_STATUS btm_sec_service_access_request(const RawAddress& bd_addr, bool outgoing,
                                           uint16_t security_required,
                                           tBTM_SEC_CALLBACK* p_callback, void* p_ref_data) {
  BtmDevice* p_device;
  tBTM_STATUS rc;
  tBT_TRANSPORT transport = BT_TRANSPORT_AUTO; /* should check PSM range in LE connection oriented
                                                  L2CAP connection */
  log::debug("Multiplex access request device:{}", bd_addr);

  /* Find or get oldest record */
  p_device = btm_find_or_alloc_dev(bd_addr);

  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  /* there are some devices (moto phone) which connects to several services at
   * the same time */
  /* we will process one after another */
  if ((p_device->sec_rec.p_callback) ||
      (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE)) {
    log::debug("Pairing in progress pairing_state:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_));

    rc = tBTM_STATUS::BTM_CMD_STARTED;

    if ((BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SERVICE) ||
        (BTM_SM4_KNOWN == p_device->sm4) ||
        (BTM_SEC_IS_SM4(p_device->sm4) && (!security_upgrade_possible(p_device, outgoing)))) {
      /* legacy mode - local is legacy or local is lisbon/peer is legacy
       * or SM4 with no possibility of link key upgrade */
      if (outgoing) {
        if (((security_required & BTM_SEC_OUT_FLAGS) == 0) ||
            (((security_required & BTM_SEC_OUT_FLAGS) == BTM_SEC_OUT_AUTHENTICATE) &&
             btm_dev_authenticated(p_device)) ||
            (((security_required & BTM_SEC_OUT_FLAGS) ==
              (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT)) &&
             btm_dev_encrypted(p_device))) {
          rc = tBTM_STATUS::BTM_SUCCESS;
        }
      } else {
        if (((security_required & BTM_SEC_IN_FLAGS) == 0) ||
            (((security_required & BTM_SEC_IN_FLAGS) == BTM_SEC_IN_AUTHENTICATE) &&
             btm_dev_authenticated(p_device)) ||
            (((security_required & BTM_SEC_IN_FLAGS) ==
              (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT)) &&
             btm_dev_encrypted(p_device))) {
          // Check for 16 digits (or MITM)
          if (((security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN) == 0) ||
              (((security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN) == BTM_SEC_IN_MIN_16_DIGIT_PIN) &&
               btm_dev_16_digit_authenticated(p_device))) {
            rc = tBTM_STATUS::BTM_SUCCESS;
          }
        }
      }
      if ((rc == tBTM_STATUS::BTM_SUCCESS) && (security_required & BTM_SEC_MODE4_LEVEL4) &&
          (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
        rc = tBTM_STATUS::BTM_CMD_STARTED;
      }
    }

    /* the new security request */
    if (p_device->sec_rec.classic_link != tSECURITY_STATE::IDLE) {
      log::debug("A pending security procedure in progress");
      rc = tBTM_STATUS::BTM_CMD_STARTED;
    }
    if (rc == tBTM_STATUS::BTM_CMD_STARTED) {
      btm_sec_queue_service_access_request(bd_addr, BT_PSM_RFCOMM, outgoing, security_required,
                                           p_callback, p_ref_data);
      return tBTM_STATUS::BTM_CMD_STORED;
    } else /* rc == tBTM_STATUS::BTM_SUCCESS */
    {
      if (access_secure_service_from_temp_bond(p_device, outgoing, security_required)) {
        log::error(
                "Trying to access a secure rfcomm service from a temp bonding, "
                "rejecting");
        rc = tBTM_STATUS::BTM_FAILED_ON_SECURITY;
      }
      if (p_callback) {
        log::debug("Notifying client that security access has been granted");
        (*p_callback)(bd_addr, transport, p_ref_data, rc);
      }
    }
    return rc;
  }

  if ((!outgoing) && ((security_required & BTM_SEC_MODE4_LEVEL4) ||
                      (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC))) {
    bool local_supports_sc = bluetooth::shim::GetController()->SupportsSecureConnections();
    /* acceptor receives service connection establishment Request for */
    /* Secure Connections Only service */
    if (!(local_supports_sc) || !(p_device->SupportsSecureConnections())) {
      log::debug(
              "Secure Connection only mode unsupported local_SC_support:{} "
              "remote_SC_support:{}",
              local_supports_sc, p_device->SupportsSecureConnections());
      if (p_callback) {
        (*p_callback)(bd_addr, transport, (void*)p_ref_data,
                      tBTM_STATUS::BTM_MODE4_LEVEL4_NOT_SUPPORTED);
      }

      return tBTM_STATUS::BTM_MODE4_LEVEL4_NOT_SUPPORTED;
    }
  }

  if (security_required & BTM_SEC_OUT_AUTHENTICATE) {
    security_required |= BTM_SEC_OUT_MITM;
  }
  if (security_required & BTM_SEC_IN_AUTHENTICATE) {
    security_required |= BTM_SEC_IN_MITM;
  }

  p_device->sec_rec.required_security_flags_for_pairing = security_required;
  p_device->sec_rec.security_required = security_required;

  if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SP ||
      BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
    if (BTM_SEC_IS_SM4(p_device->sm4)) {
      if ((p_device->sec_rec.security_required & BTM_SEC_MODE4_LEVEL4) &&
          (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
        /* BTM_LKEY_TYPE_AUTH_COMB_P_256 is the only acceptable key in this case
         */
        if ((p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) != 0) {
          p_device->sm4 |= BTM_SM4_UPGRADE;
        }

        p_device->sec_rec.sec_flags &=
                ~(BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_LINK_KEY_AUTHED | BTM_SEC_AUTHENTICATED);
        log::verbose("sec_flags:0x{:x}", p_device->sec_rec.sec_flags);
      } else {
        log::debug("Already have link key; checking if link key is sufficient");
        btm_sec_check_upgrade(p_device, outgoing);
      }
    }
  }

  p_device->outgoing = outgoing;
  p_device->sec_rec.p_callback = p_callback;
  p_device->sec_rec.p_ref_data = p_ref_data;

  rc = btm_sec_execute_procedure(p_device);
  log::debug("Started security procedure peer:{} btm_status:{}", p_device->RemoteAddress(),
             btm_status_text(rc));
  if (rc != tBTM_STATUS::BTM_CMD_STARTED) {
    if (p_callback) {
      p_device->sec_rec.p_callback = NULL;
      (*p_callback)(bd_addr, transport, p_ref_data, rc);
    }
  }

  return rc;
}

/*******************************************************************************
 *
 * Function         btm_sec_conn_req
 *
 * Description      This function is when the peer device is requesting
 *                  connection
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_conn_req(const RawAddress& bda, const DEV_CLASS dc) {
  // Host is not interested or approved connection. Save BDA and DC and pass request to L2CAP
  BtmSecurity::Get().connecting_bda_ = bda;
  BtmSecurity::Get().connecting_dc_ = dc;

  BtmDevice* p_device = btm_find_or_alloc_dev(bda);
  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }
  p_device->sm4 |= BTM_SM4_CONN_PEND;

  if (!com_android_bluetooth_flags_update_cod_on_incoming_connection()) {
    if (p_device->sec_rec.is_bonded() &&
        (p_device->dev_class == kDevClassEmpty || p_device->dev_class == kDevClassUnclassified)) {
      log::debug("Updating CoD for bonded device {} to [0x{:x}, 0x{:x}, 0x{:x}]", bda, dc[0], dc[1],
                 dc[2]);
      p_device->dev_class = dc;
      btif_update_remote_properties(bda, p_device->sec_bd_name, p_device->dev_class,
                                    p_device->device_type);
    }
    return;
  }

  // Update CoD if cached value does not match
  if (dc != kDevClassEmpty && p_device->dev_class != kDevClassUnclassified &&
      p_device->dev_class != dc) {
    log::debug("Updating CoD for {} to [0x{:x}, 0x{:x}, 0x{:x}]", bda, dc[0], dc[1], dc[2]);
    p_device->dev_class = dc;
    btif_update_remote_properties(bda, p_device->sec_bd_name, p_device->dev_class,
                                  p_device->device_type);
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_bond_cancel_complete
 *
 * Description      This function is called to report bond cancel complete
 *                  event.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_bond_cancel_complete(void) {
  BtmDevice* p_device;

  if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE) ||
      (BTM_PAIR_STATE_WAIT_LOCAL_PIN == BtmSecurity::Get().pairing_state_ &&
       BTM_PAIR_FLAGS_WE_STARTED_DD & BtmSecurity::Get().pairing_flags_) ||
      (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_GET_REM_NAME &&
       BTM_PAIR_FLAGS_WE_CANCEL_DD & BtmSecurity::Get().pairing_flags_) ||
      (BTM_PAIR_STATE_WAIT_PIN_REQ == BtmSecurity::Get().pairing_state_)) {
    /* for dedicated bonding in legacy mode, authentication happens at "link
     * level"
     * btm_sec_connected is called with failed status.
     * In theory, the code that handles is_pairing_device/true should clean out
     * security related code.
     * However, this function may clean out the security related flags and
     * btm_sec_connected would not know
     * this function also needs to do proper clean up.
     */
    p_device = btm_get_dev(BtmSecurity::Get().link_spec_.addrt.bda);
    if (p_device != NULL) {
      p_device->sec_rec.security_required = BTM_SEC_NONE;
    }
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

    /* Notify application that the cancel succeeded */
    BtmSecurity::Get().app_->bond_cancel_cmpl_callback(tBTM_STATUS::BTM_SUCCESS);
  }
}

/*******************************************************************************
 *
 * Function         btm_create_conn_cancel_complete
 *
 * Description      This function is called when the command complete message
 *                  is received from the HCI for the create connection cancel
 *                  command.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_create_conn_cancel_complete(uint8_t status, const RawAddress& bd_addr) {
  log::verbose("btm_create_conn_cancel_complete(): in State: {}  status:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_), status);
  bluetooth::metrics::LogMetricLinkLayerConnectionEvent(
          bd_addr, bluetooth::metrics::kUnknownConnectionHandle,
          android::bluetooth::DIRECTION_OUTGOING, android::bluetooth::LINK_TYPE_ACL,
          android::bluetooth::hci::CMD_CREATE_CONNECTION_CANCEL,
          android::bluetooth::hci::EVT_COMMAND_COMPLETE, android::bluetooth::hci::BLE_EVT_UNKNOWN,
          status, android::bluetooth::hci::STATUS_UNKNOWN);

  /* if the create conn cancel cmd was issued by the bond cancel,
  ** the application needs to be notified that bond cancel succeeded
  */
  switch (status) {
    case HCI_SUCCESS:
      btm_sec_bond_cancel_complete();
      break;
    case HCI_ERR_CONNECTION_EXISTS:
    case HCI_ERR_NO_CONNECTION:
    default:
      /* Notify application of the error */
      BtmSecurity::Get().app_->bond_cancel_cmpl_callback(tBTM_STATUS::BTM_ERR_PROCESSING);
      break;
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_check_pending_reqs
 *
 * Description      This function is called at the end of the security procedure
 *                  to let L2CAP and RFCOMM know to re-submit any pending
 *                  requests
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_check_pending_reqs(void) {
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE) {
    log::warn("Busy state {} device {}", btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
              BtmSecurity::Get().link_spec_);
    return;
  }

  /* Resubmit L2CAP requests, if any */
  if (BtmSecurity::Get().l2c_service_access_pending_) {
    BtmSecurity::Get().l2c_service_access_pending_ = false;
    l2cu_resubmit_pending_sec_req(nullptr);
  }

  // Remove any service access requests which are concluded or belong to disconnected devices
  auto predicate = [](const tBTM_SERVICE_ACCESS_REQ& req) {
    if (!get_btm_client_interface().peer.BTM_IsAclConnectionUp(req.bd_addr, BT_TRANSPORT_BR_EDR)) {
      log::debug(
              "Ignoring service access request for disconnected device {} psm:0x{:04x} is_orig:{}",
              req.bd_addr, req.psm, req.is_orig);
      return true;
    }

    if (btm_sec_service_access_request(req.bd_addr, req.is_orig, req.rfcomm_security_requirement,
                                       req.callback, req.ref) != tBTM_STATUS::BTM_CMD_STORED) {
      log::debug("Service access request concluded or started for {} psm:0x{:04x} is_orig:{}",
                 req.bd_addr, req.psm, req.is_orig);
      return true;
    }

    return false;
  };
  std::erase_if(BtmSecurity::Get().service_access_q_, predicate);
}

/*******************************************************************************
 *
 * Function         btm_sec_dev_reset
 *
 * Description      This function should be called after device reset
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_dev_reset(void) {
  log::assert_that(bluetooth::shim::GetController()->SupportsSimplePairing(),
                   "only controllers with SSP is supported");

  /* add mx service to use no security */
  btm_set_security_level(false, "RFC_MUX", BTM_SEC_SERVICE_RFC_MUX, BTM_SEC_NONE, BT_PSM_RFCOMM,
                         BTM_SEC_PROTO_RFCOMM, 0);
  btm_set_security_level(true, "RFC_MUX", BTM_SEC_SERVICE_RFC_MUX, BTM_SEC_NONE, BT_PSM_RFCOMM,
                         BTM_SEC_PROTO_RFCOMM, 0);
  log::verbose("btm_sec_dev_reset sec mode: {}", BtmSecurity::Get().security_mode_);
}

/*******************************************************************************
 *
 * Function         btm_sec_abort_access_req
 *
 * Description      This function is called by the L2CAP or RFCOMM to abort
 *                  the pending operation.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_abort_access_req(const RawAddress& bd_addr) {
  BtmDevice* p_device = btm_get_dev(bd_addr);

  if (!p_device) {
    return;
  }

  if ((p_device->sec_rec.classic_link != tSECURITY_STATE::AUTHORIZING) &&
      (p_device->sec_rec.classic_link != tSECURITY_STATE::AUTHENTICATING)) {
    return;
  }

  p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;

  log::verbose("clearing callback. p_device={}, p_callback={}", std::format_ptr(p_device),
               std::format_ptr(p_device->sec_rec.p_callback));
  p_device->sec_rec.p_callback = NULL;
}

/*******************************************************************************
 *
 * Function         btm_sec_dd_create_conn
 *
 * Description      This function is called to create an ACL connection for
 *                  the dedicated bonding process
 *
 * Returns          tBTM_STATUS::BTM_SUCCESS if an ACL connection is already up
 *                  tBTM_STATUS::BTM_CMD_STARTED if the ACL connection has been requested
 *                  tBTM_STATUS::BTM_NO_RESOURCES if failed to start the ACL connection
 *
 ******************************************************************************/
static tBTM_STATUS btm_sec_dd_create_conn(BtmDevice* p_device) {
  tBTM_STATUS status = l2cu_ConnectAclForSecurity(p_device->bd_addr);
  if (status == tBTM_STATUS::BTM_CMD_STARTED) {
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);
    /* If already connected, start pending security procedure */
    if (get_btm_client_interface().peer.BTM_IsAclConnectionUp(p_device->bd_addr,
                                                              BT_TRANSPORT_BR_EDR)) {
      return tBTM_STATUS::BTM_SUCCESS;
    }
    return tBTM_STATUS::BTM_CMD_STARTED;
  } else if (status == tBTM_STATUS::BTM_NO_RESOURCES) {
    return tBTM_STATUS::BTM_NO_RESOURCES;
  }

  /* set up the control block to indicated dedicated bonding */
  BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_DISC_WHEN_DONE;

  log::info("Security Manager: {}", p_device->bd_addr);

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_PIN_REQ);

  return tBTM_STATUS::BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         call_registered_rmt_name_callbacks
 *
 * Description      When an RNR event is received from the controller execute
 *                  the registered RNR callbacks.
 *
 * Returns          None
 *
 ******************************************************************************/
static void call_registered_rmt_name_callbacks(const RawAddress& bd_addr, const BD_NAME& bd_name) {
  if (btm_cb.rnr.p_rmt_name_callback == nullptr) {
    log::error("No RNR callback registered!");
    return;
  }

  (*btm_cb.rnr.p_rmt_name_callback)(bd_addr, bd_name);
}

/*******************************************************************************
 *
 * Function         btm_rnr_add_name_to_security_record
 *
 * Description      When an RNR event is received from the controller,
 *                  if valid, add the name to the device record.
 *
 * Returns          SecurityDeviceRecord pointer if record is found for
 *                    given bluetooth device address.  If hci status was
 *                    successful bd_name is updated in security device record.
 *                  nullptr if record is not found
 *
 ******************************************************************************/
static BtmDevice* btm_rnr_add_name_to_security_record(const RawAddress* p_bd_addr,
                                                      const uint8_t* p_bd_name,
                                                      tHCI_STATUS hci_status) {
  /* If remote name request failed, p_bd_addr is null and we need to search */
  /* based on state assuming that we are doing 1 at a time */
  BtmDevice* p_device = nullptr;
  if (p_bd_addr) {
    p_device = btm_get_dev(*p_bd_addr);
  } else {
    log::info(
            "Remote read request complete with no address so searching device "
            "database");
    p_device = btm_sec_find_dev_by_sec_state(tSECURITY_STATE::GETTING_NAME);
    if (p_device) {
      p_bd_addr = &p_device->bd_addr;
    }
  }

  if (!p_bd_name) {
    p_bd_name = (const uint8_t*)kBtmBdNameEmpty;
  }

  BTM_LogHistory(kBtmLogTag, (p_bd_addr) ? *p_bd_addr : RawAddress::kEmpty, "RNR complete",
                 std::format("hci_status:{} name:{}", hci_error_code_text(hci_status),
                             reinterpret_cast<char const*>(p_bd_name)));

  if (p_device == nullptr) {
    log::warn("Unable to issue callback with unknown address status:{}",
              hci_status_code_text(hci_status));
    return nullptr;
  }

  // We are guaranteed to have an address at this point
  const RawAddress bd_addr(*p_bd_addr);

  if (hci_status == HCI_SUCCESS) {
    log::debug(
            "Remote read request complete for known device pairing_state:{} "
            "name:{} classic_link:{}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
            reinterpret_cast<char const*>(p_bd_name), p_device->sec_rec.classic_link);
    bd_name_copy(p_device->sec_bd_name, p_bd_name);
    p_device->sec_rec.sec_flags |= BTM_SEC_NAME_KNOWN;
    log::verbose("setting BTM_SEC_NAME_KNOWN sec_flags:0x{:x}", p_device->sec_rec.sec_flags);
  } else {
    log::warn(
            "Remote read request failed for known device pairing_state:{} "
            "hci_status:{} name:{} classic_link:{}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
            hci_status_code_text(hci_status), reinterpret_cast<char const*>(p_bd_name),
            p_device->sec_rec.classic_link);

    /* Notify all clients waiting for name to be resolved even if it failed so
     * clients can continue */
    p_device->sec_bd_name[0] = 0;
  }

  bluetooth::metrics::LogRemoteNameRequestCompletion(bd_addr, hci_status);

  /* Notify all clients waiting for name to be resolved */
  call_registered_rmt_name_callbacks(bd_addr, p_device->sec_bd_name);
  return p_device;
}

/*******************************************************************************
 *
 * Function         btm_sec_rmt_name_request_complete
 *
 * Description      This function is called when remote name was obtained from
 *                  the peer device
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_rmt_name_request_complete(const RawAddress* p_bd_addr, const uint8_t* p_bd_name,
                                       tHCI_STATUS hci_status) {
  log::info("btm_sec_rmt_name_request_complete for {}",
            p_bd_addr ? p_bd_addr->ToRedactedStringForLogging() : "null");

  if ((!p_bd_addr && !get_btm_client_interface().peer.BTM_IsAclConnectionUp(
                             BtmSecurity::Get().connecting_bda_, BT_TRANSPORT_BR_EDR)) ||
      (p_bd_addr &&
       !get_btm_client_interface().peer.BTM_IsAclConnectionUp(*p_bd_addr, BT_TRANSPORT_BR_EDR))) {
    log::warn("Remote read request complete with no underlying link connection");
  }

  BtmDevice* p_device = btm_rnr_add_name_to_security_record(p_bd_addr, p_bd_name, hci_status);
  if (p_device == nullptr) {
    log::warn(
            "Remote read request complete for unknown device peer:{} "
            "pairing_state:{} hci_status:{} name:{}",
            p_bd_addr ? p_bd_addr->ToRedactedStringForLogging() : "null",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
            hci_status_code_text(hci_status), reinterpret_cast<char const*>(p_bd_name));
    return;
  }
  const RawAddress bd_addr(p_device->RemoteAddress());

  // Security procedure resumes
  const bool is_security_state_getting_name =
          (p_device->sec_rec.classic_link == tSECURITY_STATE::GETTING_NAME);
  if (is_security_state_getting_name) {
    p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
  }

  /* If we were delaying asking UI for a PIN because name was not resolved, ask now */
  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_WAIT_LOCAL_PIN &&
      BtmSecurity::Get().link_spec_.addrt.bda == bd_addr) {
    log::verbose("delayed pin now being requested flags:0x{:x}", BtmSecurity::Get().pairing_flags_);

    if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_PIN_REQD) == 0) {
      log::verbose("calling pin_callback");
      BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_PIN_REQD;
      (BtmSecurity::Get().app_->pin_callback)(
              p_device->bd_addr, p_device->dev_class, p_device->sec_bd_name,
              p_device->sec_rec.required_security_flags_for_pairing & BTM_SEC_IN_MIN_16_DIGIT_PIN,
              p_device->sec_rec.pairing_algorithm);
    }

    /* Set the same state again to force the timer to be restarted */
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_LOCAL_PIN);
    return;
  }

  /* Check if we were delaying bonding because name was not resolved */
  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_GET_REM_NAME) {
    if (BtmSecurity::Get().link_spec_.addrt.bda != bd_addr) {
      log::warn("wrong BDA {}, retry with pairing device {}", bd_addr,
                BtmSecurity::Get().link_spec_);
      tBTM_STATUS btm_status = get_stack_rnr_interface().BTM_ReadRemoteDeviceName(
              BtmSecurity::Get().link_spec_.addrt.bda, NULL, BT_TRANSPORT_BR_EDR);
      if (btm_status != tBTM_STATUS::BTM_CMD_STARTED) {
        log::warn(
                "failed ({}) to restart remote name request for pairing {}, must be already queued",
                btm_status_text(btm_status), BtmSecurity::Get().link_spec_);
      }
      return;
    }

    log::verbose("continue bonding sm4: 0x{:04x}, hci_status:{}", p_device->sm4,
                 hci_error_code_text(hci_status));
    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_CANCEL_DD) {
      btm_sec_bond_cancel_complete();
      return;
    }

    if (hci_status != HCI_SUCCESS) {
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

      return NotifyBondingChange(*p_device, hci_status);
    }

    /* if peer is very old legacy devices, HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT is
     * not reported */
    if (BTM_SEC_IS_SM4_UNKNOWN(p_device->sm4)) {
      /* set the KNOWN flag only if BTM_PAIR_FLAGS_REJECTED_CONNECT is not
       * set.*/
      /* If it is set, there may be a race condition */
      log::verbose("IS_SM4_UNKNOWN Flags:0x{:04x}", BtmSecurity::Get().pairing_flags_);
      if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_REJECTED_CONNECT) == 0) {
        p_device->sm4 |= BTM_SM4_KNOWN;
      }
    }

    log::verbose("SM4 Value: {:x}, Legacy:{},IS SM4:{}, Unknown:{}", p_device->sm4,
                 BTM_SEC_IS_SM4_LEGACY(p_device->sm4), BTM_SEC_IS_SM4(p_device->sm4),
                 BTM_SEC_IS_SM4_UNKNOWN(p_device->sm4));

    bool await_connection = true;
    /* Note: Prefetching is removed with the flag security_mode_3_pairing.
     *
     * If peer is BT 2.1 or carkit, bring up the connection to force the peer to request PIN.
     ** Else prefetch (btm_sec_check_prefetch_pin will do the prefetching if needed)
     */
    if ((p_device->sm4 != BTM_SM4_KNOWN) || !btm_sec_check_prefetch_pin(p_device)) {
      /* if we rejected incoming connection request, we have to wait
       * HCI_Connection_Complete event */
      /*  before originating  */
      if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_REJECTED_CONNECT) {
        log::warn("waiting HCI_Connection_Complete after rejecting connection");
      } else {
        /* Both we and the peer are 2.1 - continue to create connection */
        tBTM_STATUS req_status = btm_sec_dd_create_conn(p_device);
        bluetooth::metrics::LogAclAfterRemoteNameRequest(bd_addr, req_status);
        if (req_status == tBTM_STATUS::BTM_SUCCESS) {
          await_connection = false;
        } else if (req_status != tBTM_STATUS::BTM_CMD_STARTED) {
          log::warn("failed to start connection");

          BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

          NotifyBondingChange(*p_device, HCI_ERR_MEMORY_FULL);
        }
      }
    }

    if (await_connection) {
      log::debug("Wait for connection to begin pairing");
      return;
    }
  }

  /* check if we were delaying link_key_callback because name was not resolved
   */
  if (p_device->sec_rec.link_key_not_sent) {
    /* If HCI connection complete has not arrived, wait for it */
    if (p_device->hci_handle == HCI_INVALID_HANDLE) {
      return;
    }

    p_device->sec_rec.link_key_not_sent = false;
    btm_send_link_key_notif(p_device);
  }

  /* If this is a bonding procedure can disconnect the link now */
  if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
      (p_device->sec_rec.sec_flags & BTM_SEC_AUTHENTICATED)) {
    log::warn("btm_sec_rmt_name_request_complete (none/ce)");
    p_device->sec_rec.security_required &= ~(BTM_SEC_OUT_AUTHENTICATE);
    l2cu_start_post_bond_timer(p_device->hci_handle);
    return;
  }

  if (!is_security_state_getting_name) {
    log::warn("Security manager received RNR event when not in expected state");
    return;
  }

  /* If get name failed, notify the waiting layer */
  if (hci_status != HCI_SUCCESS) {
    btm_sec_dev_rec_cback_event(p_device, tBTM_STATUS::BTM_ERR_PROCESSING, false);
    return;
  }

  if (p_device->sm4 & BTM_SM4_REQ_PEND) {
    log::verbose("waiting for remote features!!");
    return;
  }

  /* Remote Name succeeded, execute the next security procedure, if any */
  tBTM_STATUS btm_status = btm_sec_execute_procedure(p_device);

  /* If result is pending reply from the user or from the device is pending */
  if (btm_status == tBTM_STATUS::BTM_CMD_STARTED) {
    return;
  }

  /* There is no next procedure or start of procedure failed, notify the waiting
   * layer */
  btm_sec_dev_rec_cback_event(p_device, btm_status, false);
}

/*******************************************************************************
 *
 * Function         btm_sec_rmt_host_support_feat_evt
 *
 * Description      This function is called when the
 *                  HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT is received
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_rmt_host_support_feat_evt(const RawAddress& bd_addr, uint8_t features_0) {
  BtmDevice* p_device = btm_find_or_alloc_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  log::debug("{}: sm4: 0x{:x}  p[0]: 0x{:x}", bd_addr, p_device->sm4, features_0);

  if (BTM_SEC_IS_SM4_UNKNOWN(p_device->sm4)) {
    p_device->sm4 = BTM_SM4_KNOWN;
    if (HCI_SSP_HOST_SUPPORTED(&features_0)) {
      p_device->sm4 = BTM_SM4_TRUE;
    }
  }
}

/*******************************************************************************
 *
 * Function         btm_io_capabilities_req
 *
 * Description      This function is called when LM request for the IO
 *                  capability of the local device and
 *                  if the OOB data is present for the device in the event
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_io_capabilities_req(const RawAddress& bda) {
  BtmDevice* p_device = btm_find_or_alloc_dev(bda);

  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  if (p_device->sec_rec.is_bonded(BT_TRANSPORT_BR_EDR)) {
    /* Encrypted link means that the device is already authenticated and is trying to upgrade
     * security */
    if (!p_device->sec_rec.is_device_encrypted()) {
      if (!is_autonomous_repairing_supported()) {
        btsnd_hcic_io_cap_req_neg_reply(bda, HCI_ERR_PAIRING_NOT_ALLOWED);
      }
      btm_sec_report_bond_loss(p_device, BT_TRANSPORT_BR_EDR,
                               BTM_KEY_MISSING_BREDR_INCOMING_PAIRING);
      if (!is_autonomous_repairing_supported()) {
        // continue with pairing process
        return;
      }
    }

    log::info("Incoming pairing request for bonded and encrypted device {}", bda);
    if (!is_autonomous_repairing_supported() || !p_device->bond_lost) {
      // Do not remove the device, just proceed with re-pairing.
      bta_dm_process_remove_device(bda);
    }
  }

  if ((BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) &&
      (!p_device->remote_feature_received)) {
    log::verbose(
            "Device security mode is SC only.To continue need to know remote "
            "features.");

    // ACL calls back to btm_sec_set_peer_sec_caps after it gets data
    p_device->remote_features_needed = true;
    return;
  }

  tBTM_SP_IO_REQ evt_data;
  evt_data.bd_addr = bda;

  // TODO(optedoblivion): Inject OOB_DATA_PRESENT Flag
  evt_data.oob_data = BTM_OOB_NONE;
  evt_data.auth_req = BTM_AUTH_SP_NO;

  p_device->sm4 |= BTM_SM4_TRUE;

  log::verbose("State: {}, Security Mode: {}, Device security Flags: 0x{:04x}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
               BtmSecurity::Get().security_mode_, BtmSecurity::Get().pairing_flags_);

  uint8_t err_code = 0;
  bool is_orig = true;
  switch (BtmSecurity::Get().pairing_state_) {
    /* initiator connecting */
    case BTM_PAIR_STATE_IDLE:
      // TODO: Handle Idle pairing state
      // security_required = p_device->sec_rec.security_required;
      break;

    /* received IO capability response already->acceptor */
    case BTM_PAIR_STATE_INCOMING_SSP:
      is_orig = false;

      if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_PEER_STARTED_DD) {
        /* acceptor in dedicated bonding */
        evt_data.auth_req = BTM_AUTH_AP_YES;
      }
      break;

    /* initiator, at this point it is expected to be dedicated bonding
    initiated by local device */
    case BTM_PAIR_STATE_WAIT_PIN_REQ:
      if (evt_data.bd_addr == BtmSecurity::Get().link_spec_.addrt.bda) {
        evt_data.auth_req = BTM_AUTH_AP_YES;
      } else {
        err_code = HCI_ERR_HOST_BUSY_PAIRING;
      }
      break;

    /* any other state is unexpected */
    default:
      err_code = HCI_ERR_HOST_BUSY_PAIRING;
      log::error("Unexpected Pairing state received {}", BtmSecurity::Get().pairing_state_);
      break;
  }

  if (BtmSecurity::Get().pairing_disabled_) {
    /* pairing is not allowed */
    log::verbose("Pairing is not allowed -> fail pairing.");
    err_code = HCI_ERR_PAIRING_NOT_ALLOWED;
  } else if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
    bool local_supports_sc = bluetooth::shim::GetController()->SupportsSecureConnections();
    /* device in Secure Connections Only mode */
    if (!(local_supports_sc) || !(p_device->SupportsSecureConnections())) {
      log::debug(
              "SC only service, local_support_for_sc:{}, remote_support_for_sc:{} "
              "-> fail pairing",
              local_supports_sc, p_device->SupportsSecureConnections());
      err_code = HCI_ERR_PAIRING_NOT_ALLOWED;
    }
  }

  if (err_code != 0) {
    btsnd_hcic_io_cap_req_neg_reply(evt_data.bd_addr, err_code);
    return;
  }

  evt_data.is_orig = is_orig;

  if (is_orig) {
    /* local device initiated the pairing non-bonding -> use
     * required_security_flags_for_pairing */
    if (!(BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
        (p_device->sec_rec.required_security_flags_for_pairing & BTM_SEC_OUT_AUTHENTICATE)) {
      if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
        /* SC only mode device requires MITM protection */
        evt_data.auth_req = BTM_AUTH_SP_YES;
      } else {
        evt_data.auth_req =
                (p_device->sec_rec.required_security_flags_for_pairing & BTM_SEC_OUT_MITM)
                        ? BTM_AUTH_SP_YES
                        : BTM_AUTH_SP_NO;
      }
    }
  }

  /* Notify L2CAP to increase timeout */
  l2c_pin_code_request(evt_data.bd_addr);

  BtmSecurity::Get().link_spec_.addrt.bda = evt_data.bd_addr;
  BtmSecurity::Get().link_spec_.transport = BT_TRANSPORT_BR_EDR;

  if (evt_data.bd_addr == BtmSecurity::Get().connecting_bda_) {
    p_device->dev_class = BtmSecurity::Get().connecting_dc_;
  }

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_LOCAL_IOCAPS);

  if (p_device->sm4 & BTM_SM4_UPGRADE) {
    p_device->sm4 &= ~BTM_SM4_UPGRADE;

    /* link key upgrade: always use SPGB_YES - assuming we want to save the link key */
    evt_data.auth_req = BTM_AUTH_SPGB_YES;
  } else {
    /* the callback function implementation may change the IO capability... */
    (BtmSecurity::Get().app_->sp_callback)(BTM_SP_IO_REQ_EVT, (tBTM_SP_EVT_DATA*)&evt_data);
  }

  if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) {
    evt_data.auth_req = (BTM_AUTH_DD_BOND | (evt_data.auth_req & BTM_AUTH_YN_BIT));
  }

  if (BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) {
    /* At this moment we know that both sides are SC capable, device in */
    /* SC only mode requires MITM for any service so let's set MITM bit */
    evt_data.auth_req |= BTM_AUTH_YN_BIT;
    log::verbose("for device in \"SC only\" mode set auth_req to 0x{:02x}", evt_data.auth_req);
  }

  /* if the user does not indicate "reply later" by setting the oob_data to
   * unknown */
  /* send the response right now. Save the current IO capability in the
   * control block */
  BtmSecurity::Get().devcb_.loc_auth_req = evt_data.auth_req;
  const BtIoCap local_io_caps = btm_sec_get_local_iocaps();

  log::verbose("State: {}  IO_CAP:{} oob_data:{} auth_req:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_), local_io_caps,
               evt_data.oob_data, evt_data.auth_req);

  btsnd_hcic_io_cap_req_reply(evt_data.bd_addr, local_io_caps, evt_data.oob_data,
                              evt_data.auth_req);
}

/*******************************************************************************
 *
 * Function         btm_io_capabilities_rsp
 *
 * Description      This function is called when the IO capability of the
 *                  specified device is received
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_io_capabilities_rsp(const tBTM_SP_IO_RSP evt_data) {
  /* Allocate a new device record or reuse the oldest one */
  BtmDevice* p_device = btm_find_or_alloc_dev(evt_data.bd_addr);

  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  /* If device is bonded, and encrypted it's upgrading security and it's ok.
   * If it's bonded and not encrypted, it's remote missing keys scenario
   * Do not process this RSP and return, REQ will handle generation of
   * key missing event and disconnect.
   *
   * Note: Process this RSP if autonomous repair is supported, as this will be used to continue the
   * re-pair attempt. The changes in this function will be reset on pairing success or failure.
   */
  if (p_device->sec_rec.is_bonded(BT_TRANSPORT_BR_EDR) &&
      !p_device->sec_rec.is_device_encrypted() &&
      !(com::android::bluetooth::flags::process_iocap_rsp_while_repairing() &&
        is_autonomous_repairing_supported())) {
    log::warn("Incoming bond request, but {} is already bonded (notifying user)", evt_data.bd_addr);
    return;
  }

  /* If no security is in progress, this indicates incoming security */
  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_IDLE) {
    BtmSecurity::Get().link_spec_.addrt.bda = evt_data.bd_addr;
    BtmSecurity::Get().link_spec_.transport = BT_TRANSPORT_BR_EDR;

    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_INCOMING_SSP);
  }

  /* Notify L2CAP to increase timeout */
  l2c_pin_code_request(evt_data.bd_addr);

  /* We must have a device record here.
   * Use the connecting device's CoD for the connection */
  if (evt_data.bd_addr == BtmSecurity::Get().connecting_bda_) {
    p_device->dev_class = BtmSecurity::Get().connecting_dc_;
  }

  /* peer sets dedicated bonding bit and we did not initiate dedicated bonding
   */
  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_INCOMING_SSP /* peer initiated bonding */
      && (evt_data.auth_req & BTM_AUTH_DD_BOND)) /* and dedicated bonding bit is set */
  {
    BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_PEER_STARTED_DD;
  }

  /* save the IO capability in the device record */
  p_device->sec_rec.rmt_io_caps = evt_data.io_cap;
  p_device->sec_rec.rmt_auth_req = evt_data.auth_req;

  (BtmSecurity::Get().app_->sp_callback)(BTM_SP_IO_RSP_EVT, (tBTM_SP_EVT_DATA*)&evt_data);
}

/*******************************************************************************
 *
 * Function         btm_proc_sp_req_evt
 *
 * Description      This function is called to process/report
 *                  HCI_USER_CONFIRMATION_REQUEST_EVT
 *                  or HCI_USER_PASSKEY_REQUEST_EVT
 *                  or HCI_USER_PASSKEY_NOTIFY_EVT
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_proc_sp_req_evt(tBTM_SP_EVT event, const RawAddress& bd_addr, const uint32_t value) {
  tBTM_STATUS status = tBTM_STATUS::BTM_ERR_PROCESSING;
  const BtIoCap local_io_caps = btm_sec_get_local_iocaps();

  log::debug("BDA:{}, event:{}, state:{}", bd_addr, sp_evt_to_text(event),
             btm_pair_state_descr(BtmSecurity::Get().pairing_state_));

  const BtmDevice* p_device = btm_find_dev(bd_addr);
  if (p_device != NULL && BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      BtmSecurity::Get().link_spec_.addrt.bda == bd_addr) {
    tBTM_SP_EVT_DATA evt_data = {};
    evt_data.cfm_req.bd_addr = p_device->bd_addr;
    evt_data.cfm_req.dev_class = p_device->dev_class;
    log::info("CoD: evt_data.cfm_req.dev_class = {}", dev_class_text(evt_data.cfm_req.dev_class));
    bd_name_copy(evt_data.cfm_req.bd_name, p_device->sec_bd_name);

    switch (event) {
      case BTM_SP_CFM_REQ_EVT:
        /* Numeric confirmation. Need user to conf the passkey */
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_NUMERIC_CONFIRM);

        /* The device record must be allocated in the "IO cap exchange" step */
        evt_data.cfm_req.num_val = value;
        log::verbose("num_val:{}", evt_data.cfm_req.num_val);

        evt_data.cfm_req.just_works = true;

        /* process user confirm req in association with the auth_req param */
        if (local_io_caps == BtIoCap::DISPLAY_YES_NO) {
          if (p_device->sec_rec.rmt_io_caps == BtIoCap::IO_CAP_UNKNOWN) {
            log::error(
                    "did not receive IO cap response prior to BTM_SP_CFM_REQ_EVT, "
                    "failing pairing request");
            status = tBTM_STATUS::BTM_WRONG_MODE;
            btm_confirm_req_reply(status, bd_addr);
            return;
          }

          if ((p_device->sec_rec.rmt_io_caps == BtIoCap::DISPLAY_YES_NO ||
               p_device->sec_rec.rmt_io_caps == BtIoCap::DISPLAY_ONLY) &&
              (local_io_caps == BtIoCap::DISPLAY_YES_NO) &&
              ((p_device->sec_rec.rmt_auth_req & BTM_AUTH_SP_YES) ||
               (BtmSecurity::Get().devcb_.loc_auth_req & BTM_AUTH_SP_YES))) {
            /* Use Numeric Comparison if
             * 1. Local IO capability is DisplayYesNo,
             * 2. Remote IO capability is DisplayOnly or DisplayYesNo, and
             * 3. Either of the devices have requested authenticated link key */
            evt_data.cfm_req.just_works = false;
          }
        }

        log::verbose("just_works:{}, io loc:{}, rmt:{}, auth loc:{}, rmt:{}",
                     evt_data.cfm_req.just_works, local_io_caps, p_device->sec_rec.rmt_io_caps,
                     BtmSecurity::Get().devcb_.loc_auth_req, p_device->sec_rec.rmt_auth_req);

        evt_data.cfm_req.loc_auth_req = BtmSecurity::Get().devcb_.loc_auth_req;
        evt_data.cfm_req.rmt_auth_req = p_device->sec_rec.rmt_auth_req;
        evt_data.cfm_req.loc_io_caps = local_io_caps;
        evt_data.cfm_req.rmt_io_caps = p_device->sec_rec.rmt_io_caps;
        evt_data.cfm_req.pairing_algorithm = p_device->sec_rec.pairing_algorithm;
        break;

      case BTM_SP_KEY_NOTIF_EVT:
        /* Passkey notification (other side is a keyboard) */
        evt_data.key_notif.passkey = value;
        evt_data.key_notif.pairing_algorithm = p_device->sec_rec.pairing_algorithm;
        log::verbose("passkey:{}", evt_data.key_notif.passkey);

        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
        break;

      case BTM_SP_KEY_REQ_EVT:
        if (local_io_caps != BtIoCap::NO_INPUT_NO_OUTPUT) {
          /* HCI_USER_PASSKEY_REQUEST_EVT */
          BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_KEY_ENTRY);
        }
        break;
      default:
        log::warn("unhandled event:{}", sp_evt_to_text(event));
        break;
    }

    if ((BtmSecurity::Get().app_->sp_callback)(event, &evt_data) !=
        tBTM_STATUS::BTM_NOT_AUTHORIZED) {
      return;
    }

    if (event == BTM_SP_CFM_REQ_EVT) {
      log::verbose("calling btm_confirm_req_reply with status: {}", status);
      btm_confirm_req_reply(status, bd_addr);
    } else if (local_io_caps != BtIoCap::NO_INPUT_NO_OUTPUT && event == BTM_SP_KEY_REQ_EVT) {
      btm_passkey_req_reply(status, bd_addr, 0);
    }
    return;
  }

  /* Something bad. we can only fail this connection */
  acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);

  if (BTM_SP_CFM_REQ_EVT == event) {
    btsnd_hcic_user_conf_reply(bd_addr, false);
  } else if (BTM_SP_KEY_NOTIF_EVT == event) {
    /* do nothing -> it very unlikely to happen.
    This event is most likely to be received by a HID host when it first
    connects to a HID device.
    Usually the Host initiated the connection in this case.
    On Mobile platforms, if there's a security process happening,
    the host probably can not initiate another connection.
    BTW (PC) is another story.  */
    p_device = btm_find_dev(bd_addr);
    if (p_device != NULL) {
      btm_sec_disconnect(p_device->hci_handle, HCI_ERR_AUTH_FAILURE,
                         "stack::btm::btm_sec::btm_proc_sp_req_evt Security failure");
    }
  } else if (local_io_caps != BtIoCap::NO_INPUT_NO_OUTPUT) {
    btsnd_hcic_user_passkey_neg_reply(bd_addr);
  }
}

/*******************************************************************************
 *
 * Function         btm_simple_pair_complete
 *
 * Description      This function is called when simple pairing process is
 *                  complete
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_simple_pair_complete(const RawAddress& bd_addr, uint8_t status) {
  BtmDevice* p_device;
  bool disc = false;

  p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("unknown BDA: {}", bd_addr);
    return;
  }

  log::verbose("btm_simple_pair_complete()  Pair State: {}  Status:{}  classic_link:{}",
               btm_pair_state_descr(BtmSecurity::Get().pairing_state_), status,
               p_device->sec_rec.classic_link);

  if (status == HCI_SUCCESS) {
    p_device->sec_rec.sec_flags |= BTM_SEC_AUTHENTICATED;
  } else if (status == HCI_ERR_PAIRING_NOT_ALLOWED) {
    /* The test spec wants the peer device to get this failure code. */
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_DISCONNECT);

    /* Change the timer to 1 second */
    alarm_set_on_mloop(BtmSecurity::Get().pairing_timer_, BT_1SEC_TIMEOUT_MS,
                       btm_sec_pairing_timeout, NULL);
  } else if (BtmSecurity::Get().link_spec_.addrt.bda == bd_addr) {
    /* stop the timer */
    alarm_cancel(BtmSecurity::Get().pairing_timer_);

    if (p_device->sec_rec.classic_link != tSECURITY_STATE::AUTHENTICATING) {
      /* the initiating side: will receive auth complete event. disconnect ACL
       * at that time */
      disc = true;
    }
  } else {
    disc = true;
  }

  if (disc) {
    /* simple pairing failed */
    /* Avoid sending disconnect on HCI_ERR_PEER_USER */
    if ((status != HCI_ERR_PEER_USER) && (status != HCI_ERR_CONN_CAUSE_LOCAL_HOST)) {
      btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, p_device->hci_handle,
                                  "stack::btm::btm_sec::btm_simple_pair_complete Auth fail");
    }
  }
}

/*******************************************************************************
 *
 * Function         btm_rem_oob_req
 *
 * Description      This function is called to process/report
 *                  HCI_REMOTE_OOB_DATA_REQUEST_EVT
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_rem_oob_req(const RawAddress& bd_addr) {
  log::verbose("BDA: {}", bd_addr);
  const BtmDevice* p_device = btm_find_dev(bd_addr);

  if (p_device != nullptr) {
    tBTM_SP_RMT_OOB evt_data = {};

    evt_data.bd_addr = bd_addr;
    evt_data.bd_addr = p_device->bd_addr;
    evt_data.dev_class = p_device->dev_class;
    bd_name_copy(evt_data.bd_name, p_device->sec_bd_name);

    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_LOCAL_OOB_RSP);
    if ((BtmSecurity::Get().app_->sp_callback)(BTM_SP_RMT_OOB_EVT, (tBTM_SP_EVT_DATA*)&evt_data) ==
        tBTM_STATUS::BTM_NOT_AUTHORIZED) {
      Octet16 c;
      Octet16 r;
      btm_remote_oob_data_reply(static_cast<tBTM_STATUS>(true), bd_addr, c, r);
    }
    return;
  }

  /* something bad. we can only fail this connection */
  acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
  btsnd_hcic_rem_oob_neg_reply(bd_addr);
}

/*******************************************************************************
 *
 * Function         btm_read_local_oob_complete
 *
 * Description      This function is called when read local oob data is
 *                  completed by the LM
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_read_local_oob_complete(const tBTM_SP_LOC_OOB evt_data) {
  log::verbose("btm_read_local_oob_complete:{}", evt_data.status);
  tBTM_SP_EVT_DATA btm_sp_evt_data;
  btm_sp_evt_data.loc_oob = evt_data;
  (BtmSecurity::Get().app_->sp_callback)(BTM_SP_LOC_OOB_EVT, &btm_sp_evt_data);
}

/*******************************************************************************
 *
 * Function         btm_sec_auth_collision
 *
 * Description      This function is called when authentication or encryption
 *                  needs to be retried at a later time.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_auth_collision(uint16_t handle) {
  auto& security = BtmSecurity::Get();
  uint64_t now = bluetooth::common::time_get_os_boottime_ms();

  if (security.collision_start_time_ == 0) {
    security.collision_start_time_ = now;
  } else if ((now - security.collision_start_time_) >= BTM_SEC_MAX_COLLISION_DELAY) {
    return;
  }

  BtmDevice* p_device = nullptr;
  if (handle == HCI_INVALID_HANDLE) {
    p_device = btm_sec_find_dev_by_sec_state(tSECURITY_STATE::AUTHENTICATING);
    if (p_device == nullptr) {
      p_device = btm_sec_find_dev_by_sec_state(tSECURITY_STATE::ENCRYPTING);
    }
  } else {
    p_device = btm_get_dev_by_handle(handle);
  }

  if (p_device == nullptr) {
    log::warn("No device found for handle {}", handle);
    return;
  }

  log::verbose("btm_sec_auth_collision: state {} (retrying in a moment...)",
               p_device->sec_rec.classic_link);

  if (p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING ||
      p_device->sec_rec.classic_link == tSECURITY_STATE::ENCRYPTING) {
    p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
  }
  security.p_collided_dev_ = p_device;

  // Restart procedure after a fixed timeout as central initiated procedure should succeed
  alarm_set_on_mloop(security.sec_collision_timer_, BT_1SEC_TIMEOUT_MS, btm_sec_collision_timeout,
                     nullptr);
}

/******************************************************************************
 *
 * Function         btm_sec_auth_retry
 *
 * Description      This function is called when authentication or encryption
 *                  needs to be retried at a later time.
 *
 * Returns          TRUE if a security retry required
 *
 *****************************************************************************/
static bool btm_sec_auth_retry(uint16_t handle, uint8_t status) {
  BtmDevice* p_device = btm_get_dev_by_handle(handle);
  if (!p_device) {
    return false;
  }

  /* keep the old sm4 flag and clear the retry bit in control block */
  uint8_t old_sm4 = p_device->sm4;
  p_device->sm4 &= ~BTM_SM4_RETRY;

  if ((BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_IDLE) &&
      ((old_sm4 & BTM_SM4_RETRY) == 0) && (HCI_ERR_KEY_MISSING == status) &&
      BTM_SEC_IS_SM4(p_device->sm4)) {
    /* This retry for missing key is for Lisbon or later only.
       Legacy device do not need this. the controller will drive the retry
       automatically
       set the retry bit */
    BtmSecurity::Get().collision_start_time_ = 0;
    btm_restore_mode();
    p_device->sm4 |= BTM_SM4_RETRY;
    p_device->sec_rec.sec_flags &= ~BTM_SEC_LINK_KEY_KNOWN;
    log::verbose("Retry for missing key sm4:x{:x} sec_flags:0x{:x}", p_device->sm4,
                 p_device->sec_rec.sec_flags);

    /* With BRCM controller, we do not need to delete the stored link key in
       controller.
       If the stack may sit on top of other controller, we may need this
       btm_sec_hci_delete_stored_link_key(p_device->bd_addr); */
    p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
    btm_sec_execute_procedure(p_device);
    return true;
  }

  return false;
}

void btm_sec_auth_complete(uint16_t handle, tHCI_STATUS status) {
  tBTM_PAIRING_STATE old_state = BtmSecurity::Get().pairing_state_;
  BtmDevice* p_device = btm_get_dev_by_handle(handle);
  bool are_bonding = false;
  bool was_authenticating = false;

  if (p_device) {
    bluetooth::metrics::LogAuthenticationComplete(p_device->bd_addr, status);
    log::verbose(
            "Security Manager: in state: {}, handle: {}, status: {}, "
            "dev->sec_rec.classic_link:{}, bda: {}, RName: {}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_), handle, status,
            p_device->sec_rec.classic_link, p_device->bd_addr,
            reinterpret_cast<char const*>(p_device->sec_bd_name));

    if (status == HCI_ERR_KEY_MISSING) {
      if (is_autonomous_repairing_supported()) {
        // Reset the security state to IDLE to allow for a new pairing attempt.
        p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
      }

      btm_sec_report_bond_loss(p_device, BT_TRANSPORT_BR_EDR, BTM_KEY_MISSING_BREDR_AUTH_FAILURE);
      return;
    }

  } else {
    log::verbose("Security Manager: in state: {}, handle: {}, status: {}",
                 btm_pair_state_descr(BtmSecurity::Get().pairing_state_), handle, status);
  }

  if (status == HCI_ERR_LMP_ERR_TRANS_COLLISION || status == HCI_ERR_DIFF_TRANSACTION_COLLISION) {
    // Only peripheral receives the collision error, central initiated procedure should go through
    btm_sec_auth_collision(handle);
    return;
  } else if (btm_sec_auth_retry(handle, status)) {
    return;
  }

  if (p_device && BtmSecurity::Get().p_collided_dev_ &&
      p_device->bd_addr == BtmSecurity::Get().p_collided_dev_->bd_addr) {
    BtmSecurity::Get().collision_start_time_ = 0;
    BtmSecurity::Get().p_collided_dev_ = NULL;
    if (alarm_is_scheduled(BtmSecurity::Get().sec_collision_timer_)) {
      alarm_cancel(BtmSecurity::Get().sec_collision_timer_);
    }
  }

  btm_restore_mode();

  /* Check if connection was made just to do bonding.  If we authenticate
     the connection that is up, this is the last event received.
  */
  if (p_device && (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) &&
      !(BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE)) {
    p_device->sec_rec.security_required &= ~BTM_SEC_OUT_AUTHENTICATE;

    l2cu_start_post_bond_timer(p_device->hci_handle);
  }

  if (!p_device) {
    return;
  }

  if (p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING) {
    p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
    was_authenticating = true;
    /* There can be a race condition, when we are starting authentication
     * and the peer device is doing encryption.
     * If first we receive encryption change up, then initiated
     * authentication can not be performed.
     * According to the spec we can not do authentication on the
     * encrypted link, so device is correct.
     */
    if ((status == HCI_ERR_COMMAND_DISALLOWED) &&
        ((p_device->sec_rec.sec_flags & (BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED)) ==
         (BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED))) {
      status = HCI_SUCCESS;
    }
    if (status == HCI_SUCCESS) {
      p_device->sec_rec.sec_flags |= BTM_SEC_AUTHENTICATED;
    }
  }

  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      p_device->bd_addr == BtmSecurity::Get().link_spec_.addrt.bda) {
    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) {
      are_bonding = true;
    }
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
  }

  if (was_authenticating == false) {
    if (status != HCI_SUCCESS && old_state != BTM_PAIR_STATE_IDLE) {
      NotifyBondingChange(*p_device, status);
    }
    return;
  }

  /* Currently we do not notify user if it is a keyboard which connects. */
  /* User probably disabled the keyboard while it was asleap. Let them try to report the
   * authentication status */
  if (old_state != BTM_PAIR_STATE_IDLE || status != HCI_SUCCESS) {
    (BtmSecurity::Get().app_->auth_complete_callback)(p_device->bd_addr, p_device->sec_bd_name,
                                                      status);
  }

  /* If this is a bonding procedure can disconnect the link now */
  if (are_bonding) {
    tHCI_ROLE role = HCI_ROLE_UNKNOWN;
    if (get_btm_client_interface().link_policy.BTM_GetRole(p_device->bd_addr, BT_TRANSPORT_BR_EDR,
                                                           &role) != tBTM_STATUS::BTM_SUCCESS) {
      log::warn("Unable to get link role peer:{}", p_device->bd_addr);
    }
    p_device->role_switch_pending = BtmDevice::RoleSwitchPending::kNone;
    p_device->sec_rec.security_required &= ~BTM_SEC_OUT_AUTHENTICATE;

    if (status != HCI_SUCCESS) {
      if (status != HCI_ERR_PEER_USER && status != HCI_ERR_CONN_CAUSE_LOCAL_HOST) {
        btm_sec_send_hci_disconnect(
                p_device, HCI_ERR_PEER_USER, p_device->hci_handle,
                "stack::btm::btm_sec::btm_sec_auth_retry Auth fail while bonding");
      }
    } else {
      BTM_LogHistory(kBtmLogTag, p_device->bd_addr, "Bonding completed",
                     hci_error_code_text(status));
      p_device->role_switch_pending =
              (p_device->IsLocallyInitiated() && role == HCI_ROLE_PERIPHERAL)
                      ? BtmDevice::RoleSwitchPending::kAfterEnc
                      : BtmDevice::RoleSwitchPending::kNone;
      btm_set_encryption(p_device->bd_addr, BT_TRANSPORT_BR_EDR, NULL, NULL, BTM_BLE_SEC_NONE);
      l2cu_start_post_bond_timer(p_device->hci_handle);
    }

    return;
  }

  /* If authentication failed, notify the waiting layer */
  if (status != HCI_SUCCESS) {
    btm_sec_dev_rec_cback_event(p_device, tBTM_STATUS::BTM_ERR_PROCESSING, false);

    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_DISC_WHEN_DONE) {
      btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, p_device->hci_handle,
                                  "stack::btm::btm_sec::btm_sec_auth_retry Auth failed");
    }
    return;
  }

  if (p_device->sec_rec.pin_code_length >= 16 ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB_P_256) {
    // If we have MITM protection we have a higher level of security than
    // provided by 16 digits PIN
    p_device->sec_rec.sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
  }

  /* Authentication succeeded, execute the next security procedure, if any */
  tBTM_STATUS btm_status = btm_sec_execute_procedure(p_device);

  /* If there is no next procedure, or procedure failed to start, notify the
   * caller */
  if (btm_status != tBTM_STATUS::BTM_CMD_STARTED) {
    btm_sec_dev_rec_cback_event(p_device, btm_status, false);
  }
}

/******************************************************************************
 *
 * Function         btm_sec_perform_ctkd
 *
 * Description      This function is called on BR/EDR encryption to perform
 *                  CTKD if conditions are met.
 *
 * Returns          TRUE if CTKD is initiated successfully. FALSE otherwise.
 *
 *****************************************************************************/
static bool btm_sec_perform_ctkd(BtmDevice* p_device) {
  /* Must be bonded over BR/EDR */
  if (!p_device->sec_rec.is_bonded(BT_TRANSPORT_BR_EDR)) {
    log::verbose("Not bonded over BR/EDR");
    return false;
  }

  switch (p_device->sec_rec.bredr_sc_enc_reason) {
    case BtmSecurityRecord::BrEdrScEncReason::PAIRED:
      /* Must not be bonded over LE with equal or higher security */
      if (p_device->sec_rec.is_bonded(BT_TRANSPORT_LE) &&
          ((p_device->sec_rec.sec_flags & BTM_SEC_LE_LINK_KEY_AUTHED) ||
           !(p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_AUTHED))) {
        log::verbose("LE bonded with equal or higher security");
        return false;
      }
      break;

    case BtmSecurityRecord::BrEdrScEncReason::REPAIRED:
      /* Must not be bonded over LE with higher security */
      if (p_device->sec_rec.is_bonded(BT_TRANSPORT_LE) &&
          ((p_device->sec_rec.sec_flags & BTM_SEC_LE_LINK_KEY_AUTHED) &&
           !(p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_AUTHED))) {
        log::verbose("LE bonded with higher security");
        return false;
      }
      break;

    case BtmSecurityRecord::BrEdrScEncReason::OTHER:
    default:
      log::verbose("BR/EDR pairing did not complete recently");
      return false;
  }

  /* Must support SMP over BR/EDR */
  if (!btm_sec_use_smp_br_chnl(p_device)) {
    log::verbose("SMP over BR/EDR is not supported");
    return false;
  }

  /* Must be in central role */
  tHCI_ROLE role = HCI_ROLE_UNKNOWN;
  if (get_btm_client_interface().link_policy.BTM_GetRole(p_device->bd_addr, BT_TRANSPORT_BR_EDR,
                                                         &role) != tBTM_STATUS::BTM_SUCCESS) {
    log::warn("Unable to get link policy role peer:{}", p_device->bd_addr);
  }
  if (role != HCI_ROLE_CENTRAL) {
    log::verbose("Not in central role");
    return false;
  }

  /* CTKD must not be disabled for this device */
  if (interop_match_addr(INTEROP_DISABLE_OUTGOING_BR_SMP, p_device->bd_addr)) {
    log::warn("BR SMP is disabled due to interop issues {}", p_device->bd_addr);
    return false;
  }

  tSMP_STATUS status = SMP_BR_PairWith(p_device->bd_addr);
  if (status != SMP_STARTED) {
    log::warn("Failed to start SMP over BR/EDR {}, reason: {}", p_device->bd_addr,
              smp_status_text(status));
    return false;
  }
  log::info("Started SMP over BR/EDR {}", p_device->bd_addr);
  return true;
}

/*******************************************************************************
 *
 * Function         btm_sec_encrypt_change
 *
 * Description      This function is when encryption of the connection is
 *                  completed by the LM
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_encrypt_change(uint16_t handle, tHCI_STATUS status, uint8_t encr_enable,
                            uint8_t key_size, bool from_key_refresh = false) {
  if (status == HCI_ERR_LMP_ERR_TRANS_COLLISION || status == HCI_ERR_DIFF_TRANSACTION_COLLISION) {
    // Only peripheral receives the collision error, central initiated procedure should go through
    log::error("Encryption collision failed status:{}", hci_error_code_text(status));
    btm_sec_auth_collision(handle);
    return;
  }

  BtmSecurity::Get().collision_start_time_ = 0;

  BtmDevice* p_device = btm_get_dev_by_handle(handle);
  if (p_device == nullptr) {
    log::warn(
            "Received encryption change for unknown device handle:0x{:04x} "
            "status:{} enable:0x{:x}",
            handle, hci_status_code_text(status), encr_enable);
    return;
  }

  const tBT_TRANSPORT transport =
          BTM_IsBleConnection(handle) ? BT_TRANSPORT_LE : BT_TRANSPORT_BR_EDR;

  if (transport == BT_TRANSPORT_LE) {
    key_size = p_device->sec_rec.ble_keys.key_size;
    if (key_size == 0 && status == HCI_SUCCESS && encr_enable == HCI_ENCRYPT_MODE_ON) {
      /* Only case when key size is 0 during successfull encryption is pairing - for this case look
       * up the key size */
      key_size = SMP_GetPendingPairingKeySize();
    }
  }

  log::debug(
          "Security Manager encryption change request hci_status:{} request:{} "
          "state: le_link:{} classic_link:{} sec_flags:0x{:x} key_size:{}",
          hci_status_code_text(status), (encr_enable) ? "encrypt" : "unencrypt",
          p_device->sec_rec.le_link, p_device->sec_rec.classic_link, p_device->sec_rec.sec_flags,
          key_size);

  if (status == HCI_SUCCESS) {
    if (encr_enable) {
      if (p_device->hci_handle == handle) {  // classic
        p_device->sec_rec.sec_flags |= (BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED);
        if (p_device->sec_rec.pin_code_length >= 16 ||
            p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB ||
            p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB_P_256) {
          p_device->sec_rec.sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
        }
      } else if (p_device->ble_hci_handle == handle) {  // BLE
        p_device->sec_rec.set_le_device_encrypted();
        if (p_device->sec_rec.is_le_link_key_authenticated()) {
          p_device->sec_rec.set_le_device_authenticated();
        }
      } else {
        log::error(
                "Received encryption change for unknown device handle:0x{:04x} "
                "status:{} enable:0x{:x}",
                handle, hci_status_code_text(status), encr_enable);
      }
    } else {
      log::info("Encryption was not enabled locally resetting encryption state");
      /* It is possible that we decrypted the link to perform role switch */
      /* mark link not to be encrypted, so that when we execute security next
       * time it will kick in again */
      if (p_device->hci_handle == handle) {  // classic
        p_device->sec_rec.sec_flags &= ~BTM_SEC_ENCRYPTED;
      } else if (p_device->ble_hci_handle == handle) {  // BLE
        p_device->sec_rec.sec_flags &= ~BTM_SEC_LE_ENCRYPTED;
      } else {
        log::error(
                "Received encryption change for unknown device handle:0x{:04x} "
                "status:{} enable:0x{:x}",
                handle, hci_status_code_text(status), encr_enable);
      }
    }
  }

  const bool is_encrypted = (transport == BT_TRANSPORT_LE)
                                    ? p_device->sec_rec.is_le_device_encrypted()
                                    : p_device->sec_rec.is_device_encrypted();
  BTM_LogHistory(
          kBtmLogTag,
          (transport == BT_TRANSPORT_LE) ? p_device->ble.pseudo_addr : p_device->bd_addr,
          (status == HCI_SUCCESS) ? "Encryption success" : "Encryption failed",
          std::format("status:{} transport:{} is_encrypted:{:c}", hci_status_code_text(status),
                      bt_transport_text(transport), is_encrypted ? 'T' : 'F'));

  log::debug("after update p_device->sec_rec.sec_flags=0x{:x}", p_device->sec_rec.sec_flags);

  btm_sec_check_pending_enc_req(p_device, transport, encr_enable != HCI_ENCRYPT_MODE_DISABLED);

  if (!from_key_refresh) {
    // Determine encryption_algo as per BT spec section `Encryption Change event`.
    EncryptionAlgorithm encryption_algo = EncryptionAlgorithm::NONE;
    if (encr_enable == HCI_ENCRYPT_MODE_ON) {
      encryption_algo =
              (transport == BT_TRANSPORT_LE) ? EncryptionAlgorithm::AES : EncryptionAlgorithm::E0;

      // Claiming HCI_ENCRYPT_MODE_ON while using BR/EDR transport implies using E0 encryption.
      // If the stored properties indicate that we should be using AES-CCM (i.e. that we were using
      // Secure Connections mode previously), then this is a downgrade.
      if (transport == BT_TRANSPORT_BR_EDR) {
        if (btm_sec_is_enc_algo_downgrade(handle, 0, 0)) {
          acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
          btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, handle,
                                      "attempted to downgrade from Secure Connections mode");
          return;
        }
      }
    } else if (encr_enable == HCI_ENCRYPT_MODE_ON_BR_EDR_AES_CCM) {
      encryption_algo = EncryptionAlgorithm::AES;  // this is for BR/EDR
      if (transport == BT_TRANSPORT_LE) {
        log::warn(
                "Incorrect parameter `Encryption_Enabled` in encryption change event for TRANSPORT "
                "LE.");
      }
    }

    bta_dm_on_encryption_change(bt_encryption_change_evt{
            p_device->bd_addr,
            status,
            (bool)encr_enable,
            key_size,
            transport,
            encryption_algo,
    });
  }

  if (transport == BT_TRANSPORT_LE) {
    if (status == HCI_ERR_KEY_MISSING || status == HCI_ERR_AUTH_FAILURE ||
        status == HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE) {
      log::error("{} encrypt failure status 0x{:x}", p_device->bd_addr, status);
    }
    p_device->sec_rec.sec_status = status;
    btm_ble_link_encrypted(p_device->ble.pseudo_addr, encr_enable);

    if (status == HCI_ERR_KEY_MISSING) {
      btm_sec_report_bond_loss(p_device, BT_TRANSPORT_LE, BTM_KEY_MISSING_LE_ENCRYPT_FAILURE);
      return;
    }

    return;
  } else {
    /* BR/EDR connection, update the encryption key size to be 16 as always */
    p_device->sec_rec.enc_key_size = 16;
  }

  if (status == HCI_SUCCESS && encr_enable && p_device->hci_handle == handle) {
    /* BR/EDR link encrypted successfully */
    btm_sec_perform_ctkd(p_device);

    tHCI_ROLE role = HCI_ROLE_UNKNOWN;
    if (get_btm_client_interface().link_policy.BTM_GetRole(p_device->bd_addr, BT_TRANSPORT_BR_EDR,
                                                           &role) != tBTM_STATUS::BTM_SUCCESS) {
      log::warn("Unable to get link policy role peer:{}", p_device->bd_addr);
    }

    if (p_device->role_switch_pending != BtmDevice::RoleSwitchPending::kNone &&
        role == HCI_ROLE_PERIPHERAL) {
      if (btm_sec_use_smp_br_chnl(p_device)) {
        /* Role switch request might prevent remote central device from initiating CTKD */
        p_device->role_switch_pending = BtmDevice::RoleSwitchPending::kAfterCtkd;
      } else {
        if (get_btm_client_interface().link_policy.BTM_SwitchRoleToCentral(
                    p_device->RemoteAddress()) == tBTM_STATUS::BTM_CMD_STARTED) {
          log::info("Trying to switch role to central peer: {}", p_device->RemoteAddress());
        } else {
          log::warn("Unable to switch role to central peer:{}", p_device->RemoteAddress());
        }
        p_device->role_switch_pending = BtmDevice::RoleSwitchPending::kNone;
      }
    }
  }

  if (status == HCI_SUCCESS && !p_device->sec_rec.is_security_state_bredr_encrypting() &&
      alarm_is_scheduled(BtmSecurity::Get().sec_collision_timer_) &&
      BtmSecurity::Get().p_collided_dev_ &&
      BtmSecurity::Get().p_collided_dev_->bd_addr == p_device->bd_addr) {
    log::debug("Clear collision info after incoming encryption {}", p_device->bd_addr);
    BtmSecurity::Get().p_collided_dev_ = NULL;
    alarm_cancel(BtmSecurity::Get().sec_collision_timer_);
  } else if (status == HCI_SUCCESS &&
             p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING) {
    log::debug("Incoming encryption occur during auth, so continue next security procedure");
  } else if (!p_device->sec_rec.is_security_state_bredr_encrypting()) {
    /* Link encrypted by peer, so no need to do anything */
    if (tSECURITY_STATE::DELAY_FOR_ENC == p_device->sec_rec.classic_link) {
      p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
      log::verbose("clearing callback. p_device={}, p_callback={}", std::format_ptr(p_device),
                   std::format_ptr(p_device->sec_rec.p_callback));
      p_device->sec_rec.p_callback = NULL;
      l2cu_resubmit_pending_sec_req(&p_device->bd_addr);
      return;
    } else if (!concurrentPeerAuthIsEnabled() &&
               p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING) {
      p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
      return;
    }
    if (!handleUnexpectedEncryptionChange()) {
      return;
    }
  }

  p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
  /* If encryption setup failed, notify the waiting layer */
  if (status != HCI_SUCCESS) {
    btm_sec_dev_rec_cback_event(p_device, tBTM_STATUS::BTM_ERR_PROCESSING, false);
    return;
  }

  /* Encryption setup succeeded, execute the next security procedure, if any */
  tBTM_STATUS btm_status = btm_sec_execute_procedure(p_device);
  /* If there is no next procedure, or procedure failed to start, notify the
   * caller */
  if (static_cast<std::underlying_type_t<tBTM_STATUS>>(status) !=
      static_cast<uint8_t>(tBTM_STATUS::BTM_CMD_STARTED)) {
    btm_sec_dev_rec_cback_event(p_device, btm_status, false);
  }
}

static void read_encryption_key_size_complete_after_encryption_change(uint8_t encr_enable,
                                                                      uint8_t status,
                                                                      uint16_t handle,
                                                                      uint8_t key_size) {
  if (status == HCI_ERR_INSUFFICIENT_SECURITY) {
    /* If remote device stop the encryption before we call "Read Encryption Key
     * Size", we might receive Insufficient Security, which means that link is
     * no longer encrypted. */
    log::info("encryption stopped on link:0x{:x}", handle);
    return;
  }

  if (status != HCI_SUCCESS) {
    log::error("disconnecting, status:0x{:x}", status);
    acl_disconnect_from_handle(handle, HCI_ERR_PEER_USER,
                               "stack::btu::btu_hcif::read_encryption_key_size_"
                               "complete_after_encryption_change Bad key size");
    return;
  }

  if (key_size < btm_sec_get_min_enc_key_size()) {
    log::error("encryption key too short, disconnecting. handle:0x{:x},key_size:{}", handle,
               key_size);

    acl_disconnect_from_handle(handle, HCI_ERR_HOST_REJECT_SECURITY,
                               "stack::btu::btu_hcif::read_encryption_key_size_complete_after_"
                               "encryption_change Key Too Short");
    return;
  }

  if (btm_sec_is_session_key_size_downgrade(handle, key_size)) {
    log::error(
            "encryption key size lower than cached value, disconnecting. "
            "handle: 0x{:x} attempted key size: {}",
            handle, key_size);
    acl_disconnect_from_handle(handle, HCI_ERR_HOST_REJECT_SECURITY,
                               "stack::btu::btu_hcif::read_encryption_key_size_complete_after_"
                               "encryption_change Key Size Downgrade");
    return;
  }

  btm_sec_update_session_key_size(handle, key_size);

  // good key size - succeed
  btm_acl_encrypt_change(handle, static_cast<tHCI_STATUS>(status), encr_enable);
  btm_sec_encrypt_change(handle, static_cast<tHCI_STATUS>(status), encr_enable, key_size);
}

/*******************************************************************************
 *
 * Function         btm_encryption_change_evt
 *
 * Description      Process event HCI_ENCRYPTION_CHANGE_EVT
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_encryption_change_evt(uint16_t handle, tHCI_STATUS status, uint8_t encr_enable,
                                   uint8_t key_size) {
  if (status == HCI_SUCCESS && encr_enable != 0 && !BTM_IsBleConnection(handle)) {
    if (key_size != 0) {
      read_encryption_key_size_complete_after_encryption_change(encr_enable, status, handle,
                                                                key_size);
      return;
    }

    if (bluetooth::shim::GetController()->IsSupported(
                bluetooth::hci::OpCode::READ_ENCRYPTION_KEY_SIZE)) {
      btsnd_hcic_read_encryption_key_size(
              handle,
              base::Bind(&read_encryption_key_size_complete_after_encryption_change, encr_enable));
      return;
    }
  }

  if (status == HCI_ERR_CONNECTION_TOUT && BTM_IsBleConnection(handle)) {
    smp_cancel_start_encryption_attempt(acl_address_from_handle(handle));
    return;
  }

  if (status != HCI_SUCCESS && encr_enable == 0) {
    if (status == HCI_ERR_LMP_ERR_TRANS_COLLISION || status == HCI_ERR_DIFF_TRANSACTION_COLLISION) {
      // Do nothing as collision is handled in btm_sec_encrypt_change()
    } else if (is_autonomous_repairing_supported() && status == HCI_ERR_KEY_MISSING) {
      // Skip the disconnection in case of bond-loss, instead proceed with re-pairing
    } else {
      log::error("Encryption failure {}, disconnecting {}", status, handle);
      btm_sec_disconnect(handle, status, "btm_sec_encryption_change_evt: Encryption Failure");
    }
  }

  btm_acl_encrypt_change(handle, static_cast<tHCI_STATUS>(status), encr_enable);
  btm_sec_encrypt_change(handle, static_cast<tHCI_STATUS>(status), encr_enable, 0);
}
/*******************************************************************************
 *
 * Function         btm_sec_connect_after_reject_timeout
 *
 * Description      This function is used to re-initiate an outgoing ACL
 *                  connection in case the ACL connection for bonding failed,
 *                  e.g., because of the collision.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_connect_after_reject_timeout(void* /* data */) {
  BtmDevice* p_device = BtmSecurity::Get().p_collided_dev_;

  log::verbose("restarting ACL connection");
  BtmSecurity::Get().p_collided_dev_ = 0;

  if (btm_sec_dd_create_conn(p_device) != tBTM_STATUS::BTM_CMD_STARTED) {
    log::warn("Security Manager: failed to start connection");

    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

    NotifyBondingChange(*p_device, HCI_ERR_MEMORY_FULL);
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_connected
 *
 * Description      This function is called when a (BR/EDR) ACL connection to
 *                  the peer device is established
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_connected(const RawAddress& bda, uint16_t handle, tHCI_STATUS status, uint8_t enc_mode,
                       bool locally_initiated, tHCI_ROLE assigned_role) {
  uint8_t bit_shift = 0;

  if (status == HCI_ERR_CONNECTION_EXISTS) {
    log::warn("Connection already exists, ignore");
    return;
  }

  BtmDevice* p_device = btm_get_dev(bda);
  if (p_device == nullptr) {
    log::debug(
            "Connected to new device state:{} handle:0x{:04x} status:{} "
            "enc_mode:{} bda:{}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_), handle,
            hci_status_code_text(status), enc_mode, bda);

    if (status == HCI_SUCCESS) {
      p_device = btm_sec_alloc_dev(bda);
      if (p_device == nullptr) {
        log::debug("new device record Allocation failed for new connection peer:{}", bda);
        return;
      } else {
        log::debug("Allocated new device record for new connection peer:{}", bda);
      }
    } else {
      /* If the device matches with stored paring address
       * reset the paring state to idle */
      if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
          BtmSecurity::Get().link_spec_.addrt.bda == bda) {
        log::warn("Connection failed during bonding attempt peer:{} reason:{}", bda,
                  hci_error_code_text(status));
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      }

      log::debug("Ignoring failed device connection peer:{} reason:{}", bda,
                 hci_error_code_text(status));
      return;
    }
  } else {
    log::debug(
            "Connected to known device state:{} handle:0x{:04x} status:{} "
            "enc_mode:{} bda:{} RName:{}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_), handle,
            hci_status_code_text(status), enc_mode, bda,
            reinterpret_cast<char const*>(p_device->sec_bd_name));

    bit_shift = (handle == p_device->ble_hci_handle) ? 8 : 0;
    /* Update the timestamp for this device */
    p_device->timestamp = BtmSecurity::Get().dev_rec_count_++;
    if (p_device->sm4 & BTM_SM4_CONN_PEND) {
      if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
          BtmSecurity::Get().link_spec_.addrt.bda == p_device->bd_addr &&
          (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD)) {
        /* if incoming acl connection failed while pairing, then try to connect
         * and continue */
        /* Motorola S9 disconnects without asking pin code */
        if ((status != HCI_SUCCESS) &&
            (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_WAIT_PIN_REQ)) {
          log::warn(
                  "Security Manager: btm_sec_connected: incoming connection failed "
                  "without asking PIN");

          p_device->sm4 &= ~BTM_SM4_CONN_PEND;
          if (p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) {
            /* remote device name is known, start a new acl connection */

            /* Start timer with 0 to initiate connection with new LCB */
            /* because L2CAP will delete current LCB with this event  */
            BtmSecurity::Get().p_collided_dev_ = p_device;
            alarm_set_on_mloop(BtmSecurity::Get().sec_collision_timer_, 0,
                               btm_sec_connect_after_reject_timeout, NULL);
          } else {
            /* remote device name is unknowm, start getting remote name first */

            BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_GET_REM_NAME);
            if (get_stack_rnr_interface().BTM_ReadRemoteDeviceName(p_device->bd_addr, NULL,
                                                                   BT_TRANSPORT_BR_EDR) !=
                tBTM_STATUS::BTM_CMD_STARTED) {
              log::error("cannot read remote name");
              BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
            }
          }
          return;
        } else {
          /* tell L2CAP it's a bonding connection. */
          l2cu_update_lcb_4_bonding(p_device->bd_addr, true);
        }
      }
      /* always clear the pending flag */
      p_device->sm4 &= ~BTM_SM4_CONN_PEND;
    }
  }

  p_device->role_switch_pending = BtmDevice::RoleSwitchPending::kNone;
  p_device->device_type |= BT_DEVICE_TYPE_BREDR;
  bool is_pairing_device = false;
  const bool addr_matched = (BtmSecurity::Get().link_spec_.addrt.bda == bda);

  if ((BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE) && addr_matched) {
    /* if we rejected incoming connection from bonding device */
    if ((status == HCI_ERR_HOST_REJECT_DEVICE) &&
        (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_REJECTED_CONNECT)) {
      log::warn(
              "Security Manager: btm_sec_connected: HCI_Conn_Comp Flags:0x{:04x}, "
              "sm4: 0x{:x}",
              BtmSecurity::Get().pairing_flags_, p_device->sm4);

      BtmSecurity::Get().pairing_flags_ &= ~BTM_PAIR_FLAGS_REJECTED_CONNECT;
      if (BTM_SEC_IS_SM4_UNKNOWN(p_device->sm4)) {
        /* Try again: RNR when no ACL causes HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT */
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_GET_REM_NAME);
        if (get_stack_rnr_interface().BTM_ReadRemoteDeviceName(bda, NULL, BT_TRANSPORT_BR_EDR) !=
            tBTM_STATUS::BTM_CMD_STARTED) {
          log::error("cannot read remote name");
          BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
        }
        return;
      }

      /* if we already have pin code */
      if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_LOCAL_PIN) {
        /* Start timer with 0 to initiate connection with new LCB */
        /* because L2CAP will delete current LCB with this event  */
        BtmSecurity::Get().p_collided_dev_ = p_device;
        alarm_set_on_mloop(BtmSecurity::Get().sec_collision_timer_, 0,
                           btm_sec_connect_after_reject_timeout, NULL);
      }
      return;
    } else if (status == HCI_ERR_CONNECTION_EXISTS) {
      /* wait for incoming connection without resetting pairing state */
      log::warn("Security Manager: btm_sec_connected: Wait for incoming connection");
      return;
    }
    is_pairing_device = true;
  }

  /* If connection was made to do bonding restore link security if changed */
  btm_restore_mode();

  /* if connection fails during pin request, notify application */
  if (status != HCI_SUCCESS) {
    /* If connection failed because of during pairing, need to tell user */
    if (is_pairing_device) {
      p_device->sec_rec.security_required &= ~BTM_SEC_OUT_AUTHENTICATE;
      p_device->sec_rec.sec_flags &=
              ~((BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_LINK_KEY_AUTHED) << bit_shift);
      log::verbose("security_required:{:x}", p_device->sec_rec.security_required);

      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

      /* We need to notify host that the key is not known any more */
      NotifyBondingChange(*p_device, status);
    } else if ((p_device->sec_rec.link_key_type <= BTM_LKEY_TYPE_REMOTE_UNIT) &&
               ((status == HCI_ERR_AUTH_FAILURE) || (status == HCI_ERR_KEY_MISSING) ||
                (status == HCI_ERR_HOST_REJECT_SECURITY) ||
                (status == HCI_ERR_PAIRING_NOT_ALLOWED) || (status == HCI_ERR_UNIT_KEY_USED) ||
                (status == HCI_ERR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED) ||
                (status == HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE) ||
                (status == HCI_ERR_REPEATED_ATTEMPTS))) {
      /*
          Do not send authentication failure, if following conditions hold good
           1.  BTM Sec Pairing state is idle
           2.  Link key for the remote device is present.
           3.  Remote is SSP capable.
       */
      p_device->sec_rec.security_required &= ~BTM_SEC_OUT_AUTHENTICATE;
      p_device->sec_rec.sec_flags &= ~(BTM_SEC_LE_LINK_KEY_KNOWN << bit_shift);

#ifdef BRCM_NOT_4_BTE
      /* If we rejected pairing, pass this special result code */
      if (acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY)) {
        status = HCI_ERR_HOST_REJECT_SECURITY;
      }
#endif

      /* We need to notify host that the key is not known any more */
      NotifyBondingChange(*p_device, status);
    }

    /* auth_complete_callback might have freed the p_device, ensure it exists before accessing */
    p_device = btm_get_dev(bda);
    if (!p_device) {
      /* Don't callback when device security record was removed */
      log::debug(
              "device security record associated with this bda has been removed! "
              "bda={}, do not callback",
              bda);
      return;
    }

    if (status == HCI_ERR_CONNECTION_TOUT || status == HCI_ERR_LMP_RESPONSE_TIMEOUT ||
        status == HCI_ERR_UNSPECIFIED || status == HCI_ERR_PAGE_TIMEOUT) {
      btm_sec_dev_rec_cback_event(p_device, tBTM_STATUS::BTM_DEVICE_TIMEOUT, false);
    } else {
      btm_sec_dev_rec_cback_event(p_device, tBTM_STATUS::BTM_ERR_PROCESSING, false);
    }

    return;
  }

  /*
   * The device is still in the pairing state machine and we now have the
   * link key.  If we have not sent the link key, send it now and remove
   * the authenticate requirement bit.  Reset the pairing state machine
   * and inform l2cap if the directed bonding was initiated.
   */
  if (is_pairing_device && (p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN)) {
    if (p_device->sec_rec.link_key_not_sent) {
      p_device->sec_rec.link_key_not_sent = false;
      btm_send_link_key_notif(p_device);
    }

    p_device->sec_rec.security_required &= ~BTM_SEC_OUT_AUTHENTICATE;

    /* remember flag before it is initialized */
    const bool is_pair_flags_we_started_dd =
            BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD;
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);

    if (is_pair_flags_we_started_dd) {
      /* Let l2cap start bond timer */
      l2cu_update_lcb_4_bonding(p_device->bd_addr, true);
    }
    log::info("Connection complete during pairing process peer:{}", bda);
    BTM_LogHistory(
            kBtmLogTag, bda, "Dedicated bonding",
            std::format("Initiated:{:c} pairing_flag:0x{:02x}",
                        (is_pair_flags_we_started_dd) ? 'T' : 'F', p_device->sec_rec.sec_flags));
  }

  p_device->hci_handle = handle;
  AclLinkSpec link_spec = {.addrt = {.type = BLE_ADDR_PUBLIC, .bda = bda},
                           .transport = BT_TRANSPORT_BR_EDR};
  btm_acl_created(link_spec, handle, assigned_role, locally_initiated);

  /* role may not be correct here, it will be updated by l2cap, but we need to
   */
  /* notify btm_acl that link is up, so starting of rmt name request will not */
  /* set paging flag up */
  /* whatever is in btm_establish_continue() without reporting the
   * BTM_BL_CONN_EVT event */
  /* For now there are a some devices that do not like sending */
  /* commands events and data at the same time. */
  /* Set the packet types to the default allowed by the device */
  btm_set_packet_types_from_address(bda, acl_get_supported_packet_types());

  /* Initialize security flags.  We need to do that because some            */
  /* authorization complete could have come after the connection is dropped */
  /* and that would set wrong flag that link has been authorized already    */
  p_device->sec_rec.sec_flags &=
          ~((BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED | BTM_SEC_ROLE_SWITCHED) << bit_shift);

  if (enc_mode != HCI_ENCRYPT_MODE_DISABLED) {
    p_device->sec_rec.sec_flags |= ((BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED) << bit_shift);
  }

  if (p_device->sec_rec.pin_code_length >= 16 ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB_P_256) {
    p_device->sec_rec.sec_flags |= (BTM_SEC_16_DIGIT_PIN_AUTHED << bit_shift);
  }

  /* After connection is established we perform security if we do not know */
  /* the name, or if we are originator because some procedure can have */
  /* been scheduled while connection was down */
  log::debug("Is connection locally initiated:{}", p_device->outgoing);
  if (!(p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) || p_device->outgoing) {
    tBTM_STATUS res = btm_sec_execute_procedure(p_device);
    if (res != tBTM_STATUS::BTM_CMD_STARTED) {
      btm_sec_dev_rec_cback_event(p_device, res, false);
    }
  }
}

tBTM_STATUS btm_sec_disconnect(uint16_t handle, tHCI_STATUS reason, std::string comment) {
  BtmDevice* p_device = btm_get_dev_by_handle(handle);

  /* In some weird race condition we may not have a record */
  if (!p_device) {
    acl_disconnect_from_handle(handle, reason,
                               "stack::btm::btm_sec::btm_sec_disconnect No security record");
    return tBTM_STATUS::BTM_SUCCESS;
  }

  /* If we are in the process of bonding we need to tell client that auth failed
   */
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      BtmSecurity::Get().link_spec_.addrt.bda == p_device->bd_addr &&
      (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD)) {
    /* we are currently doing bonding.  Link will be disconnected when done */
    BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_DISC_WHEN_DONE;
    return tBTM_STATUS::BTM_BUSY;
  }

  return btm_sec_send_hci_disconnect(p_device, reason, handle, comment);
}

void btm_sec_disconnected(uint16_t handle, tHCI_REASON reason, std::string comment) {
  if ((reason != HCI_ERR_CONN_CAUSE_LOCAL_HOST) && (reason != HCI_ERR_PEER_USER) &&
      (reason != HCI_ERR_REMOTE_POWER_OFF)) {
    log::warn("Got uncommon disconnection reason:{} handle:0x{:04x} comment:{}",
              hci_error_code_text(reason), handle, comment);
  }

  BtmDevice* p_device = btm_get_dev_by_handle(handle);
  if (p_device == nullptr) {
    log::warn("Got disconnect for unknown device record handle:0x{:04x}", handle);
    return;
  }

  const tBT_TRANSPORT transport =
          (handle == p_device->hci_handle) ? BT_TRANSPORT_BR_EDR : BT_TRANSPORT_LE;

  tBT_TRANSPORT pairing_transport =
          (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_LE_ACTIVE) == 0 ? BT_TRANSPORT_BR_EDR
                                                                              : BT_TRANSPORT_LE;
  bool pairing_transport_matches = (transport == pairing_transport);

  /* clear unused flags */
  p_device->sm4 &= BTM_SM4_TRUE;

  if (BtmSecurity::Get().p_collided_dev_ &&
      p_device->bd_addr == BtmSecurity::Get().p_collided_dev_->bd_addr) {
    log::debug("clear auth collision info after disconnection");
    BtmSecurity::Get().collision_start_time_ = 0;
    BtmSecurity::Get().p_collided_dev_ = NULL;
    if (alarm_is_scheduled(BtmSecurity::Get().sec_collision_timer_)) {
      alarm_cancel(BtmSecurity::Get().sec_collision_timer_);
    }
  }

  // Reset link key request timer currently pairing device disconnected
  if (BtmSecurity::Get().link_spec_.addrt.bda == p_device->bd_addr) {
    BtmSecurity::Get().ResetLinkKeyRequestTimer();
  }

  /* If we are in the process of bonding we need to tell client that auth failed
   */
  const uint8_t old_pairing_flags = BtmSecurity::Get().pairing_flags_;
  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      BtmSecurity::Get().link_spec_.addrt.bda == p_device->bd_addr && pairing_transport_matches) {
    log::debug("Disconnected while pairing process active handle:0x{:04x}", handle);
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
    p_device->sec_rec.sec_flags &= ~BTM_SEC_LINK_KEY_KNOWN;

    /* If the disconnection reason is REPEATED_ATTEMPTS,
       send this error message to complete callback function
       to display the error message of Repeated attempts.
       All others, send HCI_ERR_AUTH_FAILURE. */
    tHCI_STATUS status = HCI_ERR_AUTH_FAILURE;
    if (reason == HCI_ERR_REPEATED_ATTEMPTS) {
      status = HCI_ERR_REPEATED_ATTEMPTS;
    } else if (old_pairing_flags & BTM_PAIR_FLAGS_WE_STARTED_DD) {
      status = HCI_ERR_HOST_REJECT_SECURITY;
    } else {
      DEVICE_IOT_CONFIG_ADDR_INT_ADD_ONE(p_device->bd_addr, IOT_CONF_KEY_GAP_DISC_AUTHFAIL_COUNT);
    }

    NotifyBondingChange(*p_device, status);

    p_device = btm_get_dev_by_handle(handle);
    if (p_device == nullptr) {
      // |BtmSecurity::Get().app_->auth_complete_callback| may cause |p_device| to be deallocated.
      log::warn("Device record was deallocated after user callback");
      return;
    }
  }

  log::debug("device:{} name:{} state:{} reason:{} flag:0x{:x} bond_type:{} sec_req:0x{:x}",
             p_device->bd_addr, reinterpret_cast<char const*>(p_device->sec_bd_name),
             btm_pair_state_descr(BtmSecurity::Get().pairing_state_), hci_reason_code_text(reason),
             p_device->sec_rec.sec_flags, bond_type_text(p_device->sec_rec.bond_type),
             p_device->sec_rec.security_required);

  /* see sec_flags processing in btm_acl_removed */

  if (transport == BT_TRANSPORT_LE) {
    p_device->ble_hci_handle = HCI_INVALID_HANDLE;
    p_device->sec_rec.sec_flags &=
            ~(BTM_SEC_LE_AUTHENTICATED | BTM_SEC_LE_ENCRYPTED | BTM_SEC_ROLE_SWITCHED);
    p_device->sec_rec.le_enc_key_size = 0;
    p_device->suggested_tx_octets = 0;

    if ((p_device->sec_rec.sec_flags & BTM_SEC_LE_LINK_KEY_KNOWN) == 0) {
      p_device->sec_rec.sec_flags &= ~(BTM_SEC_LE_LINK_KEY_AUTHED | BTM_SEC_LE_AUTHENTICATED);
    }
  } else {
    p_device->hci_handle = HCI_INVALID_HANDLE;
    p_device->sec_rec.sec_flags &= ~(BTM_SEC_AUTHENTICATED | BTM_SEC_ENCRYPTED |
                                     BTM_SEC_ROLE_SWITCHED | BTM_SEC_16_DIGIT_PIN_AUTHED);
    p_device->sec_rec.enc_key_size = 0;

    // Remove temporary key.
    if (p_device->sec_rec.bond_type == BOND_TYPE_TEMPORARY) {
      p_device->sec_rec.sec_flags &= ~(BTM_SEC_LINK_KEY_KNOWN);
    }
  }

  /* Some devices hardcode sample LTK value from spec, instead of generating
   * one. Treat such devices as insecure, and remove such bonds on
   * disconnection.
   */
  if (p_device->sec_rec.ble_keys.pltk == SAMPLE_LTK) {
    log::info("removing bond to device that used sample LTK: {}", p_device->bd_addr);

    bta_dm_remove_device(p_device->bd_addr);
    return;
  }

  if (transport == BT_TRANSPORT_LE) {
    p_device->sec_rec.le_link = tSECURITY_STATE::IDLE;
  } else if (transport == BT_TRANSPORT_BR_EDR) {
    p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
  }

  if (p_device->sec_rec.classic_link == tSECURITY_STATE::DISCONNECTING ||
      p_device->sec_rec.le_link == tSECURITY_STATE::DISCONNECTING) {
    log::debug("Waiting for other transport to disconnect current:{}",
               bt_transport_text(transport));
    return;
  }

  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      BtmSecurity::Get().link_spec_.addrt.bda == p_device->bd_addr && !pairing_transport_matches) {
    log::debug("Disconnection on the other transport while pairing");
    return;
  }

  if (p_device->sec_rec.le_link == tSECURITY_STATE::ENCRYPTING && transport != BT_TRANSPORT_LE) {
    log::debug("Disconnection on the other transport while encrypting LE");
    return;
  }

  if ((p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING ||
       p_device->sec_rec.classic_link == tSECURITY_STATE::ENCRYPTING) &&
      transport != BT_TRANSPORT_BR_EDR) {
    log::debug("Disconnection on the other transport while encrypting BR/EDR");
    return;
  }

  p_device->sec_rec.classic_link = tSECURITY_STATE::IDLE;
  p_device->sec_rec.le_link = tSECURITY_STATE::IDLE;
  p_device->sec_rec.security_required = BTM_SEC_NONE;
  if (!p_device->sec_rec.is_bonded()) {
    log::warn("Clearing security flags for unbonded device {}", p_device->bd_addr);
    p_device->sec_rec.sec_flags = 0;
  }

  if (p_device->sec_rec.p_callback != nullptr) {
    tBTM_SEC_CALLBACK* p_callback = p_device->sec_rec.p_callback;
    /* when the peer device time out the authentication before
       we do, this call back must be reset here */
    p_device->sec_rec.p_callback = nullptr;
    (*p_callback)(p_device->bd_addr, transport, p_device->sec_rec.p_ref_data,
                  tBTM_STATUS::BTM_ERR_PROCESSING);
    log::debug("Cleaned up pending security state device:{} transport:{}", p_device->bd_addr,
               bt_transport_text(transport));
  }
}

void btm_sec_role_changed(tHCI_STATUS hci_status, const RawAddress& bd_addr, tHCI_ROLE new_role) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);

  if (p_device == nullptr || hci_status != HCI_SUCCESS) {
    return;
  }
  if (new_role == HCI_ROLE_CENTRAL && btm_dev_authenticated(p_device) &&
      !btm_dev_encrypted(p_device)) {
    btm_set_encryption(p_device->bd_addr, BT_TRANSPORT_BR_EDR, NULL, NULL, BTM_BLE_SEC_NONE);
  }
}

static void read_encryption_key_size_complete_after_key_refresh(uint8_t encr_enable, uint8_t status,
                                                                uint16_t handle, uint8_t key_size) {
  if (status == HCI_ERR_INSUFFICIENT_SECURITY) {
    /* If remote device stop the encryption before we call "Read Encryption Key
     * Size", we might receive Insufficient Security, which means that link is
     * no longer encrypted. */
    log::info("encryption stopped on link: 0x{:x}", handle);
    return;
  }

  if (status != HCI_SUCCESS) {
    log::info("disconnecting, status: 0x{:x}", status);
    acl_disconnect_from_handle(handle, HCI_ERR_PEER_USER, "stack::btu_hcif Key size fail");
    return;
  }

  if (key_size < btm_sec_get_min_enc_key_size()) {
    log::error("encryption key too short, disconnecting. handle: 0x{:x} key_size {}", handle,
               key_size);

    acl_disconnect_from_handle(handle, HCI_ERR_HOST_REJECT_SECURITY,
                               "stack::btu::btu_hcif::read_encryption_key_size_"
                               "complete_after_key_refresh Key size too small");
    return;
  }

  btm_sec_encrypt_change(handle, static_cast<tHCI_STATUS>(status), encr_enable, key_size);
}

void btm_sec_encryption_key_refresh_complete(uint16_t handle, tHCI_STATUS status) {
  if (status != HCI_SUCCESS || BTM_IsBleConnection(handle) ||
      // Skip encryption key size check when using set_min_encryption_key_size
      bluetooth::shim::GetController()->IsSupported(
              bluetooth::hci::OpCode::SET_MIN_ENCRYPTION_KEY_SIZE)) {
    btm_sec_encrypt_change(handle, static_cast<tHCI_STATUS>(status),
                           (status == HCI_SUCCESS) ? 1 : 0, 0, true);
  } else {
    btsnd_hcic_read_encryption_key_size(
            handle,
            base::Bind(&read_encryption_key_size_complete_after_key_refresh, 1 /* encr_enable */));
  }
}

/** This function is called when a new connection link key is generated */
void btm_sec_link_key_notification(const RawAddress& bda, const Octet16& link_key,
                                   uint8_t key_type) {
  BtmDevice* p_device = btm_find_or_alloc_dev(bda);
  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  bool locally_initiated = false;
  bool ctkd = false;

  log::debug("New link key generated device:{} key_type:{}", bda, key_type);

  if ((key_type >= BTM_LTK_DERIVED_LKEY_OFFSET + BTM_LKEY_TYPE_COMBINATION) &&
      (key_type <= BTM_LTK_DERIVED_LKEY_OFFSET + BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
    ctkd = true;
    key_type -= BTM_LTK_DERIVED_LKEY_OFFSET;
    btm_sec_link_key_request_reply(bda, link_key);
  }

  /* If connection was made to do bonding restore link security if changed */
  btm_restore_mode();

  if (key_type != BTM_LKEY_TYPE_CHANGED_COMB) {
    p_device->sec_rec.link_key_type = key_type;
  }

  p_device->sec_rec.sec_flags |= BTM_SEC_LINK_KEY_KNOWN;

  /*
   * Until this point in time, we do not know if MITM was enabled, hence we
   * add the extended security flag here.
   */
  if (p_device->sec_rec.pin_code_length >= 16 ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB ||
      p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB_P_256) {
    p_device->sec_rec.sec_flags |= BTM_SEC_LINK_KEY_AUTHED;
    p_device->sec_rec.sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED;
  }

  /* BR/EDR connection, update the encryption key size to be 16 as always */
  p_device->sec_rec.enc_key_size = 16;
  p_device->sec_rec.link_key = link_key;

  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE &&
      BtmSecurity::Get().link_spec_.addrt.bda == bda) {
    if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_WE_STARTED_DD) {
      locally_initiated = true;
    } else {
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
    }
  }

  /* Always save derived LTK */
  if (ctkd) {
    p_device->sec_rec.pairing_algorithm = PairingAlgorithm::SC;  // for CTKD
    log::verbose("Save LTK derived LK (key_type = {})", p_device->sec_rec.link_key_type);
    (BtmSecurity::Get().app_->link_key_callback)(bda, p_device->sec_bd_name, link_key,
                                                 p_device->sec_rec.link_key_type, true /* ctkd */);

  } else {
    if ((p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_UNAUTH_COMB_P_256) ||
        (p_device->sec_rec.link_key_type == BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
      p_device->sec_rec.bredr_sc_enc_reason =
              p_device->bond_lost ? BtmSecurityRecord::BrEdrScEncReason::REPAIRED
                                  : BtmSecurityRecord::BrEdrScEncReason::PAIRED;
      log::verbose("set bredr_sc_enc_reason to {}", BtmSecurityRecord::bredr_sc_enc_reason_text(
                                                            p_device->sec_rec.bredr_sc_enc_reason));
    } else {
      p_device->sec_rec.bredr_sc_enc_reason = BtmSecurityRecord::BrEdrScEncReason::OTHER;
    }
  }

  if (p_device->sec_rec.is_bond_type_persistent() &&
      (p_device->is_device_type_br_edr() || p_device->is_device_type_dual_mode())) {
    btm_sec_store_device_sc_support(p_device->get_br_edr_hci_handle(),
                                    p_device->HostSupportsSecureConnections(),
                                    p_device->ControllerSupportsSecureConnections());
  }

  /* Get the name before sending link key to higher layers if it is not known already.
   * Unless it is a HID Device, then we need to send link key to higher layer right away. */
  if (!ctkd && !(p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) &&
      (p_device->dev_class[1] & BTM_COD_MAJOR_CLASS_MASK) != BTM_COD_MAJOR_PERIPHERAL) {
    log::verbose("Delayed BDA: {}, Type: {}", bda, key_type);

    p_device->sec_rec.link_key_not_sent = true;

    /* If it is for bonding nothing else will follow, so we need to start name resolution */
    if (locally_initiated) {
      bluetooth::shim::ACL_RemoteNameRequest(
              bda, HCI_PAGE_SCAN_REP_MODE_R1, HCI_MANDATARY_PAGE_SCAN_MODE,
              com_android_bluetooth_flags_use_cached_clock_offset() ? BTM_GetCachedClockOffset(bda)
                                                                    : 0);
    }

    log::verbose("rmt_io_caps:{}, sec_flags:x{:x}, dev_class[1]:x{:02x}",
                 p_device->sec_rec.rmt_io_caps, p_device->sec_rec.sec_flags,
                 p_device->dev_class[1]);
    return;
  }

  if (ctkd) {
    log::verbose(
            "btm_sec_link_key_notification()  LTK derived LK is saved already "
            "(key_type = {})",
            p_device->sec_rec.link_key_type);

    return;
  }

  (BtmSecurity::Get().app_->link_key_callback)(bda, p_device->sec_bd_name, link_key,
                                               p_device->sec_rec.link_key_type, false /* ctkd */);
}

/*******************************************************************************
 *
 * Function         btm_sec_lk_req_timeout
 *
 * Description      This function is called when link key request timer expires
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_lk_req_timeout(void* /* data */) {
  BtmSecurity::Get().ResetLinkKeyRequestTimer();

  const RawAddress& bd_addr = BtmSecurity::Get().link_spec_.addrt.bda;
  if (bd_addr.IsEmpty() || bd_addr == RawAddress::kAny) {
    log::error("No ongoing pairing, aborting link key request timer");
    return;
  }

  const BtmDevice* p_device = btm_find_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("No device found for {}", bd_addr);
    return;
  }

  // BtmSecurity::link_spec_ may have the pseudo address. If LE pairing concluded successfully,
  // BtmDevice.bd_addr should have the identity address which is what we should use with the HCI
  // commands here.
  if (p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) {
    log::warn("Sending link key reply for {} due to timeout", p_device->bd_addr);
    btsnd_hcic_link_key_req_reply(p_device->bd_addr, p_device->sec_rec.link_key);
    return;
  }

  log::warn("Sending link key negative reply for {} due to timeout", p_device->bd_addr);
  btsnd_hcic_link_key_neg_reply(p_device->bd_addr);
}

/*******************************************************************************
 *
 * Function         btm_sec_link_key_request
 *
 * Description      This function is called when controller requests link key
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_link_key_request(const RawAddress& bda) {
  BtmDevice* p_device = btm_find_or_alloc_dev(bda);

  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  log::verbose("bda: {}", bda);
  if (!concurrentPeerAuthIsEnabled()) {
    p_device->sec_rec.classic_link = tSECURITY_STATE::AUTHENTICATING;
  }

  BtmSecurity& btm_security = BtmSecurity::Get();
  if (btm_security.pairing_state_ == BTM_PAIR_STATE_WAIT_PIN_REQ &&
      btm_security.collision_start_time_ != 0 && btm_security.p_collided_dev_ &&
      btm_security.p_collided_dev_->bd_addr == bda) {
    log::verbose("Rejecting link key req State: {} Collision start time: {}",
                 BtmSecurity::Get().pairing_state_, BtmSecurity::Get().collision_start_time_);
    btsnd_hcic_link_key_neg_reply(bda);
    return;
  }

  if (p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) {
    btsnd_hcic_link_key_req_reply(bda, p_device->sec_rec.link_key);
    return;
  }

  /* Notify L2CAP to increase timeout */
  l2c_pin_code_request(bda);

  // While pairing with a device over LE, it is possible that the local SMP has not completed
  // generating the link key yet but the remote device has. This can happen due to delay in
  // transmission of SMP key distribution packets.
  // In that case, the remote device may request BR/EDR authentication request before the link key
  // is available here.
  if (com_android_bluetooth_flags_link_key_request_timer() &&
      btm_security.link_spec_.addrt.bda == bda &&
      btm_security.link_spec_.transport == BT_TRANSPORT_LE &&
      btm_security.lk_req_timer_ == nullptr) {
    log::debug("Waiting for CTKD to complete for device: {}", bda);
    btm_security.lk_req_timer_ = alarm_new("btm_sec_lk_req_timer");
    alarm_set_on_mloop(btm_security.lk_req_timer_, BTM_SEC_LK_REQ_TIMEOUT_MS,
                       btm_sec_lk_req_timeout, nullptr);
    return;
  }

  /* The link key is not in the database and it is not known to the manager */
  btsnd_hcic_link_key_neg_reply(bda);
}

static void btm_sec_link_key_request_reply(const RawAddress& bda, const LinkKey& link_key) {
  if (!BtmSecurity::Get().ResetLinkKeyRequestTimer()) {
    // No one is waiting for the link key reply, so we can return
    return;
  }

  log::verbose("bda: {}", bda);
  btsnd_hcic_link_key_req_reply(bda, link_key);
}

/*******************************************************************************
 *
 * Function         btm_sec_pairing_timeout
 *
 * Description      This function is called when host does not provide PIN
 *                  within requested time
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_pairing_timeout(void* /* data */) {
  log::warn("State: {} Flags: {} Device: {}",
            btm_pair_state_descr(BtmSecurity::Get().pairing_state_),
            BtmSecurity::Get().pairing_flags_, BtmSecurity::Get().link_spec_);

  bluetooth::metrics::LogBluetoothEvent(BtmSecurity::Get().link_spec_.addrt.bda,
                                        bluetooth::metrics::EventType::BONDING,
                                        bluetooth::metrics::State::TIMEOUT);

  if (is_autonomous_repairing_supported() &&
      btm_is_bond_lost(BtmSecurity::Get().link_spec_.addrt.bda)) {
    bluetooth::metrics::Counter(bluetooth::metrics::CounterKey::BOND_REPAIR_LOCAL_TIMEOUT);
  }

  const BtIoCap local_io_caps = btm_sec_get_local_iocaps();
  BtmDevice* p_device = btm_get_dev(BtmSecurity::Get().link_spec_.addrt.bda);

  switch (BtmSecurity::Get().pairing_state_) {
    case BTM_PAIR_STATE_WAIT_PIN_REQ:
      btm_sec_bond_cancel_complete();
      break;

    case BTM_PAIR_STATE_WAIT_LOCAL_PIN:
      if (com_android_bluetooth_flags_security_mode_3_pairing() ||
          (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_PRE_FETCH_PIN) == 0) {
        btsnd_hcic_pin_code_neg_reply(BtmSecurity::Get().link_spec_.addrt.bda);
      }
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      /* We need to notify the UI that no longer need the PIN */
      if (p_device == nullptr) {
        BD_NAME name = {};
        (BtmSecurity::Get().app_->auth_complete_callback)(BtmSecurity::Get().link_spec_.addrt.bda,
                                                          name, HCI_ERR_CONNECTION_TOUT);
      } else {
        NotifyBondingChange(*p_device, HCI_ERR_CONNECTION_TOUT);
      }

      break;

    case BTM_PAIR_STATE_WAIT_NUMERIC_CONFIRM:
      btsnd_hcic_user_conf_reply(BtmSecurity::Get().link_spec_.addrt.bda, false);
      /* BtmSecurity::Get().change_pairing_state (BTM_PAIR_STATE_IDLE); */
      break;

    case BTM_PAIR_STATE_KEY_ENTRY:
      if (local_io_caps != BtIoCap::NO_INPUT_NO_OUTPUT) {
        btsnd_hcic_user_passkey_neg_reply(BtmSecurity::Get().link_spec_.addrt.bda);
      } else {
        BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      }
      break;

    case BTM_PAIR_STATE_WAIT_LOCAL_IOCAPS: {
      tBTM_AUTH_REQ auth_req =
              (local_io_caps == BtIoCap::NO_INPUT_NO_OUTPUT) ? BTM_AUTH_AP_NO : BTM_AUTH_AP_YES;
      // TODO(optedoblivion): Inject OOB_DATA_PRESENT Flag
      btsnd_hcic_io_cap_req_reply(BtmSecurity::Get().link_spec_.addrt.bda, local_io_caps,
                                  BTM_OOB_NONE, auth_req);
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      break;
    }

    case BTM_PAIR_STATE_WAIT_LOCAL_OOB_RSP:
      btsnd_hcic_rem_oob_neg_reply(BtmSecurity::Get().link_spec_.addrt.bda);
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      break;

    case BTM_PAIR_STATE_WAIT_DISCONNECT:
      /* simple pairing failed. Started a 1-sec timer at simple pairing
       * complete.
       * now it's time to tear down the ACL link*/
      if (p_device == nullptr) {
        log::error("BTM_PAIR_STATE_WAIT_DISCONNECT unknown device: {}",
                   BtmSecurity::Get().link_spec_);
        break;
      }
      btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, p_device->hci_handle,
                                  "stack::btm::btm_sec::btm_sec_pairing_timeout");
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      break;

    case BTM_PAIR_STATE_WAIT_AUTH_COMPLETE:
      if (BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_LE_ACTIVE) {
        SMP_PairCancel(BtmSecurity::Get().link_spec_.addrt.bda);
      }
      ABSL_FALLTHROUGH_INTENDED;
    case BTM_PAIR_STATE_GET_REM_NAME:
      /* We need to notify the UI that timeout has happened while waiting for
       * authentication*/
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      if (p_device == nullptr) {
        BD_NAME name = {};
        (BtmSecurity::Get().app_->auth_complete_callback)(BtmSecurity::Get().link_spec_.addrt.bda,
                                                          name, HCI_ERR_CONNECTION_TOUT);
      } else {
        NotifyBondingChange(*p_device, HCI_ERR_CONNECTION_TOUT);
      }
      break;

    default:
      log::warn("not processed state: {}", btm_pair_state_descr(BtmSecurity::Get().pairing_state_));
      BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_IDLE);
      break;
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_pin_code_request
 *
 * Description      This function is called when controller requests PIN code
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_pin_code_request(const RawAddress& bda) {
  /* Tell L2CAP that there was a PIN code request,  */
  /* it may need to stretch timeouts                */
  l2c_pin_code_request(bda);

  log::debug("Controller requests PIN code device:{} state:{}", bda,
             btm_pair_state_descr(BtmSecurity::Get().pairing_state_));

  RawAddress local_bd_addr =
          bluetooth::ToRawAddress(bluetooth::shim::GetController()->GetMacAddress());
  if (bda == local_bd_addr) {
    btsnd_hcic_pin_code_neg_reply(bda);
    return;
  }

  if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_IDLE) {
    if (bda == BtmSecurity::Get().link_spec_.addrt.bda &&
        BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_WAIT_AUTH_COMPLETE) {
      btsnd_hcic_pin_code_neg_reply(bda);
      return;
    } else if (BtmSecurity::Get().pairing_state_ != BTM_PAIR_STATE_WAIT_PIN_REQ ||
               bda != BtmSecurity::Get().link_spec_.addrt.bda) {
      log::warn("Rejected - state: {}", btm_pair_state_descr(BtmSecurity::Get().pairing_state_));
      btsnd_hcic_pin_code_neg_reply(bda);
      return;
    }
  }

  BtmDevice* p_device = btm_find_or_alloc_dev(bda);
  if (p_device == nullptr) {
    log::error("No memory to allocate new p_device");
    return;
  }

  if (p_device->sec_rec.is_bonded(BT_TRANSPORT_BR_EDR) &&
      !p_device->sec_rec.is_device_encrypted() &&
      com_android_bluetooth_flags_detect_bondloss_legacy_bredr_pairing()) {
    log::warn(
            "Remote device is already bonded but it is initiating legacy pairing, marking bond "
            "as lost");
    btsnd_hcic_pin_code_neg_reply(bda);
    btm_sec_report_bond_loss(p_device, BT_TRANSPORT_BR_EDR, BTM_KEY_MISSING_BREDR_INCOMING_PAIRING);
    return;
  }

  /* received PIN code request. must be non-sm4 */
  p_device->sm4 = BTM_SM4_KNOWN;
  p_device->sec_rec.pairing_algorithm = PairingAlgorithm::BREDR_LEGACY;

  if (BtmSecurity::Get().pairing_state_ == BTM_PAIR_STATE_IDLE) {
    BtmSecurity::Get().link_spec_.addrt.bda = bda;
    BtmSecurity::Get().link_spec_.transport = BT_TRANSPORT_BR_EDR;

    BtmSecurity::Get().pairing_flags_ = BTM_PAIR_FLAGS_PEER_STARTED_DD;
  }

  if (!com_android_bluetooth_flags_local_pin_key_type() && !BtmSecurity::Get().pairing_disabled_ &&
      (BtmSecurity::Get().cfg_.pin_type == HCI_PIN_TYPE_FIXED)) {
    log::verbose("Fixed pin replying");
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
    btsnd_hcic_pin_code_req_reply(bda, BtmSecurity::Get().cfg_.pin_code_len,
                                  BtmSecurity::Get().cfg_.pin_code);
    return;
  }

  /* Use the connecting device's CoD for the connection */
  if ((bda == BtmSecurity::Get().connecting_bda_) &&
      (BtmSecurity::Get().connecting_dc_ != kDevClassEmpty)) {
    log::info("CoD: previous value {}, replaced with {}", dev_class_text(p_device->dev_class),
              dev_class_text(BtmSecurity::Get().connecting_dc_));
    p_device->dev_class = BtmSecurity::Get().connecting_dc_;
  }

  /* We could have started connection after asking user for the PIN code */
  if (!com_android_bluetooth_flags_security_mode_3_pairing() &&
      BtmSecurity::Get().pin_code_len_ != 0) {
    log::verbose("Sending reply");
    btsnd_hcic_pin_code_req_reply(bda, BtmSecurity::Get().pin_code_len_,
                                  BtmSecurity::Get().pin_code_);

    /* Mark that we forwarded received from the user PIN code */
    BtmSecurity::Get().pin_code_len_ = 0;

    /* We can change mode back right away, that other connection being
     * established */
    /* is not forced to be secure - found a FW issue, so we can not do this
    btm_restore_mode(); */

    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_AUTH_COMPLETE);
  } else if (BtmSecurity::Get().pairing_disabled_ ||
             (!p_device->IsLocallyInitiated() &&
              ((p_device->dev_class[1] & BTM_COD_MAJOR_CLASS_MASK) == BTM_COD_MAJOR_PERIPHERAL) &&
              (p_device->dev_class[2] & BTM_COD_MINOR_KEYBOARD))) {
    /* If pairing disabled
     * OR no PIN callback and not bonding
     * OR we could not allocate entry in the database reject pairing request
     * OR Microsoft keyboard can for some reason try to establish connection the only thing we can
     *    do here is to shut it up. Normally we will be originator for keyboard bonding */
    log::warn("Pairing disabled:{}; Dev Rec:{}!", BtmSecurity::Get().pairing_disabled_,
              std::format_ptr(p_device));

    btsnd_hcic_pin_code_neg_reply(bda);
  } else {
    /* Notify upper layer of PIN request and start expiration timer */
    BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_LOCAL_PIN);
    /* Pin code request can not come at the same time as connection request */
    BtmSecurity::Get().connecting_bda_ = bda;
    BtmSecurity::Get().connecting_dc_ = p_device->dev_class;

    /* Check if the name is known */
    /* Even if name is not known we might not be able to get one */
    /* this is the case when we are already getting something from the */
    /* device, so HCI level is flow controlled */
    /* Also cannot send remote name request while paging, i.e. connection is not
     * completed */
    if (p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) {
      log::verbose("Going for callback");

      BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_PIN_REQD;
      (BtmSecurity::Get().app_->pin_callback)(
              bda, p_device->dev_class, p_device->sec_bd_name,
              p_device->sec_rec.required_security_flags_for_pairing & BTM_SEC_IN_MIN_16_DIGIT_PIN,
              p_device->sec_rec.pairing_algorithm);

    } else {
      log::verbose("Going for remote name");

      /* We received PIN code request for the device with unknown name */
      /* it is not user friendly just to ask for the PIN without name */
      /* try to get name at first */
      bluetooth::shim::ACL_RemoteNameRequest(p_device->bd_addr, HCI_PAGE_SCAN_REP_MODE_R1,
                                             HCI_MANDATARY_PAGE_SCAN_MODE,
                                             com_android_bluetooth_flags_use_cached_clock_offset()
                                                     ? BTM_GetCachedClockOffset(p_device->bd_addr)
                                                     : 0);
    }
  }

  return;
}

/*******************************************************************************
 *
 * Function         btm_sec_update_clock_offset
 *
 * Description      This function is called to update clock offset
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_update_clock_offset(uint16_t handle, uint16_t clock_offset) {
  BtmDevice* p_device = btm_get_dev_by_handle(handle);
  if (p_device == nullptr) {
    return;
  }
  p_device->clock_offset = clock_offset | BTM_CLOCK_OFFSET_VALID;

  if (com_android_bluetooth_flags_use_cached_clock_offset()) {
    btif_set_device_clockoffset(p_device->bd_addr, clock_offset);
  }

  tBTM_INQ_INFO* p_inq_info = BTM_InqDbRead(p_device->bd_addr);
  if (p_inq_info == nullptr) {
    return;
  }
  p_inq_info->results.clock_offset = clock_offset | BTM_CLOCK_OFFSET_VALID;
}

/******************************************************************
 * S T A T I C     F U N C T I O N S
 ******************************************************************/

/*******************************************************************************
 *
 * Function         btm_sec_execute_procedure
 *
 * Description      This function is called to start required security
 *                  procedure.  There is a case when multiplexing protocol
 *                  calls this function on the originating side, connection to
 *                  the peer will not be established.  This function in this
 *                  case performs only authorization.
 *
 * Returns          tBTM_STATUS::BTM_SUCCESS     - permission is granted
 *                  tBTM_STATUS::BTM_CMD_STARTED - in process
 *                  tBTM_STATUS::BTM_NO_RESOURCES  - permission declined
 *
 ******************************************************************************/
tBTM_STATUS btm_sec_execute_procedure(BtmDevice* p_device) {
  log::assert_that(p_device != nullptr, "assert failed: p_device != nullptr");
  log::debug("security_required:0x{:x} security_flags:0x{:x} le_link:{} classic_link:{}",
             p_device->sec_rec.security_required, p_device->sec_rec.sec_flags,
             p_device->sec_rec.le_link, p_device->sec_rec.classic_link);

  if (p_device->sec_rec.classic_link != tSECURITY_STATE::IDLE) {
    log::info("No immediate action taken in busy state: le_link={} classic_link={}",
              p_device->sec_rec.le_link, p_device->sec_rec.classic_link);
    return tBTM_STATUS::BTM_CMD_STARTED;
  }

  /* If any security is required, get the name first */
  if (!(p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) &&
      (p_device->hci_handle != HCI_INVALID_HANDLE)) {
    log::debug("Security Manager: Start get name");
    if (!btm_sec_start_get_name(p_device)) {
      log::warn("Unable to start remote name request");
      return tBTM_STATUS::BTM_NO_RESOURCES;
    }
    return tBTM_STATUS::BTM_CMD_STARTED;
  }

  /* If connection is not authenticated and authentication is required */
  /* start authentication and return PENDING to the caller */
  if (p_device->hci_handle != HCI_INVALID_HANDLE) {
    bool start_auth = false;

    // Check link status of BR/EDR
    if (!(p_device->sec_rec.sec_flags & BTM_SEC_AUTHENTICATED)) {
      if (p_device->IsLocallyInitiated()) {
        if (p_device->sec_rec.security_required &
            (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT)) {
          log::debug("Outgoing authentication/encryption Required");
          start_auth = true;
        }
      } else {
        if (p_device->sec_rec.security_required & (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT)) {
          log::debug("Incoming authentication/encryption Required");
          start_auth = true;
        }
      }
    }

    if (!(p_device->sec_rec.sec_flags & BTM_SEC_16_DIGIT_PIN_AUTHED)) {
      /*
       * We rely on BTM_SEC_16_DIGIT_PIN_AUTHED being set if MITM is in use,
       * as 16 DIGIT is only needed if MITM is not used. Unfortunately, the
       * BTM_SEC_AUTHENTICATED is used for both MITM and non-MITM
       * authenticated connections, hence we cannot distinguish here.
       */
      if (!p_device->IsLocallyInitiated()) {
        if (p_device->sec_rec.security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN) {
          log::debug("BTM_SEC_IN_MIN_16_DIGIT_PIN Required");
          start_auth = true;
        }
      }
    }

    if (start_auth) {
      if (alarm_is_scheduled(BtmSecurity::Get().sec_collision_timer_) &&
          (BtmSecurity::Get().p_collided_dev_->bd_addr == p_device->bd_addr)) {
        log::debug(
                "Security Manager: Authentication will be executed after collision "
                "timer expired");
        return tBTM_STATUS::BTM_CMD_STARTED;
      }
      log::debug("Security Manager: Start authentication");

      /*
       * If we do have a link-key, but we end up here because we need an
       * upgrade, then clear the link-key known and authenticated flag before
       * restarting authentication.
       * WARNING: If the controller has link-key, it is optional and
       * recommended for the controller to send a Link_Key_Request.
       * In case we need an upgrade, the only alternative would be to delete
       * the existing link-key. That could lead to very bad user experience
       * or even IOP issues, if a reconnect causes a new connection that
       * requires an upgrade.
       */
      if ((p_device->sec_rec.sec_flags & BTM_SEC_LINK_KEY_KNOWN) &&
          (!(p_device->sec_rec.sec_flags & BTM_SEC_16_DIGIT_PIN_AUTHED) &&
           (!p_device->IsLocallyInitiated() &&
            (p_device->sec_rec.security_required & BTM_SEC_IN_MIN_16_DIGIT_PIN)))) {
        p_device->sec_rec.sec_flags &=
                ~(BTM_SEC_LINK_KEY_KNOWN | BTM_SEC_LINK_KEY_AUTHED | BTM_SEC_AUTHENTICATED);
      }

      btm_sec_wait_and_start_authentication(p_device);
      return tBTM_STATUS::BTM_CMD_STARTED;
    }
  }

  /* If connection is not encrypted and encryption is required */
  /* start encryption and return PENDING to the caller */
  if (!(p_device->sec_rec.sec_flags & BTM_SEC_ENCRYPTED) &&
      ((p_device->IsLocallyInitiated() &&
        (p_device->sec_rec.security_required & BTM_SEC_OUT_ENCRYPT)) ||
       (!p_device->IsLocallyInitiated() &&
        (p_device->sec_rec.security_required & BTM_SEC_IN_ENCRYPT))) &&
      (p_device->hci_handle != HCI_INVALID_HANDLE)) {
    log::verbose("Security Manager: Start encryption");

    btsnd_hcic_set_conn_encrypt(p_device->hci_handle, true);
    p_device->sec_rec.classic_link = tSECURITY_STATE::ENCRYPTING;
    return tBTM_STATUS::BTM_CMD_STARTED;
  } else {
    log::debug("Encryption not required");
  }

  if ((p_device->sec_rec.security_required & BTM_SEC_MODE4_LEVEL4) &&
      (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
    log::verbose(
            "Security Manager: SC only service, but link key type is 0x{:02x} "
            "-security failure",
            p_device->sec_rec.link_key_type);
    return tBTM_STATUS::BTM_FAILED_ON_SECURITY;
  }

  if (access_secure_service_from_temp_bond(p_device, p_device->IsLocallyInitiated(),
                                           p_device->sec_rec.security_required)) {
    log::error("Trying to access a secure service from a temp bonding, rejecting");
    return tBTM_STATUS::BTM_FAILED_ON_SECURITY;
  }

  /* All required  security procedures already established */
  p_device->sec_rec.security_required &= ~(BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_IN_AUTHENTICATE |
                                           BTM_SEC_OUT_ENCRYPT | BTM_SEC_IN_ENCRYPT);

  log::verbose("Security Manager: access granted");

  return tBTM_STATUS::BTM_SUCCESS;
}

/*******************************************************************************
 *
 * Function         btm_sec_start_get_name
 *
 * Description      This function is called to start get name procedure
 *
 * Returns          true if started
 *
 ******************************************************************************/
static bool btm_sec_start_get_name(BtmDevice* p_device) {
  if (!get_btm_client_interface().local.BTM_IsDeviceUp()) {
    return false;
  }

  p_device->sec_rec.classic_link = tSECURITY_STATE::GETTING_NAME;

  /* 0 and NULL are as timeout and callback params because they are not used in
   * security get name case */
  bluetooth::shim::ACL_RemoteNameRequest(p_device->bd_addr, HCI_PAGE_SCAN_REP_MODE_R1,
                                         HCI_MANDATARY_PAGE_SCAN_MODE,
                                         com_android_bluetooth_flags_use_cached_clock_offset()
                                                 ? BTM_GetCachedClockOffset(p_device->bd_addr)
                                                 : 0);
  return true;
}

/*******************************************************************************
 *
 * Function         btm_sec_wait_and_start_authentication
 *
 * Description      This function is called to add an alarm to wait and start
 *                  authentication
 *
 ******************************************************************************/
static void btm_sec_wait_and_start_authentication(BtmDevice* p_device) {
  int32_t delay_auth = osi_property_get_int32("bluetooth.btm.sec.delay_auth_ms.value", 0);

  /* Overwrite the system-wide authentication delay if device-specific
   * interoperability delay is needed. */
  if (interop_match_addr(INTEROP_DELAY_AUTH, p_device->bd_addr) ||
      interop_match_name(INTEROP_DELAY_AUTH,
                         reinterpret_cast<char const*>(p_device->sec_bd_name))) {
    delay_auth = BTM_SEC_START_AUTH_DELAY;
  }

  BtStatus status =
          do_in_main_thread_delayed(base::BindOnce(btm_sec_auth_timer_timeout, p_device->bd_addr),
                                    std::chrono::milliseconds(delay_auth));
  if (!status) {
    log::error("do_in_main_thread_delayed failed. directly calling");
    btm_sec_auth_timer_timeout(p_device->bd_addr);
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_auth_timer_timeout
 *
 * Description      called after wait timeout to request authentication
 *
 ******************************************************************************/
static void btm_sec_auth_timer_timeout(RawAddress bd_addr) {
  BtmDevice* p_device = btm_get_dev(bd_addr);

  if (p_device == nullptr) {
    log::info("invalid device or not found");
  } else if (btm_dev_authenticated(p_device)) {
    log::info("device is already authenticated");
    if (p_device->sec_rec.p_callback) {
      (*p_device->sec_rec.p_callback)(p_device->bd_addr, BT_TRANSPORT_BR_EDR,
                                      p_device->sec_rec.p_ref_data, tBTM_STATUS::BTM_SUCCESS);
    }
  } else if (p_device->sec_rec.classic_link == tSECURITY_STATE::AUTHENTICATING) {
    log::info("device is in the process of authenticating");
  } else {
    log::info("starting authentication");
    p_device->sec_rec.classic_link = tSECURITY_STATE::AUTHENTICATING;
    btsnd_hcic_auth_request(p_device->hci_handle);
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_collision_timeout
 *
 * Description      Encryption could not start because of the collision
 *                  try to do it again
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_collision_timeout(void* /* data */) {
  log::verbose("restaring security process after collision");

  tBTM_STATUS status = btm_sec_execute_procedure(BtmSecurity::Get().p_collided_dev_);

  /* If result is pending reply from the user or from the device is pending */
  if (status != tBTM_STATUS::BTM_CMD_STARTED) {
    /* There is no next procedure or start of procedure failed, notify the
     * waiting layer */
    btm_sec_dev_rec_cback_event(BtmSecurity::Get().p_collided_dev_, status, false);
  }
}

/*******************************************************************************
 *
 * Function         btm_send_link_key_notif
 *
 * Description      Call the link key callback.
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_send_link_key_notif(BtmDevice* p_device) {
  (BtmSecurity::Get().app_->link_key_callback)(p_device->bd_addr, p_device->sec_bd_name,
                                               p_device->sec_rec.link_key,
                                               p_device->sec_rec.link_key_type, false);
}

/*******************************************************************************
 *
 * Function         btm_restore_mode
 *
 * Description      This function returns the security mode to previous setting
 *                  if it was changed during bonding.
 *
 *
 * Parameters:      void
 *
 ******************************************************************************/
static void btm_restore_mode(void) {
  if (!com_android_bluetooth_flags_security_mode_3_pairing() &&
      BtmSecurity::Get().security_mode_changed_) {
    BtmSecurity::Get().security_mode_changed_ = false;
    btsnd_hcic_write_auth_enable(false);
  }

  if (!com_android_bluetooth_flags_local_pin_key_type() && BtmSecurity::Get().pin_type_changed_) {
    BtmSecurity::Get().pin_type_changed_ = false;
    btsnd_hcic_write_pin_type(BtmSecurity::Get().cfg_.pin_type);
  }
}

/*******************************************************************************
 *
 * Function         change_pairing_state
 *
 * Description      This function is called to change pairing state
 *
 ******************************************************************************/
void BtmSecurity::change_pairing_state(tBTM_PAIRING_STATE new_state) {
  tBTM_PAIRING_STATE old_state = pairing_state_;

  log::debug("Pairing state changed {} => {} pairing_flags:0x{:x}",
             btm_pair_state_descr(pairing_state_), btm_pair_state_descr(new_state), pairing_flags_);

  if (pairing_state_ != new_state) {
    BTM_LogHistory(kBtmLogTag, BtmSecurity::Get().link_spec_.addrt.bda, "Pairing state changed",
                   std::format("{} => {}", btm_pair_state_descr(pairing_state_),
                               btm_pair_state_descr(new_state)));
  }
  pairing_state_ = new_state;

  if (new_state == BTM_PAIR_STATE_IDLE) {
    alarm_cancel(pairing_timer_);

    pairing_flags_ = 0;
    pin_code_len_ = 0;

    /* Make sure the the lcb shows we are not bonding */
    l2cu_update_lcb_4_bonding(link_spec_.addrt.bda, false);

    btm_restore_mode();
    btm_sec_check_pending_reqs();
    BtmSecurity::Get().ResetLinkKeyRequestTimer();

    link_spec_ = {};
    link_spec_.addrt.bda = RawAddress::kAny;
  } else {
    /* If transitioning out of idle, mark the lcb as bonding */
    if (old_state == BTM_PAIR_STATE_IDLE) {
      l2cu_update_lcb_4_bonding(link_spec_.addrt.bda, true);
    }

    alarm_set_on_mloop(BtmSecurity::Get().pairing_timer_, BTM_SEC_TIMEOUT_VALUE * 1000,
                       btm_sec_pairing_timeout, NULL);
  }
}

/*******************************************************************************
 *
 * Function         btm_sec_dev_rec_cback_event
 * Description      This function calls the callback function with the given
 *                  result and clear the callback function.
 *
 * Parameters:      void
 *
 ******************************************************************************/
void btm_sec_dev_rec_cback_event(BtmDevice* p_device, tBTM_STATUS btm_status,
                                 bool is_le_transport) {
  log::assert_that(p_device != nullptr, "assert failed: p_device != nullptr");
  log::debug("transport={}, btm_status={}", is_le_transport ? "le" : "classic",
             btm_status_text(btm_status));

  tBTM_SEC_CALLBACK* p_callback = p_device->sec_rec.p_callback;
  p_device->sec_rec.p_callback = NULL;
  if (p_callback != nullptr) {
    if (is_le_transport) {
      (*p_callback)(p_device->ble.pseudo_addr, BT_TRANSPORT_LE, p_device->sec_rec.p_ref_data,
                    btm_status);
    } else {
      (*p_callback)(p_device->bd_addr, BT_TRANSPORT_BR_EDR, p_device->sec_rec.p_ref_data,
                    btm_status);
    }
  }

  btm_sec_check_pending_reqs();
}

void btm_sec_cr_loc_oob_data_cback_event(const RawAddress& address,
                                         tSMP_LOC_OOB_DATA loc_oob_data) {
  tBTM_LE_EVT_DATA evt_data = {
          .local_oob_data = loc_oob_data,
  };
  BTM_BLE_SEC_CALLBACK(BTM_LE_SC_LOC_OOB_EVT, address, &evt_data);
}

/*******************************************************************************
 *
 * Function         btm_sec_queue_service_access_request
 *
 * Description      Return state description for tracing
 *
 ******************************************************************************/
static bool btm_sec_queue_service_access_request(const RawAddress& bd_addr, uint16_t psm,
                                                 bool is_orig, uint16_t security_required,
                                                 tBTM_SEC_CALLBACK* callback, void* ref) {
  if (callback == nullptr) {
    log::warn("Callback is null, device: {}, psm: 0x{:04x}", bd_addr, psm);
    return false;
  }
  tBTM_SERVICE_ACCESS_REQ req = {
          .bd_addr = bd_addr,
          .psm = psm,
          .is_orig = is_orig,
          .rfcomm_security_requirement = security_required,
          .callback = callback,
          .ref = ref,
  };

  // Insert the request only if it's not already present
  auto comparator = [req](const tBTM_SERVICE_ACCESS_REQ& other) {
    return req.bd_addr == other.bd_addr && req.psm == other.psm && req.is_orig == other.is_orig &&
           req.rfcomm_security_requirement == other.rfcomm_security_requirement &&
           req.callback == other.callback && req.ref == other.ref;
  };
  if (std::find_if(BtmSecurity::Get().service_access_q_.begin(),
                   BtmSecurity::Get().service_access_q_.end(),
                   comparator) != BtmSecurity::Get().service_access_q_.end()) {
    log::verbose("Service access request already present, device: {}, psm: 0x{:04x}", bd_addr, psm);
    return false;
  }

  BtmSecurity::Get().service_access_q_.push_back(req);
  return true;
}

// TODO (b/460502961): Remove this function when the flag security_mode_3_pairing is shipped
static bool btm_sec_check_prefetch_pin(BtmDevice* p_device) {
  if (com_android_bluetooth_flags_security_mode_3_pairing()) {
    return false;
  }

  uint8_t major = (uint8_t)(p_device->dev_class[1] & BTM_COD_MAJOR_CLASS_MASK);
  uint8_t minor = (uint8_t)(p_device->dev_class[2] & BTM_COD_MINOR_CLASS_MASK);

  if (major == BTM_COD_MAJOR_AUDIO &&
      (minor == BTM_COD_MINOR_CONFM_HANDSFREE || minor == BTM_COD_MINOR_CAR_AUDIO)) {
    log::verbose("Skipping pre-fetch PIN for carkit COD Major: 0x{:02x} Minor: 0x{:02x}", major,
                 minor);

    if (!BtmSecurity::Get().security_mode_changed_) {
      BtmSecurity::Get().security_mode_changed_ = true;
      btsnd_hcic_write_auth_enable(true);
    }
    return false;
  }

  BtmSecurity::Get().change_pairing_state(BTM_PAIR_STATE_WAIT_LOCAL_PIN);
  p_device->sec_rec.pairing_algorithm = PairingAlgorithm::BREDR_LEGACY;

  /* If we got a PIN, use that, else try to get one */
  if (BtmSecurity::Get().pin_code_len_) {
    btm_pin_code_reply(p_device->bd_addr, tBTM_STATUS::BTM_SUCCESS,
                       BtmSecurity::Get().pin_code_len_, BtmSecurity::Get().pin_code_);
    return true;
  }

  /* Pin was not supplied - pre-fetch pin code now */
  if ((BtmSecurity::Get().pairing_flags_ & BTM_PAIR_FLAGS_PIN_REQD) == 0) {
    log::verbose("PIN code callback called");
    if (get_btm_client_interface().peer.BTM_IsAclConnectionUp(p_device->bd_addr,
                                                              BT_TRANSPORT_BR_EDR)) {
      BtmSecurity::Get().pairing_flags_ |= BTM_PAIR_FLAGS_PIN_REQD;
    }
    (BtmSecurity::Get().app_->pin_callback)(
            p_device->bd_addr, p_device->dev_class, p_device->sec_bd_name,
            p_device->sec_rec.required_security_flags_for_pairing & BTM_SEC_IN_MIN_16_DIGIT_PIN,
            p_device->sec_rec.pairing_algorithm);
  }

  return true;
}

static void btm_sec_queue_encrypt_request(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                                          tBTM_BLE_SEC_ACT sec_act, tBTM_SEC_CALLBACK* callback,
                                          void* ref) {
  if (callback == nullptr) {
    log::warn("Callback is null, device: {}, transport: {}, sec_act: 0x{:x}", bd_addr, transport,
              sec_act);
    return;
  }
  tBTM_SEC_REQ req = {
          .bd_addr = bd_addr,
          .transport = transport,
          .sec_act = sec_act,
          .callback = callback,
          .ref = ref,
  };

  // Insert the request only if it's not already present
  auto comparator = [req](const tBTM_SEC_REQ& other) {
    return req.bd_addr == other.bd_addr && req.transport == other.transport &&
           req.sec_act == other.sec_act && req.callback == other.callback && req.ref == other.ref;
  };
  if (std::find_if(BtmSecurity::Get().enc_request_q_.begin(),
                   BtmSecurity::Get().enc_request_q_.end(),
                   comparator) != BtmSecurity::Get().enc_request_q_.end()) {
    log::debug("Encryption request already present, device: {}, transport: {}, sec_act: 0x{:x}",
               bd_addr, transport, sec_act);
    return;
  }
  BtmSecurity::Get().enc_request_q_.push_back(req);
}

/*******************************************************************************
 *
 * Function         btm_sec_check_pending_enc_req
 *
 * Description      This function is called to send pending encryption callback
 *                  if waiting
 *
 * Returns          void
 *
 ******************************************************************************/
static void btm_sec_check_pending_enc_req(BtmDevice* p_device, tBT_TRANSPORT transport,
                                          bool encrypted) {
  // Remove all the encryption requests for the given device and transport, and inform the callers.
  // If the link is encrypted but the link key is not authenticated, retry the security procedure.
  auto predicate = [p_device, transport, encrypted](const tBTM_SEC_REQ& req) {
    if (req.transport != transport) {
      return false;
    }

    if (req.bd_addr != p_device->bd_addr && req.bd_addr != p_device->ble.pseudo_addr &&
        req.bd_addr != p_device->ble.identity_address_with_type.bda) {
      return false;
    }

    if (encrypted && req.sec_act == BTM_BLE_SEC_ENCRYPT_MITM &&
        !p_device->sec_rec.is_le_link_key_authenticated()) {
      // Link encrypted but link key is not authenticated, retry the security procedure
      log::info("Retrying encryption request: addr={}, transport={}, sec_act=0x{:x}",
                p_device->bd_addr, transport, req.sec_act);
      tBTM_STATUS res =
              btm_set_encryption(p_device->bd_addr, transport, req.callback, req.ref, req.sec_act);
      if (res != tBTM_STATUS::BTM_SUCCESS && res != tBTM_STATUS::BTM_CMD_STARTED) {
        log::warn(
                "Failed to retry encryption request: addr={}, transport={}, sec_act=0x{:x}, res={}",
                p_device->bd_addr, transport, req.sec_act, btm_status_text(res));
      }
    } else {
      tBTM_STATUS res = encrypted ? tBTM_STATUS::BTM_SUCCESS : tBTM_STATUS::BTM_ERR_PROCESSING;
      req.callback(req.bd_addr, req.transport, req.ref, res);
    }

    return true;
  };

  std::erase_if(BtmSecurity::Get().enc_request_q_, predicate);
}

/*******************************************************************************
 *
 * Function         btm_sec_set_serv_level4_flags
 *
 * Description      This function is called to set security mode 4 level 4
 *                  flags.
 *
 * Returns          service security requirements updated to include secure
 *                  connections only mode.
 *
 ******************************************************************************/
static uint16_t btm_sec_set_serv_level4_flags(uint16_t cur_security, bool outgoing) {
  uint16_t sec_level4_flags = outgoing ? BTM_SEC_OUT_LEVEL4_FLAGS : BTM_SEC_IN_LEVEL4_FLAGS;

  return cur_security | sec_level4_flags;
}

/*******************************************************************************
 *
 * Function         btm_sec_clear_ble_keys
 *
 * Description      This function is called to clear out the BLE keys.
 *                  Typically when devices are removed in btm_sec_delete_device,
 *                  or when a new BT Link key is generated.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_clear_ble_keys(BtmDevice* p_device) {
  log::verbose("Clearing BLE Keys");
  memset(&p_device->sec_rec.ble_keys, 0, sizeof(tBTM_SEC_BLE_KEYS));

  btm_ble_resolving_list_remove_dev(p_device);
}

/*******************************************************************************
 *
 * Function         btm_sec_use_smp_br_chnl
 *
 * Description      The function checks if SMP BR connection can be used with
 *                  the peer.
 *                  Is called when authentication for dedicated bonding is
 *                  successfully completed.
 *
 * Returns          true - if SMP BR connection can be used (the link key is
 *                         generated from P-256 and the peer supports Security
 *                         Manager over BR).
 *
 ******************************************************************************/
static bool btm_sec_use_smp_br_chnl(BtmDevice* p_device) {
  uint32_t ext_feat;
  uint8_t chnl_mask[L2CAP_FIXED_CHNL_ARRAY_SIZE];

  log::verbose("link_key_type = 0x{:x}", p_device->sec_rec.link_key_type);

  if ((p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_UNAUTH_COMB_P_256) &&
      (p_device->sec_rec.link_key_type != BTM_LKEY_TYPE_AUTH_COMB_P_256)) {
    return false;
  }

  if (!stack::l2cap::get_interface().L2CA_GetPeerFeatures(p_device->bd_addr, &ext_feat,
                                                          chnl_mask)) {
    return false;
  }

  if (!(chnl_mask[0] & L2CAP_FIXED_CHNL_SMP_BR_BIT)) {
    return false;
  }

  return true;
}

/*******************************************************************************
 *
 * Function         btm_sec_set_peer_sec_caps
 *
 * Description      This function is called to set sm4 and rmt_sec_caps fields
 *                  based on the available peer device features.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_set_peer_sec_caps(uint16_t hci_handle, bool ssp_supported, bool host_sc_supported,
                               bool controller_sc_supported, bool hci_role_switch_supported,
                               bool br_edr_supported, bool le_supported) {
  BtmDevice* p_device = btm_get_dev_by_handle(hci_handle);
  if (p_device == nullptr) {
    return;
  }

  // Drop the connection here if the remote attempts to downgrade from Secure
  // Connections mode.
  if (p_device->is_device_type_br_edr() && p_device->sec_rec.is_bonded() &&
      btm_sec_is_enc_algo_downgrade(hci_handle, host_sc_supported, controller_sc_supported)) {
    acl_set_disconnect_reason(HCI_ERR_HOST_REJECT_SECURITY);
    btm_sec_send_hci_disconnect(p_device, HCI_ERR_AUTH_FAILURE, hci_handle,
                                "attempted to downgrade from Secure Connections mode");
    return;
  }

  p_device->remote_feature_received = true;
  p_device->remote_supports_hci_role_switch = hci_role_switch_supported;

  uint8_t req_pend = (p_device->sm4 & BTM_SM4_REQ_PEND);

  if (!(p_device->sec_rec.sec_flags & BTM_SEC_NAME_KNOWN) || p_device->outgoing) {
    tBTM_STATUS btm_status = btm_sec_execute_procedure(p_device);
    if (btm_status != tBTM_STATUS::BTM_CMD_STARTED) {
      log::warn("Security procedure not started! status:{}", btm_status_text(btm_status));
      btm_sec_dev_rec_cback_event(p_device, btm_status, false);
    }
  }

  /* Store the Peer Security Capabilities (in SM4 and rmt_sec_caps) */
  if ((BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SP ||
       BtmSecurity::Get().security_mode_ == BTM_SEC_MODE_SC) &&
      ssp_supported) {
    p_device->sm4 = BTM_SM4_TRUE;
    p_device->remote_host_supports_secure_connections = host_sc_supported;
    p_device->remote_controller_supports_secure_connections = controller_sc_supported;
  } else {
    p_device->sm4 = BTM_SM4_KNOWN;
    p_device->remote_host_supports_secure_connections = false;
    p_device->remote_controller_supports_secure_connections = false;
  }

  // To determine the pairing algorithm, check remote device features, and local controller
  // features. For local host, refer to local support bits, locally SC supported.
  if (!p_device->sec_rec.is_bonded()) {
    if (bluetooth::shim::GetController()->SupportsSecureConnections()) {
      if (p_device->remote_host_supports_secure_connections &&
          p_device->remote_controller_supports_secure_connections) {
        p_device->sec_rec.pairing_algorithm = PairingAlgorithm::SC;
      } else {
        p_device->sec_rec.pairing_algorithm = PairingAlgorithm::SSP;
      }
    } else if (bluetooth::shim::GetController()->SupportsSimplePairing()) {
      p_device->sec_rec.pairing_algorithm = PairingAlgorithm::SSP;
    } else {
      p_device->sec_rec.pairing_algorithm = PairingAlgorithm::BREDR_LEGACY;
    }
  }

  if (p_device->remote_features_needed) {
    log::debug("Now device in SC Only mode, waiting for peer remote features!");
    btm_io_capabilities_req(p_device->bd_addr);
    p_device->remote_features_needed = false;
  }

  if (req_pend) {
    /* Request for remaining Security Features (if any) */
    l2cu_resubmit_pending_sec_req(&p_device->bd_addr);
  }

  p_device->remote_supports_bredr = br_edr_supported;
  p_device->remote_supports_ble = le_supported;
}

void btm_sec_hci_delete_stored_link_key(const RawAddress& bd_addr) {
  /* Read and Write stored link key stems from a legacy use-case. */
  /* If the controller doesn't support this then just return success */
  if (!bluetooth::shim::GetController()->IsSupported(
              bluetooth::hci::OpCode::DELETE_STORED_LINK_KEY)) {
    log::verbose("DELETE_STORED_LINK_KEY not supported");
    return;
  }
  btsnd_hcic_delete_stored_key(bd_addr, false);
}

bool btm_is_bond_lost(const RawAddress& bd_addr) {
  const BtmDevice* p_device = btm_find_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("btm_is_bond_lost() - no dev CB");
    return false;
  }

  return p_device->bond_lost;
}

void btm_update_bond_lost(const RawAddress& bd_addr, bool bond_lost) {
  BtmDevice* p_device = btm_get_dev(bd_addr);
  if (p_device == nullptr) {
    log::error("btm_update_bond_lost() - no dev CB");
    return;
  }

  p_device->bond_lost = bond_lost;
}

uint8_t btm_sec_get_min_enc_key_size() {
  static uint8_t min_key_size = (uint8_t)std::min(
          std::max(android::sysprop::bluetooth::Gap::min_key_size(), MIN_KEY_SIZE), MAX_KEY_SIZE);
  return min_key_size;
}
