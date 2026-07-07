/******************************************************************************
 *
 *  Copyright (c) 2014 The Android Open Source Project
 *  Copyright 2009-2012 Broadcom Corporation
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
 *  Filename:      btif_storage.c
 *
 *  Description:   Stores the local BT adapter and remote device properties in
 *                 NVRAM storage, typically as xml file in the
 *                 mobile's filesystem
 *
 *
 */

#define LOG_TAG "bt_btif_storage"
#include "btif/include/btif_storage.h"

#include <alloca.h>
#include <bluetooth/log.h>
#include <com_android_bluetooth_flags.h>
#ifndef TARGET_FLOSS
#include <cutils/multiuser.h>
#endif
#include <bluetooth/types/ble_address_with_type.h>
#include <bluetooth/types/bt_octets.h>
#include <bluetooth/types/uuid.h>
#include <string.h>
#include <time.h>

#include <unordered_set>
#include <vector>

#include "bta/include/bta_gatts_co.h"
#include "btif/include/btif_api.h"
#include "btif/include/btif_config.h"
#include "btif/include/btif_dm.h"
#include "btif/include/btif_util.h"
#include "btif/include/core_callbacks.h"
#include "btif/include/stack_manager_t.h"
#include "hardware/bluetooth.h"
#include "hci/controller.h"
#include "internal_include/bt_target.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "main/shim/shim.h"
#include "stack/include/bt_uuid16.h"
#include "storage/config_keys.h"

/* This is a local property to add a device found */
#define BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP 0xFF

// Default user ID to use when real user ID is not available
#define BTIF_STORAGE_RESTRICTED_USER_ID_DEFAULT 1

using base::BindOnce;
using bluetooth::Uuid;
using namespace bluetooth;

/*******************************************************************************
 *  Constants & Macros
 ******************************************************************************/

struct BtifStorageKey {
  uint8_t type;
  const std::string& name;
  uint8_t size;
};
static const BtifStorageKey BTIF_STORAGE_LE_KEYS[] = {
        {BTM_LE_KEY_PENC, BTIF_STORAGE_KEY_LE_KEY_PENC, sizeof(tBTM_LE_PENC_KEYS)},
        {BTM_LE_KEY_PID, BTIF_STORAGE_KEY_LE_KEY_PID, sizeof(tBTM_LE_PID_KEYS)},
        {BTM_LE_KEY_PCSRK, BTIF_STORAGE_KEY_LE_KEY_PCSRK, sizeof(tBTM_LE_PCSRK_KEYS)},
        {BTM_LE_KEY_LENC, BTIF_STORAGE_KEY_LE_KEY_LENC, sizeof(tBTM_LE_LENC_KEYS)},
        {BTM_LE_KEY_LCSRK, BTIF_STORAGE_KEY_LE_KEY_LCSRK, sizeof(tBTM_LE_LCSRK_KEYS)},
        {BTM_LE_KEY_LID, BTIF_STORAGE_KEY_LE_KEY_LID, sizeof(tBTM_LE_PID_KEYS)},
};
static const BtifStorageKey BTIF_STORAGE_LOCAL_LE_KEYS[] = {
        {BTIF_DM_LE_LOCAL_KEY_IR, BTIF_STORAGE_KEY_LE_LOCAL_KEY_IR, sizeof(Octet16)},
        {BTIF_DM_LE_LOCAL_KEY_IRK, BTIF_STORAGE_KEY_LE_LOCAL_KEY_IRK, sizeof(Octet16)},
        {BTIF_DM_LE_LOCAL_KEY_DHK, BTIF_STORAGE_KEY_LE_LOCAL_KEY_DHK, sizeof(Octet16)},
        {BTIF_DM_LE_LOCAL_KEY_ER, BTIF_STORAGE_KEY_LE_LOCAL_KEY_ER, sizeof(Octet16)},
};

/*******************************************************************************
 *  Internal Functions
 ******************************************************************************/

static bool btif_has_ble_keys(const std::string& bdstr);

/*******************************************************************************
 *  Static functions
 ******************************************************************************/

static int btif_storage_get_user_id() {
#ifdef TARGET_FLOSS
  return BTIF_STORAGE_RESTRICTED_USER_ID_DEFAULT;
#else
  return multiuser_get_user_id(getuid());
#endif
}

static void btif_storage_set_mode(const RawAddress& addr) {
  std::string bdstr = addr.ToString();
  if (GetInterfaceToProfiles()->config->isRestrictedMode()) {
    int user_id = btif_storage_get_user_id();
    log::info("{} added by user {}, will be removed on exiting restricted mode", addr, user_id);
    btif_config_set_int(bdstr, BTIF_STORAGE_KEY_RESTRICTED, user_id);
  }
}

static bool prop2cfg(const RawAddress* addr, bt_property_t* prop) {
  if (!bluetooth::shim::is_gd_stack_started_up()) {
    log::error("is_gd_stack_started_up=false");
    return false;
  }

  std::string bdstr;
  if (addr) {
    bdstr = addr->ToString();
  }

  char value[1024];
  if (prop->len <= 0 || prop->len > static_cast<int>(sizeof(value)) - 1) {
    log::warn(
            "Unable to save property to configuration file type:{},  len:{} is "
            "invalid",
            prop->type, prop->len);
    return false;
  }
  switch (prop->type) {
    case BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP:
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_TIMESTAMP, static_cast<int>(time(NULL)));
      break;
    case BT_PROPERTY_BDNAME: {
      if (!addr) {
        log::fatal("Invalid set/get name within native config");
      }
      int name_length = prop->len > BD_NAME_LEN ? BD_NAME_LEN : prop->len;
      strncpy(value, reinterpret_cast<char*>(prop->val), name_length);
      value[name_length] = '\0';
      if (addr) {
        btif_config_set_str(bdstr, BTIF_STORAGE_KEY_NAME, value);
      } else {
        btif_config_set_str(BTIF_STORAGE_SECTION_ADAPTER, BTIF_STORAGE_KEY_NAME, value);
      }
      break;
    }
    case BT_PROPERTY_REMOTE_FRIENDLY_NAME:
      strncpy(value, reinterpret_cast<char*>(prop->val), prop->len);
      value[prop->len] = '\0';
      btif_config_set_str(bdstr, BTIF_STORAGE_KEY_ALIAS, value);
      break;
    case BT_PROPERTY_ADAPTER_DISCOVERABLE_TIMEOUT:
      btif_config_set_int(BTIF_STORAGE_SECTION_ADAPTER, BTIF_STORAGE_KEY_DISC_TIMEOUT,
                          *reinterpret_cast<int*>(prop->val));
      break;
    case BT_PROPERTY_CLASS_OF_DEVICE:
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_DEV_CLASS, *reinterpret_cast<int*>(prop->val));
      break;
    case BT_PROPERTY_TYPE_OF_DEVICE:
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_DEV_TYPE, *reinterpret_cast<int*>(prop->val));
      break;
    case BT_PROPERTY_UUIDS:
    case BT_PROPERTY_UUIDS_LE: {
      std::string val;
      size_t cnt = (prop->len) / sizeof(Uuid);
      for (size_t i = 0; i < cnt; i++) {
        val += (reinterpret_cast<Uuid*>(prop->val) + i)->ToString();
        if ((i + 1) < cnt) {
          val += " ";
        }
      }
      std::string key = (prop->type == BT_PROPERTY_UUIDS_LE) ? BTIF_STORAGE_KEY_REMOTE_SERVICE_LE
                                                             : BTIF_STORAGE_KEY_REMOTE_SERVICE;
      btif_config_set_str(bdstr, key, val);
    } break;

    case BT_PROPERTY_REMOTE_VERSION_INFO: {
      bt_remote_version_t* info = reinterpret_cast<bt_remote_version_t*>(prop->val);

      if (!info) {
        return false;
      }

      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_MFCT, info->manufacturer);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_VER, info->version);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_SUBVER, info->sub_ver);
    } break;
    case BT_PROPERTY_APPEARANCE: {
      int val = *reinterpret_cast<uint16_t*>(prop->val);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_APPEARANCE, val);
    } break;
    case BT_PROPERTY_VENDOR_PRODUCT_INFO: {
      bt_vendor_product_info_t* info = reinterpret_cast<bt_vendor_product_info_t*>(prop->val);
      if (!info) {
        return false;
      }

      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_VENDOR_ID_SOURCE, info->vendor_id_src);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_VENDOR_ID, info->vendor_id);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_PRODUCT_ID, info->product_id);
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_VERSION, info->version);
    } break;
    case BT_PROPERTY_REMOTE_MODEL_NUM: {
      strncpy(value, reinterpret_cast<char*>(prop->val), prop->len);
      value[prop->len] = '\0';
      btif_config_set_str(bdstr, BTIF_STORAGE_KEY_DIS_MODEL_NUM, value);
    } break;
    case BT_PROPERTY_REMOTE_MAX_SESSION_KEY_SIZE:
      btif_config_set_int(bdstr, BTIF_STORAGE_KEY_MAX_SESSION_KEY_SIZE,
                          *reinterpret_cast<uint8_t*>(prop->val));
      break;
    default:
      log::error("Unknown prop type:{}", prop->type);
      return false;
  }

  return true;
}

static bool cfg2prop(const RawAddress* addr, bt_property_t* prop) {
  if (!bluetooth::shim::is_gd_stack_started_up()) {
    log::error("is_gd_stack_started_up=false");
    return false;
  }

  std::string bdstr;
  if (addr) {
    bdstr = addr->ToString();
  }
  if (prop->len <= 0) {
    log::warn("Invalid property read from configuration file type:{}, len:{}", prop->type,
              prop->len);
    return false;
  }
  bool ret = false;
  switch (prop->type) {
    case BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP:
      if (prop->len >= static_cast<int>(sizeof(int))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_TIMESTAMP,
                                  reinterpret_cast<int*>(prop->val));
      }
      break;
    case BT_PROPERTY_BDNAME: {
      if (!addr) {
        log::fatal("Invalid set/get name within native config");
      }
      int len = prop->len;
      if (addr) {
        ret = btif_config_get_str(bdstr, BTIF_STORAGE_KEY_NAME, reinterpret_cast<char*>(prop->val),
                                  &len);
      } else {
        ret = btif_config_get_str(BTIF_STORAGE_SECTION_ADAPTER, BTIF_STORAGE_KEY_NAME,
                                  reinterpret_cast<char*>(prop->val), &len);
      }
      if (ret && len > 1 && len <= prop->len) {  // empty names have a len of 1
        prop->len = len - 1;
      } else {
        prop->len = 0;
        ret = false;
      }
      break;
    }
    case BT_PROPERTY_REMOTE_FRIENDLY_NAME: {
      int len = prop->len;
      ret = btif_config_get_str(bdstr, BTIF_STORAGE_KEY_ALIAS, reinterpret_cast<char*>(prop->val),
                                &len);
      if (ret && len && len <= prop->len) {
        prop->len = len - 1;
      } else {
        prop->len = 0;
        ret = false;
      }
      break;
    }
    case BT_PROPERTY_ADAPTER_DISCOVERABLE_TIMEOUT:
      if (prop->len >= static_cast<int>(sizeof(int))) {
        ret = btif_config_get_int(BTIF_STORAGE_SECTION_ADAPTER, BTIF_STORAGE_KEY_DISC_TIMEOUT,
                                  reinterpret_cast<int*>(prop->val));
      }
      break;
    case BT_PROPERTY_CLASS_OF_DEVICE:
      if (prop->len >= static_cast<int>(sizeof(int))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_CLASS,
                                  reinterpret_cast<int*>(prop->val));
      }
      break;
    case BT_PROPERTY_TYPE_OF_DEVICE:
      if (prop->len >= static_cast<int>(sizeof(int))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_TYPE,
                                  reinterpret_cast<int*>(prop->val));
      }
      break;
    case BT_PROPERTY_UUIDS:
    case BT_PROPERTY_UUIDS_LE: {
      char value[1280];
      int size = sizeof(value);

      std::string key = (prop->type == BT_PROPERTY_UUIDS_LE) ? BTIF_STORAGE_KEY_REMOTE_SERVICE_LE
                                                             : BTIF_STORAGE_KEY_REMOTE_SERVICE;

      if (btif_config_get_str(bdstr, key, value, &size)) {
        Uuid* p_uuid = reinterpret_cast<Uuid*>(prop->val);
        size_t num_uuids =
                btif_split_uuids_string(value, p_uuid, prop->len / sizeof(Uuid));
        prop->len = num_uuids * sizeof(Uuid);
        ret = true;
      } else {
        prop->val = NULL;
        prop->len = 0;
      }
    } break;

    case BT_PROPERTY_REMOTE_VERSION_INFO: {
      bt_remote_version_t* info = reinterpret_cast<bt_remote_version_t*>(prop->val);

      if (prop->len >= static_cast<int>(sizeof(bt_remote_version_t))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_MFCT, &info->manufacturer);

        if (ret) {
          ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_VER, &info->version);
        }

        if (ret) {
          ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_REMOTE_VER_SUBVER, &info->sub_ver);
        }
      }
    } break;

    case BT_PROPERTY_APPEARANCE: {
      int val;

      if (prop->len >= static_cast<int>(sizeof(uint16_t))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_APPEARANCE, &val);
        *reinterpret_cast<uint16_t*>(prop->val) = (uint16_t)val;
      }
    } break;

    case BT_PROPERTY_VENDOR_PRODUCT_INFO: {
      bt_vendor_product_info_t* info = reinterpret_cast<bt_vendor_product_info_t*>(prop->val);
      int val;

      if (prop->len >= static_cast<int>(sizeof(bt_vendor_product_info_t))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_VENDOR_ID_SOURCE, &val);
        info->vendor_id_src = static_cast<uint8_t>(val);

        if (ret) {
          ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_VENDOR_ID, &val);
          info->vendor_id = static_cast<uint16_t>(val);
        }
        if (ret) {
          ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_PRODUCT_ID, &val);
          info->product_id = static_cast<uint16_t>(val);
        }
        if (ret) {
          ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_VERSION, &val);
          info->version = static_cast<uint16_t>(val);
        }
      }
    } break;

    case BT_PROPERTY_REMOTE_MODEL_NUM: {
      int len = prop->len;
      ret = btif_config_get_str(bdstr, BTIF_STORAGE_KEY_DIS_MODEL_NUM,
                                reinterpret_cast<char*>(prop->val), &len);
      if (ret && len && len <= prop->len) {
        prop->len = len - 1;
      } else {
        prop->len = 0;
        ret = false;
      }
    } break;

    case BT_PROPERTY_REMOTE_ADDR_TYPE: {
      int val;

      if (prop->len >= static_cast<int>(sizeof(uint8_t))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_ADDR_TYPE, &val);
        *reinterpret_cast<uint8_t*>(prop->val) = (uint8_t)val;
      }
    } break;

    case BT_PROPERTY_REMOTE_MAX_SESSION_KEY_SIZE: {
      int val;

      if (prop->len >= static_cast<int>(sizeof(uint8_t))) {
        ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_MAX_SESSION_KEY_SIZE, &val);
        *reinterpret_cast<uint8_t*>(prop->val) = (uint8_t)val;
      }
    } break;

    default:
      log::error("Unknown prop type:{}", prop->type);
      return false;
  }
  return ret;
}

/*******************************************************************************
 *
 * Function         btif_in_fetch_bonded_device
 *
 * Description      Helper function to fetch the bonded devices
 *                  from NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if successful, BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_in_fetch_bonded_device(const std::string& bdstr) {
  bool bt_linkkey_file_found = false;

  LinkKey link_key;
  size_t size = link_key.size();
  if (btif_config_get_bin(bdstr, BTIF_STORAGE_KEY_LINK_KEY, link_key.data(), &size)) {
    int linkkey_type;
    if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LINK_KEY_TYPE, &linkkey_type)) {
      bt_linkkey_file_found = true;
    } else {
      bt_linkkey_file_found = false;
    }
  }
  if ((btif_in_fetch_bonded_ble_device(bdstr, false, NULL) != BT_STATUS_SUCCESS) &&
      (!bt_linkkey_file_found)) {
    return BT_STATUS_DEVICE_NOT_FOUND;
  }
  return BT_STATUS_SUCCESS;
}

/*******************************************************************************
 *
 * Function         btif_in_fetch_bonded_devices
 *
 * Description      Internal helper function to fetch the bonded devices
 *                  from NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if successful, BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
static bt_status_t btif_in_fetch_bonded_devices(btif_bonded_devices_t* p_bonded_devices, int add) {
  memset(p_bonded_devices, 0, sizeof(btif_bonded_devices_t));

  bool bt_linkkey_file_found = false;

  for (const auto& addr : btif_config_get_paired_devices()) {
    auto bdstr = addr.ToString();

    log::verbose("Remote device:{}", addr);
    LinkKey link_key;
    size_t size = sizeof(link_key);
    if (btif_config_get_bin(bdstr, BTIF_STORAGE_KEY_LINK_KEY, link_key.data(), &size)) {
      int linkkey_type;
      if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LINK_KEY_TYPE, &linkkey_type)) {
        if (add) {
          DEV_CLASS dev_class = {0, 0, 0};
          int cod;
          int pin_length = 0;
          if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_CLASS, &cod)) {
            dev_class = uint2devclass((uint32_t)cod);
          }
          btif_config_get_int(bdstr, BTIF_STORAGE_KEY_PIN_LENGTH, &pin_length);
          PairingType pairing_type =
                  btif_storage_get_bredr_pairing_type(addr).value_or(kPairingTypeNone);
          BTA_DmAddDevice(addr, dev_class, pairing_type, link_key,
                          static_cast<uint8_t>(linkkey_type), pin_length);

          int device_type = BT_DEVICE_TYPE_UNKNOWN;
          if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_TYPE, &device_type) &&
              (device_type == BT_DEVICE_TYPE_DUMO)) {
            btif_gatts_add_bonded_dev_from_nv(addr);
          }
        }
        bt_linkkey_file_found = true;

        int addr_type_int = BLE_ADDR_PUBLIC;
        btif_config_get_int(bdstr, BTIF_STORAGE_KEY_ADDR_TYPE, &addr_type_int);
        tBLE_ADDR_TYPE addr_type = static_cast<tBLE_ADDR_TYPE>(addr_type_int);

        if (p_bonded_devices->num_devices < BTM_SEC_MAX_DEVICE_RECORDS) {
          p_bonded_devices->devices[p_bonded_devices->num_devices++] = {addr_type, addr};
        } else {
          log::warn("Exceed the max number of bonded devices");
        }
      } else {
        bt_linkkey_file_found = false;
      }
    }
    if (!btif_in_fetch_bonded_ble_device(bdstr, add, p_bonded_devices) && !bt_linkkey_file_found) {
      log::verbose("No link key or ble key found for device:{}", addr);
    }
  }
  return BT_STATUS_SUCCESS;
}

/*******************************************************************************
 *
 * Function         btif_in_load_bonded_device
 *
 * Description      Helper function to load the bonded device from NVRAM, and add it to the BTA.
 *                  This function loads the bonded device and basically refreshes the device
 *                  information.
 *
 * Returns          None
 *
 ******************************************************************************/
void btif_in_load_bonded_device(const RawAddress& addr, bool add) {
  bool bt_linkkey_file_found = false;
  auto bdstr = addr.ToString();

  log::verbose("Remote device:{}", addr);
  LinkKey link_key;
  size_t size = sizeof(link_key);
  if (btif_config_get_bin(bdstr, BTIF_STORAGE_KEY_LINK_KEY, link_key.data(), &size)) {
    int linkkey_type;
    if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LINK_KEY_TYPE, &linkkey_type)) {
      if (add) {
        DEV_CLASS dev_class = {0, 0, 0};
        int cod;
        int pin_length = 0;
        if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_CLASS, &cod)) {
          dev_class = uint2devclass((uint32_t)cod);
        }
        btif_config_get_int(bdstr, BTIF_STORAGE_KEY_PIN_LENGTH, &pin_length);
        PairingType pairing_type =
                btif_storage_get_bredr_pairing_type(addr).value_or(kPairingTypeNone);
        BTA_DmAddDevice(addr, dev_class, pairing_type, link_key, static_cast<uint8_t>(linkkey_type),
                        pin_length);

        int device_type = BT_DEVICE_TYPE_UNKNOWN;
        if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_TYPE, &device_type) &&
            (device_type == BT_DEVICE_TYPE_DUMO)) {
          btif_gatts_add_bonded_dev_from_nv(addr);
        }
      }
      bt_linkkey_file_found = true;
    }
  }
  if (!btif_in_fetch_bonded_ble_device(bdstr, add, nullptr) && !bt_linkkey_file_found) {
    log::verbose("No link key or ble key found for device:{}", addr);
  }
}

static bool btif_read_le_key(const RawAddress& addr, const tBLE_ADDR_TYPE addr_type,
                             const PairingType& pairing_type, const uint8_t key_type,
                             const size_t key_len, const bool add_key, bool* device_added) {
  log::assert_that(device_added != nullptr, "assert failed: device_added != nullptr");

  tBTA_LE_KEY_VALUE key = {};
  if (btif_storage_get_ble_bonding_key(addr, key_type, reinterpret_cast<uint8_t*>(&key), key_len) !=
      BT_STATUS_SUCCESS) {
    return false;
  }

  if (add_key) {
    if (!*device_added) {
      BTA_DmAddBleDevice(addr, addr_type, BT_DEVICE_TYPE_BLE);
      *device_added = true;
    }

    log::verbose("Adding key type {} for {}", key_type, addr);
    BTA_DmAddBleKey(addr, pairing_type, key_type, key);
  }

  return true;
}

/*******************************************************************************
 * Functions
 *
 * Functions are synchronous and can be called by both from internal modules
 * such as BTIF_DM and by external entiries from HAL via BTIF_context_switch.
 * For OUT parameters, the caller is expected to provide the memory.
 * Caller is expected to provide a valid pointer to 'property->value' based on
 * the property->type.
 ******************************************************************************/

/*******************************************************************************
 *
 * Function         btif_split_uuids_string
 *
 * Description      Internal helper function to split the string of UUIDs
 *                  read from the NVRAM to an array
 *
 * Returns          Number of UUIDs parsed from the supplied string
 *
 ******************************************************************************/
size_t btif_split_uuids_string(const char* str, bluetooth::Uuid* p_uuid, size_t max_uuids) {
  log::assert_that(str != nullptr, "assert failed: str != nullptr");
  log::assert_that(p_uuid != nullptr, "assert failed: p_uuid != nullptr");

  size_t num_uuids = 0;
  while (str && num_uuids < max_uuids) {
    auto tmp = Uuid::FromString(std::string(str, Uuid::kString128BitLen));
    if (!tmp.has_value()) {
      break;
    }

    *p_uuid = *tmp;
    p_uuid++;

    num_uuids++;
    str = strchr(str, ' ');
    if (str) {
      str++;
    }
  }

  return num_uuids;
}

/** Helper function for fetching a bt_property of the adapter. */
static bt_status_t btif_storage_get_adapter_prop(bt_property_type_t type, void* buf, int size,
                                                 bt_property_t* property) {
  property->type = type;
  property->val = buf;
  property->len = size;
  return btif_storage_get_adapter_property(property);
}

/*******************************************************************************
 *
 * Function         btif_storage_get_adapter_property
 *
 * Description      BTIF storage API - Fetches the adapter property->type
 *                  from NVRAM and fills property->val.
 *                  Caller should provide memory for property->val and
 *                  set the property->val
 *
 * Returns          BT_STATUS_SUCCESS if the fetch was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_get_adapter_property(bt_property_t* property) {
  /* Special handling for adapter address and BONDED_DEVICES */
  if (property->type == BT_PROPERTY_BDADDR) {
    RawAddress* addr = reinterpret_cast<RawAddress*>(property->val);
    /* Fetch the local BD ADDR */
    if (bluetooth::shim::GetController() == nullptr) {
      log::error("Controller not ready! Unable to return Bluetooth Address");
      *addr = RawAddress::kEmpty;
      return BT_STATUS_NOT_READY;
    } else {
      log::info("Controller ready!");
      *addr = bluetooth::ToRawAddress(bluetooth::shim::GetController()->GetMacAddress());
    }
    property->len = RawAddress::kLength;
    return BT_STATUS_SUCCESS;
  } else if (property->type == BT_PROPERTY_ADAPTER_BONDED_DEVICES) {
    btif_bonded_devices_t bonded_devices;

    btif_in_fetch_bonded_devices(&bonded_devices, 0);

    log::verbose("BT_PROPERTY_ADAPTER_BONDED_DEVICES: Number of bonded devices={}",
                 bonded_devices.num_devices);

    std::vector<tBLE_BD_ADDR_SERIALIZED> bonded_devices_serialized;
    for (uint32_t i = 0; i < bonded_devices.num_devices; ++i) {
      bonded_devices_serialized.push_back(bonded_devices.devices[i].ToSerialized());
    }
    property->len = bonded_devices_serialized.size() * sizeof(tBLE_BD_ADDR_SERIALIZED);
    memcpy(property->val, bonded_devices_serialized.data(), property->len);

    /* if there are no bonded_devices, then length shall be 0 */
    return BT_STATUS_SUCCESS;
  } else if (property->type == BT_PROPERTY_UUIDS) {
    /* publish list of local supported services */
    Uuid* p_uuid = reinterpret_cast<Uuid*>(property->val);
    uint32_t num_uuids = 0;
    uint32_t i;

    tBTA_SERVICE_MASK service_mask = btif_get_enabled_services_mask();
    log::info("Service_mask=0x{:x}", service_mask);
    for (i = 0; i < BTA_MAX_SERVICE_ID; i++) {
      /* This should eventually become a function when more services are enabled
       */
      if (service_mask & (tBTA_SERVICE_MASK)(1 << i)) {
        switch (i) {
          case BTA_HFP_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_AG_HANDSFREE);
            num_uuids++;
          }
            FALLTHROUGH_INTENDED; /* FALLTHROUGH */
          /* intentional fall through: Send both BFP & HSP UUIDs if HFP is
           * enabled */
          case BTA_HSP_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_HEADSET_AUDIO_GATEWAY);
            num_uuids++;
          } break;
          case BTA_A2DP_SOURCE_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_AUDIO_SOURCE);
            num_uuids++;
          } break;
          case BTA_A2DP_SINK_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_AUDIO_SINK);
            num_uuids++;
          } break;
          case BTA_PBAP_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_PBAP_PSE);
            num_uuids++;
          } break;
          case BTA_HFP_HS_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_HF_HANDSFREE);
            num_uuids++;
          } break;
          case BTA_MAP_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_MESSAGE_ACCESS);
            num_uuids++;
          } break;
          case BTA_MN_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_MESSAGE_NOTIFICATION);
            num_uuids++;
          } break;
          case BTA_PCE_SERVICE_ID: {
            *(p_uuid + num_uuids) = Uuid::From16Bit(UUID_SERVCLASS_PBAP_PCE);
            num_uuids++;
          } break;
        }
      }
    }
    property->len = (num_uuids) * sizeof(Uuid);
    return BT_STATUS_SUCCESS;
  }

  /* fall through for other properties */
  if (!cfg2prop(NULL, property)) {
    return btif_dm_get_adapter_property(property);
  }
  return BT_STATUS_SUCCESS;
}

/*******************************************************************************
 *
 * Function         btif_storage_set_adapter_property
 *
 * Description      BTIF storage API - Stores the adapter property
 *                  to NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_set_adapter_property(bt_property_t* property) {
  return prop2cfg(NULL, property) ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/** Helper function for fetching a bt_property of a remote device. */
static bt_status_t btif_storage_get_remote_prop(const RawAddress& addr, bt_property_type_t type,
                                                void* buf, int size, bt_property_t* property) {
  property->type = type;
  property->val = buf;
  property->len = size;
  return btif_storage_get_remote_device_property(addr, property);
}

/*******************************************************************************
 *
 * Function         btif_storage_get_remote_device_property
 *
 * Description      BTIF storage API - Fetches the remote device property->type
 *                  from NVRAM and fills property->val.
 *                  Caller should provide memory for property->val and
 *                  set the property->val
 *
 * Returns          BT_STATUS_SUCCESS if the fetch was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_get_remote_device_property(const RawAddress& addr,
                                                    bt_property_t* property) {
  return cfg2prop(&addr, property) ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}
/*******************************************************************************
 *
 * Function         btif_storage_set_remote_device_property
 *
 * Description      BTIF storage API - Stores the remote device property
 *                  to NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_set_remote_device_property(const RawAddress& addr,
                                                    bt_property_t* property) {
  return prop2cfg(&addr, property) ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_add_remote_device
 *
 * Description      BTIF storage API - Adds a newly discovered device to NVRAM
 *                  along with the timestamp. Also, stores the various
 *                  properties - RSSI, BDADDR, NAME (if found in EIR)
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_add_remote_device(const RawAddress& addr, uint32_t num_properties,
                                           bt_property_t* properties) {
  uint32_t i = 0;
  /* TODO: If writing a property, fails do we go back undo the earlier
   * written properties? */
  for (i = 0; i < num_properties; i++) {
    /* Ignore properties that are not stored in DB */
    if (properties[i].type == BT_PROPERTY_REMOTE_RSSI ||
        properties[i].type == BT_PROPERTY_REMOTE_IS_COORDINATED_SET_MEMBER ||
        properties[i].type == BT_PROPERTY_REMOTE_ASHA_CAPABILITY ||
        properties[i].type == BT_PROPERTY_REMOTE_ASHA_TRUNCATED_HISYNCID ||
        properties[i].type == BT_PROPERTY_DISCOVERY_RESULT_TYPE ||
        properties[i].type == BT_PROPERTY_UUIDS_FROM_EXTENDED_INQUIRY_RESPONSE ||
        properties[i].type == BT_PROPERTY_UUIDS_FROM_LE_ADVERTISING_DATA) {
      continue;
    }

    /* address for remote device needs special handling as we also store
     * timestamp */
    if (properties[i].type == BT_PROPERTY_BDADDR) {
      bt_property_t addr_prop;
      memcpy(&addr_prop, &properties[i], sizeof(bt_property_t));
      addr_prop.type = (bt_property_type_t)BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP;
      btif_storage_set_remote_device_property(addr, &addr_prop);
    } else {
      btif_storage_set_remote_device_property(addr, &properties[i]);
    }
  }
  return BT_STATUS_SUCCESS;
}

/*******************************************************************************
 *
 * Function         btif_storage_add_bredr_keys
 *
 * Description      BTIF storage API - Adds the newly bonded device to NVRAM
 *                  along with the link-key, Key type and Pin key length
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/

bt_status_t btif_storage_add_bredr_keys(const RawAddress& addr, const PairingType& pairing_type,
                                        const LinkKey& link_key, uint8_t key_type,
                                        uint8_t pin_length) {
  log::debug("{} type: {}", addr, pairing_type);

  std::string bdstr = addr.ToString();
  bool ret = btif_config_set_int(bdstr, BTIF_STORAGE_KEY_LINK_KEY_TYPE, static_cast<int>(key_type));
  ret &= btif_config_set_int(bdstr, BTIF_STORAGE_KEY_PIN_LENGTH, static_cast<int>(pin_length));
  ret &= btif_config_set_bin(bdstr, BTIF_STORAGE_KEY_LINK_KEY, link_key.data(), link_key.size());
  ret &= btif_config_set_int(bdstr, BTIF_STORAGE_KEY_BREDR_PAIRING_ALGORITHM,
                             static_cast<int>(pairing_type.algorithm));

  int pairing_variant = pairing_type.algorithm == PairingAlgorithm::BREDR_LEGACY
                                ? static_cast<int>(pairing_type.legacy_variant)
                                : static_cast<int>(pairing_type.variant);
  ret &= btif_config_set_int(bdstr, BTIF_STORAGE_KEY_BREDR_PAIRING_VARIANT, pairing_variant);

  if (ret) {
    btif_storage_set_mode(addr);
  }
  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_remove_bonded_device
 *
 * Description      BTIF storage API - Deletes the bonded device from NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if the deletion was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_remove_bonded_device(const RawAddress& addr) {
  std::string bdstr = addr.ToString();
  log::info("Removing bonded device addr={}", addr);

  btif_config_remove_device(bdstr);

  /* Check the length of the paired devices, and if 0 then reset IRK */
  if (com_android_bluetooth_flags_btsec_cycle_irks()) {
    auto paired_devices = btif_config_get_paired_devices();
    if (paired_devices.empty()) {
      btif_remove_local_irk_from_resolving_list();

      log::info("Last paired device removed, resetting IRK");
      BTA_DmBleResetId();
    }
  }

  return BT_STATUS_SUCCESS;
}

/* Some devices hardcode sample LTK value from spec, instead of generating one.
 * Treat such devices as insecure, and remove such bonds when bluetooth
 * restarts. Removing them after disconnection is handled separately.
 *
 * We still allow such devices to bond in order to give the user a chance to
 * update firmware.
 */
static void remove_devices_with_sample_ltk() {
  std::vector<RawAddress> bad_ltk;
  for (const auto& addr : btif_config_get_paired_devices()) {
    const std::string bdstr = addr.ToString();

    tBTA_LE_KEY_VALUE key;
    memset(&key, 0, sizeof(key));

    if (btif_storage_get_ble_bonding_key(addr, BTM_LE_KEY_PENC, reinterpret_cast<uint8_t*>(&key),
                                         sizeof(tBTM_LE_PENC_KEYS)) == BT_STATUS_SUCCESS) {
      if (key.penc_key.ltk == SAMPLE_LTK) {
        bad_ltk.push_back(addr);
      }
    }
  }

  for (const RawAddress& addr : bad_ltk) {
    log::error("Removing bond to device using test TLK: {}", addr);

    btif_storage_remove_bonded_device(addr);
  }
}

/*******************************************************************************
 *
 * Function         btif_storage_load_le_devices
 *
 * Description      BTIF storage API - Loads all LE-only and Dual Mode devices
 *                  from NVRAM. This API invokes the adapter_properties_cb.
 *                  It also invokes invoke_address_consolidate_cb
 *                  to consolidate each Dual Mode device and
 *                  invoke_le_address_associate_cb to associate each LE-only
 *                  device between its RPA, identity address, and identity address type.
 *
 ******************************************************************************/
void btif_storage_load_le_devices(void) {
  btif_bonded_devices_t bonded_devices;
  btif_in_fetch_bonded_devices(&bonded_devices, 1);

  std::unordered_set<RawAddress> bonded_addresses;
  for (uint16_t i = 0; i < bonded_devices.num_devices; i++) {
    bonded_addresses.insert(bonded_devices.devices[i].bda);
  }

  std::vector<std::pair<tBLE_BD_ADDR, tBLE_BD_ADDR>> consolidated_devices;
  for (uint16_t i = 0; i < bonded_devices.num_devices; i++) {
    tBTA_LE_KEY_VALUE key = {};
    if (btif_storage_get_ble_bonding_key(bonded_devices.devices[i].bda, BTM_LE_KEY_PID,
                                         reinterpret_cast<uint8_t*>(&key),
                                         sizeof(tBTM_LE_PID_KEYS)) == BT_STATUS_SUCCESS) {
      if (bonded_devices.devices[i].bda != key.pid_key.identity_addr) {
        log::info("Found device with a known identity address {} {}", bonded_devices.devices[i],
                  key.pid_key.identity_addr);

        if (bonded_devices.devices[i].bda.IsEmpty() || key.pid_key.identity_addr.IsEmpty()) {
          log::warn("Address is empty! Skip");
        } else {
          tBLE_BD_ADDR identity_addr = {.type = key.pid_key.identity_addr_type,
                                        .bda = key.pid_key.identity_addr};
          consolidated_devices.emplace_back(bonded_devices.devices[i], identity_addr);
        }
      }
    }
  }

  /* Send the adapter_properties_cb with bonded consolidated device */
  std::vector<tBLE_BD_ADDR_SERIALIZED> serialized_bonded_devices;
  for (const auto& device : consolidated_devices) {
    serialized_bonded_devices.push_back(std::get<0>(device).ToSerialized());
  }
  bt_property_t adapter_prop = {.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
                                .len = static_cast<int>(serialized_bonded_devices.size() *
                                                        sizeof(tBLE_BD_ADDR_SERIALIZED)),
                                .val = serialized_bonded_devices.data()};
  btif_adapter_properties_evt(BT_STATUS_SUCCESS, /* num_props */ 1, &adapter_prop);

  for (const auto& device : consolidated_devices) {
    const tBLE_BD_ADDR& pseudo_addr = std::get<0>(device);
    const tBLE_BD_ADDR& identity_addr = std::get<1>(device);

    if (bonded_addresses.find(identity_addr.bda) != bonded_addresses.end()) {
      // Invokes address consolidation for DuMo devices
      GetInterfaceToProfiles()->events->invoke_address_consolidate_cb(pseudo_addr.bda,
                                                                      identity_addr.bda);
    } else {
      // Associates RPA & identity address for LE-only devices
      GetInterfaceToProfiles()->events->invoke_le_address_associate_cb(
              pseudo_addr.bda, identity_addr.bda, identity_addr.type);
    }
  }
}

/*******************************************************************************
 *
 * Function         btif_storage_load_bonded_devices
 *
 * Description      BTIF storage API - Loads all the bonded devices from NVRAM
 *                  and adds to the BTA.
 *                  Additionally, this API also invokes the adapter_properties_cb
 *                  and remote_device_properties_cb for each of the bonded
 *                  devices.
 *
 * Returns          BT_STATUS_SUCCESS if successful, BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_load_bonded_devices(void) {
  btif_bonded_devices_t bonded_devices;
  uint32_t i = 0;
  bt_property_t adapter_props[6];
  uint32_t num_props = 0;
  bt_property_t remote_properties[13];
  RawAddress addr;
  bt_bdname_t name, alias, model_name;
  uint32_t disc_timeout;
  Uuid local_uuids[BT_MAX_NUM_UUIDS];
  Uuid remote_uuids[BT_MAX_NUM_UUIDS];
  Uuid remote_uuids_le[BT_MAX_NUM_UUIDS];
  bt_status_t status;

  remove_devices_with_sample_ltk();

  btif_in_fetch_bonded_devices(&bonded_devices, 1);

  /* Now send the adapter_properties_cb with all adapter_properties */
  {
    memset(adapter_props, 0, sizeof(adapter_props));

    /* address */
    status = btif_storage_get_adapter_prop(BT_PROPERTY_BDADDR, &addr, sizeof(addr),
                                           &adapter_props[num_props]);
    // Add BT_PROPERTY_BDADDR property into list only when successful.
    // Otherwise, skip this property entry.
    if (status == BT_STATUS_SUCCESS) {
      num_props++;
    }

    /* DISC_TIMEOUT */
    btif_storage_get_adapter_prop(BT_PROPERTY_ADAPTER_DISCOVERABLE_TIMEOUT, &disc_timeout,
                                  sizeof(disc_timeout), &adapter_props[num_props]);
    num_props++;

    /* BONDED_DEVICES */
    std::vector<tBLE_BD_ADDR_SERIALIZED> serialized_bonded_devices;
    for (uint32_t i = 0; i < bonded_devices.num_devices; i++) {
      serialized_bonded_devices.push_back(bonded_devices.devices[i].ToSerialized());
    }
    adapter_props[num_props].type = BT_PROPERTY_ADAPTER_BONDED_DEVICES;
    adapter_props[num_props].len =
            serialized_bonded_devices.size() * sizeof(tBLE_BD_ADDR_SERIALIZED);
    adapter_props[num_props].val = serialized_bonded_devices.data();
    num_props++;

    /* LOCAL UUIDs */
    btif_storage_get_adapter_prop(BT_PROPERTY_UUIDS, local_uuids, sizeof(local_uuids),
                                  &adapter_props[num_props]);
    num_props++;

    btif_adapter_properties_evt(BT_STATUS_SUCCESS, num_props, adapter_props);
  }

  log::verbose("Number of bonded devices found={}", bonded_devices.num_devices);

  {
    for (i = 0; i < bonded_devices.num_devices; i++) {
      /*
       * TODO: improve handling of missing fields in NVRAM.
       */
      uint32_t cod = 0;
      uint32_t devtype = 0;

      num_props = 0;
      const RawAddress& remote_addr = bonded_devices.devices[i].bda;
      memset(remote_properties, 0, sizeof(remote_properties));

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_BDNAME, &name, sizeof(name),
                                   &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_REMOTE_FRIENDLY_NAME, &alias,
                                   sizeof(alias), &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_CLASS_OF_DEVICE, &cod, sizeof(cod),
                                   &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_TYPE_OF_DEVICE, &devtype,
                                   sizeof(devtype), &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_UUIDS, &remote_uuids,
                                   sizeof(remote_uuids), &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_UUIDS_LE, &remote_uuids_le,
                                   sizeof(remote_uuids_le), &remote_properties[num_props]);
      num_props++;

      // Floss needs appearance for metrics purposes
      uint16_t appearance = 0;
      if (btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_APPEARANCE, &appearance,
                                       sizeof(appearance),
                                       &remote_properties[num_props]) == BT_STATUS_SUCCESS) {
        num_props++;
      }

#if TARGET_FLOSS
      // Floss needs VID:PID for metrics purposes
      bt_vendor_product_info_t vp_info;
      if (btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_VENDOR_PRODUCT_INFO, &vp_info,
                                       sizeof(vp_info),
                                       &remote_properties[num_props]) == BT_STATUS_SUCCESS) {
        num_props++;
      }
#endif

      tBLE_ADDR_TYPE addr_type = BLE_ADDR_PUBLIC;
      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_REMOTE_ADDR_TYPE, &addr_type,
                                   sizeof(addr_type), &remote_properties[num_props]);
      num_props++;

      btif_storage_get_remote_prop(remote_addr, BT_PROPERTY_REMOTE_MODEL_NUM, &model_name,
                                   sizeof(model_name), &remote_properties[num_props]);
      num_props++;

      uint8_t bredr_pairing_type_value[2];
      auto bredr_pairing_type = btif_storage_get_bredr_pairing_type(remote_addr);
      if (bredr_pairing_type.has_value()) {
        bredr_pairing_type_value[0] = static_cast<uint8_t>(bredr_pairing_type.value().algorithm);
        bredr_pairing_type_value[1] = static_cast<uint8_t>(bredr_pairing_type.value().variant);
        remote_properties[num_props].type = BT_PROPERTY_BREDR_PAIRING_TYPE;
        remote_properties[num_props].len = sizeof(bredr_pairing_type_value);
        remote_properties[num_props].val = &bredr_pairing_type_value;
        num_props++;
      }

      uint8_t le_pairing_type_value[2];
      auto le_pairing_type = btif_storage_get_ble_pairing_type(remote_addr);
      if (le_pairing_type.has_value()) {
        le_pairing_type_value[0] = static_cast<uint8_t>(le_pairing_type.value().algorithm);
        le_pairing_type_value[1] = static_cast<uint8_t>(le_pairing_type.value().variant);
        remote_properties[num_props].type = BT_PROPERTY_LE_PAIRING_TYPE;
        remote_properties[num_props].len = sizeof(le_pairing_type_value);
        remote_properties[num_props].val = &le_pairing_type_value;
        num_props++;
      }

      btif_remote_properties_evt(BT_STATUS_SUCCESS, remote_addr, addr_type, num_props,
                                 remote_properties);
    }
  }
  return BT_STATUS_SUCCESS;
}

bt_status_t btif_storage_set_remote_host_sc_support(const RawAddress& addr, bool supported) {
  const std::string bdstr = addr.ToString();
  bool ret = btif_config_set_int(bdstr, BTIF_STORAGE_KEY_SECURE_CONNECTIONS_SUPPORTED,
                                 static_cast<int>(supported));
  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

std::optional<bool> btif_storage_get_remote_host_sc_support(const RawAddress& addr) {
  const std::string bdstr = addr.ToString();
  int val = 0;
  auto ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_SECURE_CONNECTIONS_SUPPORTED, &val);
  if (!ret) {
    return std::nullopt;
  }
  return val != 0;
}

bt_status_t btif_storage_set_remote_controller_sc_support(const RawAddress& addr, bool supported) {
  const std::string bdstr = addr.ToString();
  bool ret = btif_config_set_int(bdstr, BTIF_STORAGE_KEY_CONTROLLER_SECURE_CONNECTIONS_SUPPORTED,
                                 static_cast<int>(supported));
  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

std::optional<bool> btif_storage_get_remote_controller_sc_support(const RawAddress& addr) {
  const std::string bdstr = addr.ToString();
  int val = 0;
  auto ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_CONTROLLER_SECURE_CONNECTIONS_SUPPORTED,
                                 &val);
  if (!ret) {
    return std::nullopt;
  }
  return val != 0;
}

/*******************************************************************************
 *
 * Function         btif_storage_add_ble_keys
 *
 * Description      BTIF storage API - Adds the newly bonded device to NVRAM
 *                  along with the ble-key, Key type and Pin key length
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_add_ble_keys(const RawAddress& addr, const uint8_t* key_value,
                                      uint8_t key_type, uint8_t key_length) {
  for (size_t i = 0; i < std::size(BTIF_STORAGE_LE_KEYS); i++) {
    auto key = BTIF_STORAGE_LE_KEYS[i];
    if (key.type == key_type) {
      bool ret = btif_config_set_bin(addr.ToString(), key.name, key_value, key_length);

      if (ret) {
        btif_storage_set_mode(addr);
      }
      return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
    }
  }

  log::warn("Unknown LE key type: {}", key_type);
  return BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_get_ble_bonding_key
 *
 * Description
 *
 * Returns          BT_STATUS_SUCCESS if the fetch was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_get_ble_bonding_key(const RawAddress& addr, uint8_t key_type,
                                             uint8_t* key_value, int key_length) {
  for (size_t i = 0; i < std::size(BTIF_STORAGE_LE_KEYS); i++) {
    auto key = BTIF_STORAGE_LE_KEYS[i];
    if (key.type == key_type) {
      size_t length = key_length;
      bool ret = btif_config_get_bin(addr.ToString(), key.name, key_value, &length);
      return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
    }
  }

  log::warn("Unknown LE key type: {}", key_type);
  return BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_remove_ble_keys
 *
 * Description      BTIF storage API - Deletes the bonded device from NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if the deletion was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_remove_ble_bonding_keys(const RawAddress& addr) {
  std::string bdstr = addr.ToString();
  log::info("Removing bonding keys for bd addr:{}", addr);
  bool ret = true;
  for (size_t i = 0; i < std::size(BTIF_STORAGE_LE_KEYS); i++) {
    auto key_name = BTIF_STORAGE_LE_KEYS[i].name;
    if (btif_config_exist(bdstr, key_name)) {
      ret &= btif_config_remove(bdstr, key_name);
    }
  }

  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_set_ble_pairing_type
 *
 * Description      BTIF storage API - Sets the LE pairing type for the device
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_set_ble_pairing_type(const RawAddress& addr,
                                              const PairingType& pairing_type) {
  log::debug("{} type: {}", addr, pairing_type);

  const std::string bdstr = addr.ToString();
  bool ret = btif_config_set_int(bdstr, BTIF_STORAGE_KEY_LE_PAIRING_ALGORITHM,
                                 static_cast<int>(pairing_type.algorithm));
  ret &= btif_config_set_int(bdstr, BTIF_STORAGE_KEY_LE_PAIRING_VARIANT,
                             static_cast<int>(pairing_type.variant));

  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/*******************************************************************************
 *
 * Function         btif_storage_get_ble_pairing_type
 *
 * Description      BTIF storage API - Gets the LE pairing type for the device
 *
 * Returns          std::optional<PairingType> if the fetch was successful,
 *                  std::nullopt otherwise
 *
 ******************************************************************************/
std::optional<PairingType> btif_storage_get_ble_pairing_type(const RawAddress& addr) {
  const std::string bdstr = addr.ToString();

  int algorithm = 0;
  auto ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LE_PAIRING_ALGORITHM, &algorithm);
  if (!ret) {
    return std::nullopt;
  }

  PairingType pairing_type = {};
  pairing_type.algorithm = static_cast<PairingAlgorithm>(algorithm);

  int variant = 0;
  ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LE_PAIRING_VARIANT, &variant);
  if (!ret) {
    return std::nullopt;
  }

  pairing_type.variant = static_cast<PairingVariant>(variant);

  log::debug("{} type: {}", addr, pairing_type);

  return pairing_type;
}

/*******************************************************************************
 *
 * Function         btif_storage_get_bredr_pairing_type
 *
 * Description      BTIF storage API - Gets the BR/EDR pairing type for the device
 *
 * Returns          std::optional<PairingType> if the fetch was successful,
 *                  std::nullopt otherwise
 *
 ******************************************************************************/
std::optional<PairingType> btif_storage_get_bredr_pairing_type(const RawAddress& addr) {
  const std::string bdstr = addr.ToString();

  int algorithm = 0;
  auto ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_BREDR_PAIRING_ALGORITHM, &algorithm);
  if (!ret) {
    return std::nullopt;
  }

  PairingType pairing_type = {};
  pairing_type.algorithm = static_cast<PairingAlgorithm>(algorithm);

  int variant = 0;
  ret = btif_config_get_int(bdstr, BTIF_STORAGE_KEY_BREDR_PAIRING_VARIANT, &variant);
  if (!ret) {
    return std::nullopt;
  }

  if (pairing_type.algorithm == PairingAlgorithm::BREDR_LEGACY) {
    pairing_type.legacy_variant = static_cast<LegacyPairingVariant>(variant);
  } else {
    pairing_type.variant = static_cast<PairingVariant>(variant);
  }

  log::debug("{} type: {}", addr, pairing_type);

  return pairing_type;
}

/*******************************************************************************
 *
 * Function         btif_storage_add_ble_local_key
 *
 * Description      BTIF storage API - Adds the ble key to NVRAM
 *
 * Returns          BT_STATUS_SUCCESS if the store was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_add_ble_local_key(const Octet16& key_value, uint8_t key_type) {
  for (size_t i = 0; i < std::size(BTIF_STORAGE_LOCAL_LE_KEYS); i++) {
    auto key = BTIF_STORAGE_LOCAL_LE_KEYS[i];
    if (key.type == key_type) {
      bool ret = btif_config_set_bin(BTIF_STORAGE_SECTION_ADAPTER, key.name, key_value.data(),
                                     key_value.size());

      return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
    }
  }
  log::warn("Unknown LE key type: {}", key_type);
  return BT_STATUS_FAIL;
}

/** Stores local key of |key_type| into |key_value|
 * Returns BT_STATUS_SUCCESS if the fetch was successful, BT_STATUS_FAIL
 * otherwise
 */
bt_status_t btif_storage_get_ble_local_key(uint8_t key_type, Octet16* key_value) {
  for (size_t i = 0; i < std::size(BTIF_STORAGE_LOCAL_LE_KEYS); i++) {
    auto key = BTIF_STORAGE_LOCAL_LE_KEYS[i];
    if (key.type == key_type) {
      size_t length = key_value->size();
      bool ret = btif_config_get_bin(BTIF_STORAGE_SECTION_ADAPTER, key.name, key_value->data(),
                                     &length);

      return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
    }
  }
  log::warn("Unknown LE key type: {}", key_type);
  return BT_STATUS_FAIL;
}

bt_status_t btif_in_fetch_bonded_ble_device(const std::string& bdstr, int add,
                                            btif_bonded_devices_t* p_bonded_devices) {
  int device_type = BT_DEVICE_TYPE_UNKNOWN;

  const RawAddress addr = RawAddress::FromString(bdstr).value_or(RawAddress::kEmpty);

  if (!btif_config_get_int(bdstr, BTIF_STORAGE_KEY_DEV_TYPE, &device_type)) {
    return BT_STATUS_FAIL;
  }

  if ((device_type & BT_DEVICE_TYPE_BLE) == BT_DEVICE_TYPE_BLE || btif_has_ble_keys(bdstr)) {
    tBLE_ADDR_TYPE addr_type;
    bool device_added = false;
    bool key_found = false;

    log::verbose("Found a LE device: {}", addr);

    if (btif_storage_get_remote_addr_type(addr, &addr_type) != BT_STATUS_SUCCESS) {
      addr_type = BLE_ADDR_PUBLIC;
      btif_storage_set_remote_addr_type(addr, BLE_ADDR_PUBLIC);
    }

    PairingType pairing_type = btif_storage_get_ble_pairing_type(addr).value_or(kPairingTypeNone);

    for (size_t i = 0; i < std::size(BTIF_STORAGE_LE_KEYS); i++) {
      const auto& key = BTIF_STORAGE_LE_KEYS[i];
      if (btif_read_le_key(addr, addr_type, pairing_type, key.type, key.size, add, &device_added)) {
        key_found = true;
      }
    }

    // Fill in the bonded devices
    if (device_added) {
      if (p_bonded_devices) {
        if (p_bonded_devices->num_devices < BTM_SEC_MAX_DEVICE_RECORDS) {
          p_bonded_devices->devices[p_bonded_devices->num_devices++] = {addr_type, addr};
        } else {
          log::warn("Exceed the max number of bonded devices");
        }
      }
      btif_gatts_add_bonded_dev_from_nv(addr);
    }

    if (key_found) {
      return BT_STATUS_SUCCESS;
    }
  }
  return BT_STATUS_DEVICE_NOT_FOUND;
}

#if TARGET_FLOSS
static void btif_storage_invoke_addr_type_update(const RawAddress& addr,
                                                 const tBLE_ADDR_TYPE& addr_type) {
  bt_property_t prop;
  prop.type = BT_PROPERTY_REMOTE_ADDR_TYPE;
  prop.val = const_cast<tBLE_ADDR_TYPE*>(reinterpret_cast<const tBLE_ADDR_TYPE*>(&addr_type));
  prop.len = sizeof(tBLE_ADDR_TYPE);
  GetInterfaceToProfiles()->events->invoke_remote_device_properties_cb(BT_STATUS_SUCCESS, addr,
                                                                       addr_type, 1, &prop);
}
#endif  // TARGET_FLOSS

bt_status_t btif_storage_set_remote_addr_type(const RawAddress& addr, tBLE_ADDR_TYPE addr_type) {
  bool ret = btif_config_set_int(addr.ToString(), BTIF_STORAGE_KEY_ADDR_TYPE,
                                 static_cast<int>(addr_type));

#if TARGET_FLOSS
  // Floss needs to get address type for diagnosis API.
  btif_storage_invoke_addr_type_update(addr, addr_type);
#endif

  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

static bool btif_has_ble_keys(const std::string& bdstr) {
  return btif_config_exist(bdstr, BTIF_STORAGE_KEY_LE_KEY_PENC);
}

/*******************************************************************************
 *
 * Function         btif_storage_get_remote_addr_type
 *
 * Description      BTIF storage API - Fetches the remote addr type
 *
 * Returns          BT_STATUS_SUCCESS if the fetch was successful,
 *                  BT_STATUS_FAIL otherwise
 *
 ******************************************************************************/
bt_status_t btif_storage_get_remote_addr_type(const RawAddress& addr, tBLE_ADDR_TYPE* addr_type) {
  int val = BLE_ADDR_ANONYMOUS;
  bool ret = btif_config_get_int(addr.ToString(), BTIF_STORAGE_KEY_ADDR_TYPE, &val);
  *addr_type = static_cast<tBLE_ADDR_TYPE>(val);
  return ret ? BT_STATUS_SUCCESS : BT_STATUS_FAIL;
}

/** Stores information about GATT server supported features */
void btif_storage_set_gatt_sr_supp_feat(const RawAddress& addr, uint8_t feat) {
  do_in_jni_thread(BindOnce(
          [](const RawAddress& addr, uint8_t feat) {
            std::string bdstr = addr.ToString();
            log::verbose(
                    "GATT server supported features for: {} features: "
                    "{}",
                    addr, feat);
            btif_config_set_int(bdstr, BTIF_STORAGE_KEY_GATT_SERVER_SUPPORTED, feat);
          },
          addr, feat));
}

/** Gets information about GATT server supported features */
uint8_t btif_storage_get_sr_supp_feat(const RawAddress& addr) {
  auto bdstr = addr.ToString();

  int value = 0;
  btif_config_get_int(bdstr, BTIF_STORAGE_KEY_GATT_SERVER_SUPPORTED, &value);
  log::verbose("Remote device: {} GATT server supported features 0x{:02x}", addr, value);

  return value;
}

/*******************************************************************************
 *
 * Function         btif_storage_is_restricted_device
 *
 * Description      BTIF storage API - checks if this device is a restricted
 *                  device
 *
 * Returns          true  if the device is labeled as restricted
 *                  false otherwise
 *
 ******************************************************************************/
bool btif_storage_is_restricted_device(const RawAddress& addr) {
  int val;
  return btif_config_get_int(addr.ToString(), BTIF_STORAGE_KEY_RESTRICTED, &val);
}

/*******************************************************************************
 *
 * Function         btif_storage_prune_devices
 *
 * Description      Removes restricted mode devices in non-restricted mode
 *
 * Returns          none
 *
 ******************************************************************************/
void btif_storage_prune_devices() {
  if (GetInterfaceToProfiles()->config->isRestrictedMode()) {
    int user_id = btif_storage_get_user_id();

    // Remove the devices with different user id
    for (const auto& addr : btif_config_get_paired_devices()) {
      auto bdstr = addr.ToString();
      int id = 0;
      if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_RESTRICTED, &id)) {
        // Restricted device, remove if user ID is different
        if (id != user_id) {
          log::info("Removing {} since user changed from {} to {}", addr, id, user_id);
          btif_config_remove_device(bdstr);
        }
      }
    }
  } else {
    // Default user, remove all restricted devices
    btif_config_remove_device_with_key(BTIF_STORAGE_KEY_RESTRICTED);
  }
}

// Get the name of a device from btif for interop database matching.
bool btif_storage_get_stored_remote_name(const RawAddress& addr, char* name) {
  bt_property_t property{
          .type = BT_PROPERTY_BDNAME,
          .len = BD_NAME_LEN,
          .val = name,
  };

  return btif_storage_get_remote_device_property(addr, &property) == BT_STATUS_SUCCESS;
}

// Get the Class of Device.
bool btif_storage_get_cod(const RawAddress& addr, uint32_t* cod) {
  bt_property_t property{
          .type = BT_PROPERTY_CLASS_OF_DEVICE,
          .len = sizeof(*cod),
          .val = cod,
  };

  return btif_storage_get_remote_device_property(addr, &property) == BT_STATUS_SUCCESS;
}

/** Stores information about GATT Client supported features support */
void btif_storage_set_gatt_cl_supp_feat(const RawAddress& addr, uint8_t feat) {
  do_in_jni_thread(BindOnce(
          [](const RawAddress& bd_addr, uint8_t feat) {
            std::string bdstr = bd_addr.ToString();
            log::verbose("saving gatt client supported feat: {}", bd_addr);
            btif_config_set_int(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_SUPPORTED, feat);
          },
          addr, feat));
}

/** Get client supported features */
uint8_t btif_storage_get_gatt_cl_supp_feat(const RawAddress& addr) {
  const std::string bdstr = addr.ToString();

  int value = 0;
  btif_config_get_int(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_SUPPORTED, &value);
  log::verbose("Remote device: {} GATT client supported features 0x{:02x}", addr, value);

  return value;
}

/** Remove client supported features */
void btif_storage_remove_gatt_cl_supp_feat(const RawAddress& addr) {
  do_in_jni_thread(BindOnce(
          [](const RawAddress& bd_addr) {
            auto bdstr = bd_addr.ToString();
            if (btif_config_exist(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_SUPPORTED)) {
              btif_config_remove(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_SUPPORTED);
            }
          },
          addr));
}

/** Store last server database hash for remote client */
void btif_storage_set_gatt_cl_db_hash(const RawAddress& addr, Octet16 hash) {
  do_in_jni_thread(BindOnce(
          [](const RawAddress& bd_addr, Octet16 hash) {
            auto bdstr = bd_addr.ToString();
            btif_config_set_bin(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_DB_HASH, hash.data(),
                                hash.size());
          },
          addr, hash));
}

/** Get last server database hash for remote client */
Octet16 btif_storage_get_gatt_cl_db_hash(const RawAddress& addr) {
  auto bdstr = addr.ToString();

  Octet16 hash;
  size_t size = hash.size();
  btif_config_get_bin(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_DB_HASH, hash.data(), &size);

  return hash;
}

/** Remove las server database hash for remote client */
void btif_storage_remove_gatt_cl_db_hash(const RawAddress& addr) {
  do_in_jni_thread(BindOnce(
          [](const RawAddress& bd_addr) {
            auto bdstr = bd_addr.ToString();
            if (btif_config_exist(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_DB_HASH)) {
              btif_config_remove(bdstr, BTIF_STORAGE_KEY_GATT_CLIENT_DB_HASH);
            }
          },
          addr));
}

std::vector<bluetooth::Uuid> btif_storage_get_services(const RawAddress& addr,
                                                       tBT_TRANSPORT transport) {
  // Get BR/EDR services if requested transport is BT_TRANSPORT_BR_EDR or BT_TRANSPORT_AUTO
  bool get_bredr_services = transport != BT_TRANSPORT_LE;

  // Get LE services if requested transport is BT_TRANSPORT_LE or BT_TRANSPORT_AUTO
  bool get_le_services = transport != BT_TRANSPORT_BR_EDR;

  uint8_t count = 0;
  std::array<bluetooth::Uuid, BT_MAX_NUM_UUIDS> uuids = {};

  // Get BR/EDR services from storage
  if (get_bredr_services) {
    bt_property_t remote_properties = {BT_PROPERTY_UUIDS, sizeof(uuids), &uuids};
    if (btif_storage_get_remote_device_property(addr, &remote_properties) == BT_STATUS_SUCCESS) {
      count = remote_properties.len / sizeof(uuids[0]);
    }
  }

  // Get LE services from storage
  if (get_le_services) {
    int size = (uuids.size() - count) * sizeof(uuids[0]);
    bt_property_t remote_properties = {BT_PROPERTY_UUIDS_LE, size, &uuids[count]};
    if (btif_storage_get_remote_device_property(addr, &remote_properties) == BT_STATUS_SUCCESS) {
      count += remote_properties.len / sizeof(uuids[0]);
    }
  }

  return std::vector<bluetooth::Uuid>(uuids.begin(), uuids.begin() + count);
}

// TODO(b/369381361) Remove this function after all devices are migrated
void btif_storage_migrate_services() {
  for (const auto& mac_address : btif_config_get_paired_devices()) {
    auto addr_str = mac_address.ToString();

    int device_type = BT_DEVICE_TYPE_UNKNOWN;
    btif_config_get_int(addr_str, BTIF_STORAGE_KEY_DEV_TYPE, &device_type);

    if ((device_type == BT_DEVICE_TYPE_BREDR) ||
        btif_config_exist(addr_str, BTIF_STORAGE_KEY_REMOTE_SERVICE_LE)) {
      /* Classic only, or already migrated entries don't need migration */
      continue;
    }

    bt_property_t remote_uuids_prop;
    Uuid remote_uuids[BT_MAX_NUM_UUIDS];
    BTIF_STORAGE_FILL_PROPERTY(&remote_uuids_prop, BT_PROPERTY_UUIDS, sizeof(remote_uuids),
                               remote_uuids);
    btif_storage_get_remote_device_property(mac_address, &remote_uuids_prop);

    log::info("Will migrate Services => ServicesLe for {}", mac_address);

    std::vector<uint8_t> property_value;
    for (auto& uuid : remote_uuids) {
      if (!btif_is_interesting_le_service(uuid)) {
        continue;
      }

      log::info("interesting LE service: {}", uuid);
      auto uuid_128bit = uuid.To128BitBE();
      property_value.insert(property_value.end(), uuid_128bit.begin(), uuid_128bit.end());
    }

    bt_property_t le_uuids_prop{BT_PROPERTY_UUIDS_LE, static_cast<int>(property_value.size()),
                                (void*)property_value.data()};

    /* Write LE services to storage */
    btif_storage_set_remote_device_property(mac_address, &le_uuids_prop);
    log::info("Migration finished for {}", mac_address);
  }
}

void btif_debug_linkkey_type_dump(int fd) {
  dprintf(fd, "\nLink Key Types:\n");
  for (const auto& addr : btif_config_get_paired_devices()) {
    auto bdstr = addr.ToString();
    int linkkey_type;
    dprintf(fd, "  %s\n", addr.ToRedactedStringForLogging().c_str());

    dprintf(fd, "    BR: ");
    if (btif_config_get_int(bdstr, BTIF_STORAGE_KEY_LINK_KEY_TYPE, &linkkey_type)) {
      dprintf(fd, "%s", linkkey_type_text(linkkey_type).c_str());
    }
    dprintf(fd, "\n");

    dprintf(fd, "    LE:");
    for (size_t i = 0; i < std::size(BTIF_STORAGE_LE_KEYS); i++) {
      const std::string& key_name = BTIF_STORAGE_LE_KEYS[i].name;
      if (btif_config_exist(bdstr, key_name)) {
        dprintf(fd, " %s", key_name.c_str());
      }
    }

    dprintf(fd, "\n");
  }
}
