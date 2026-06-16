/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <bluetooth/log.h>
#include <bluetooth/types/ble_address_with_type.h>
#include <bluetooth/types/bt_octets.h>
#include <bluetooth/types/remote_version.h>

#include <cstdint>
#include <string>

#include "internal_include/bt_target.h"
#include "macros.h"
#include "stack/include/btm_sec_api_types.h"
#include "stack/include/hci_error_code.h"

/*
 * Define structure for Security Service Record.
 * A record exists for each service registered with the Security Manager
 */
#define BTM_SEC_OUT_FLAGS (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT)
#define BTM_SEC_IN_FLAGS (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT)

#define BTM_SEC_OUT_LEVEL4_FLAGS \
  (BTM_SEC_OUT_AUTHENTICATE | BTM_SEC_OUT_ENCRYPT | BTM_SEC_OUT_MITM | BTM_SEC_MODE4_LEVEL4)

#define BTM_SEC_IN_LEVEL4_FLAGS \
  (BTM_SEC_IN_AUTHENTICATE | BTM_SEC_IN_ENCRYPT | BTM_SEC_IN_MITM | BTM_SEC_MODE4_LEVEL4)
typedef struct {
  uint32_t mx_proto_id;     /* Service runs over this multiplexer protocol */
  uint32_t orig_mx_chan_id; /* Channel on the multiplexer protocol */
  uint32_t term_mx_chan_id; /* Channel on the multiplexer protocol */
  uint16_t psm;             /* L2CAP PSM value */
  uint16_t security_flags;  /* Bitmap of required security features */
  uint8_t service_id;       /* Passed in authorization callback */
  uint8_t orig_service_name[BT_MAX_SERVICE_NAME_LEN + 1];
  uint8_t term_service_name[BT_MAX_SERVICE_NAME_LEN + 1];
} tBTM_SEC_SERV_REC;

/* LE Security information of device in Peripheral Role */
typedef struct {
  Octet16 irk;   /* peer diverified identity root */
  Octet16 pltk;  /* peer long term key */
  Octet16 pcsrk; /* peer SRK peer device used to secured sign local data */

  Octet16 lltk;  /* local long term key */
  Octet16 lcsrk; /* local SRK peer device used to secured sign local data */

  Octet8 rand;                  /* random vector for LTK generation */
  uint16_t ediv;                /* LTK diversifier of this peripheral device */
  uint16_t div;                 /* local DIV to generate local LTK=d1(ER, DIV, 0) and
                                   CSRK=d1(ER, DIV, 1) */
  uint8_t sec_level;            /* local pairing security level */
  uint8_t key_size;             /* key size of the LTK delivered to peer device */
  uint8_t srk_sec_level;        /* security property of peer SRK for this device */
  uint8_t local_csrk_sec_level; /* security property of local CSRK for this
                                   device */

  uint32_t counter;       /* peer sign counter for verifying rcv signed cmd */
  uint32_t local_counter; /* local sign counter for sending signed write cmd*/

  tBTM_LE_KEY_TYPE key_type; /* bit mask of valid key types in record */
} tBTM_SEC_BLE_KEYS;

enum : uint16_t {
  BTM_SEC_AUTHENTICATED = 0x0002,
  BTM_SEC_ENCRYPTED = 0x0004,
  BTM_SEC_NAME_KNOWN = 0x0008,
  BTM_SEC_LINK_KEY_KNOWN = 0x0010,
  BTM_SEC_LINK_KEY_AUTHED = 0x0020,
  BTM_SEC_ROLE_SWITCHED = 0x0040,  // UNUSED - only cleared
  BTM_SEC_IN_USE = 0x0080,         // UNUSED - only set
  /* LE link security flag */
  /* LE link is encrypted after pairing with MITM */
  BTM_SEC_LE_AUTHENTICATED = 0x0200,
  /* LE link is encrypted */
  BTM_SEC_LE_ENCRYPTED = 0x0400,
  /* not used */
  BTM_SEC_LE_NAME_KNOWN = 0x0800,  // UNUSED
  /* bonded with peer (peer LTK and/or SRK is saved) */
  BTM_SEC_LE_LINK_KEY_KNOWN = 0x1000,
  /* pairing is done with MITM */
  BTM_SEC_LE_LINK_KEY_AUTHED = 0x2000,
  /* pairing is done with 16 digit pin */
  BTM_SEC_16_DIGIT_PIN_AUTHED = 0x4000,
};

enum class tSECURITY_STATE : uint8_t {
  IDLE = 0,
  AUTHENTICATING = 1,
  ENCRYPTING = 2,
  GETTING_NAME = 3,
  AUTHORIZING = 4,
  SWITCHING_ROLE = 5,
  /* disconnecting BR/EDR */
  DISCONNECTING = 6,
  /* delay to check for encryption to work around */
  /* controller problems */
  DELAY_FOR_ENC = 7,
};

static inline std::string security_state_text(const tSECURITY_STATE& state) {
  switch (state) {
    CASE_RETURN_STRING(tSECURITY_STATE::IDLE);
    CASE_RETURN_STRING(tSECURITY_STATE::AUTHENTICATING);
    CASE_RETURN_STRING(tSECURITY_STATE::ENCRYPTING);
    CASE_RETURN_STRING(tSECURITY_STATE::GETTING_NAME);
    CASE_RETURN_STRING(tSECURITY_STATE::AUTHORIZING);
    CASE_RETURN_STRING(tSECURITY_STATE::SWITCHING_ROLE);
    CASE_RETURN_STRING(tSECURITY_STATE::DISCONNECTING);
    CASE_RETURN_STRING(tSECURITY_STATE::DELAY_FOR_ENC);
    default:
      RETURN_UNKNOWN_TYPE_STRING(tSECURITY_STATE, state);
  }
}

typedef enum : uint8_t {
  BTM_SM4_UNKNOWN = 0x00,
  BTM_SM4_KNOWN = 0x10,
  BTM_SM4_TRUE = 0x11,
  BTM_SM4_REQ_PEND = 0x08,  /* set this bit when getting remote features */
  BTM_SM4_UPGRADE = 0x04,   /* set this bit when upgrading link key */
  BTM_SM4_RETRY = 0x02,     /* set this bit to retry on HCI_ERR_KEY_MISSING or \
                               HCI_ERR_LMP_ERR_TRANS_COLLISION */
  BTM_SM4_DD_ACP = 0x20,    /* set this bit to indicate peer initiated dedicated bonding */
  BTM_SM4_CONN_PEND = 0x40, /* set this bit to indicate accepting acl conn; to
                             be cleared on \ btm_acl_created */
} tBTM_SM4_BIT;

/*
 * Define structure for Security Device Record.
 * A record exists for each device authenticated with this device
 */
struct BtmSecurityRecord {
  tSECURITY_STATE classic_link; /* Operating state of Classic link */
  tSECURITY_STATE le_link;      /* Operating state of LE link */

  tHCI_STATUS sec_status; /* Status in encryption change event */
  uint16_t sec_flags;     /* Current device security state */

  uint8_t pin_code_length; /* Length of the pin_code used for pairing */
  uint32_t required_security_flags_for_pairing;
  uint16_t security_required; /* Security required for connection */
  // security callback and its argument
  tBTM_SEC_CALLBACK* p_callback;
  void* p_ref_data;

  bool link_key_not_sent;          /* link key notification has not been sent waiting for
                                      name */
  BtIoCap rmt_io_caps;             /* IO capability of the peer device */
  tBTM_AUTH_REQ rmt_auth_req;      /* the auth_req flag as in the IO caps rsp evt */
  bool new_encryption_key_is_p256; /* Set to true when the newly generated LK
                                   ** is generated from P-256.
                                   ** Link encrypted with such LK can be used
                                   ** for SM over BR/EDR. */

  /* Whether BR/EDR pairing succeeded recently. Helps decide whether to perform CTKD or not */
  enum class BrEdrScEncReason : uint8_t {
    OTHER = 0,    /* Requested by services or apps on reconnection */
    PAIRED = 1,   /* Requested after first time pairing */
    REPAIRED = 2, /* Requested after repairing */
  } bredr_sc_enc_reason;

  static constexpr std::string bredr_sc_enc_reason_text(const BrEdrScEncReason& reason) {
    switch (reason) {
      CASE_RETURN_STRING(BrEdrScEncReason::OTHER);
      CASE_RETURN_STRING(BrEdrScEncReason::PAIRED);
      CASE_RETURN_STRING(BrEdrScEncReason::REPAIRED);
      default:
        RETURN_UNKNOWN_TYPE_STRING(BrEdrScEncReason, reason);
    }
  }

  // BREDR Link Key Info
  LinkKey link_key;                   /* Device link key */
  uint8_t link_key_type;              /* Type of key used in pairing */
  uint8_t enc_key_size;               /* current link encryption key size for BR/EDR */
  uint8_t le_enc_key_size;            /* current link encryption key size for LE */
  tBTM_BOND_TYPE bond_type;           /* Whether the BR/EDR pairing was persistent or temporary */
  PairingAlgorithm pairing_algorithm; /* The pairing algorithm used for BR/EDR pairing */

  // LE Link Key Info
  tBTM_SEC_BLE_KEYS ble_keys;
  PairingAlgorithm ble_pairing_algorithm; /* The pairing algorithm used for LE pairing */

public:
  bool is_device_authenticated() const { return sec_flags & BTM_SEC_AUTHENTICATED; }
  void set_device_authenticated() { sec_flags |= BTM_SEC_AUTHENTICATED; }
  void reset_device_authenticated() { sec_flags &= ~BTM_SEC_AUTHENTICATED; }

  bool is_device_encrypted() const { return sec_flags & BTM_SEC_ENCRYPTED; }
  void set_device_encrypted() { sec_flags |= BTM_SEC_ENCRYPTED; }
  void reset_device_encrypted() { sec_flags &= ~BTM_SEC_ENCRYPTED; }

  bool is_name_known() const { return sec_flags & BTM_SEC_NAME_KNOWN; }
  void set_device_known() { sec_flags |= BTM_SEC_NAME_KNOWN; }
  void reset_device_known() { sec_flags &= ~BTM_SEC_NAME_KNOWN; }

  bool is_link_key_known() const { return sec_flags & BTM_SEC_LINK_KEY_KNOWN; }
  void set_link_key_known() { sec_flags |= BTM_SEC_LINK_KEY_KNOWN; }
  void reset_link_key_known() { sec_flags &= ~BTM_SEC_LINK_KEY_KNOWN; }

  bool is_link_key_authenticated() const { return sec_flags & BTM_SEC_LINK_KEY_AUTHED; }
  void set_link_key_authenticated() { sec_flags |= BTM_SEC_LINK_KEY_AUTHED; }
  void reset_link_key_authenticated() { sec_flags &= ~BTM_SEC_LINK_KEY_AUTHED; }

  bool is_le_device_authenticated() const { return sec_flags & BTM_SEC_LE_AUTHENTICATED; }
  void set_le_device_authenticated() { sec_flags |= BTM_SEC_LE_AUTHENTICATED; }
  void reset_le_device_authenticated() { sec_flags &= ~BTM_SEC_LE_AUTHENTICATED; }

  bool is_le_device_encrypted() const { return sec_flags & BTM_SEC_LE_ENCRYPTED; }
  void set_le_device_encrypted() { sec_flags |= BTM_SEC_LE_ENCRYPTED; }
  void reset_le_device_encrypted() { sec_flags &= ~BTM_SEC_LE_ENCRYPTED; }

  bool is_le_link_key_known() const { return sec_flags & BTM_SEC_LE_LINK_KEY_KNOWN; }
  void set_le_link_key_known() { sec_flags |= BTM_SEC_LE_LINK_KEY_KNOWN; }
  void reset_le_link_key_known() { sec_flags &= ~BTM_SEC_LE_LINK_KEY_KNOWN; }

  bool is_le_link_key_authenticated() const { return sec_flags & BTM_SEC_LE_LINK_KEY_AUTHED; }
  void set_le_link_key_authenticated() { sec_flags |= BTM_SEC_LE_LINK_KEY_AUTHED; }
  void reset_le_link_key_authenticated() { sec_flags &= ~BTM_SEC_LE_LINK_KEY_AUTHED; }

  bool is_le_link_16_digit_key_authenticated() const {
    return sec_flags & BTM_SEC_16_DIGIT_PIN_AUTHED;
  }
  void set_le_link_16_digit_key_authenticated() { sec_flags |= BTM_SEC_16_DIGIT_PIN_AUTHED; }
  void reset_le_link_16_digit_key_authenticated() { sec_flags &= ~BTM_SEC_16_DIGIT_PIN_AUTHED; }

  bool is_security_state_bredr_encrypting() const {
    return classic_link == tSECURITY_STATE::ENCRYPTING;
  }
  bool is_security_state_le_encrypting() const { return le_link == tSECURITY_STATE::ENCRYPTING; }
  bool is_security_state_encrypting() const {
    return is_security_state_bredr_encrypting() || is_security_state_le_encrypting();
  }
  bool is_security_state_getting_name() const {
    return classic_link == tSECURITY_STATE::GETTING_NAME;
  }

  bool is_bond_type_unknown() const { return bond_type == BOND_TYPE_UNKNOWN; }
  bool is_bond_type_persistent() const { return bond_type == BOND_TYPE_PERSISTENT; }
  bool is_bond_type_temporary() const { return bond_type == BOND_TYPE_TEMPORARY; }

  bool is_bonded(tBT_TRANSPORT transport = BT_TRANSPORT_AUTO) const;

  uint8_t get_encryption_key_size() const { return enc_key_size; }

  void increment_sign_counter(bool local);

  std::string ToString() const {
    return std::format(
            "bredr_linkkey_known:{:c},le_linkkey_known:{:c},bond_type:{},bredr_linkkey_type:{},ble_"
            "enc_key_size:{},le_enc_key_size:{},bredr_authenticated:{:c},le_authenticated:{:c},16_"
            "digit_key_authenticated:{:c},bredr_encrypted:{:c},le_encrypted:{:c}, "
            "pairing_algorithm:{}, ble_pairing_algorithm:{}",
            is_link_key_known() ? 'T' : 'F', is_le_link_key_known() ? 'T' : 'F',
            bond_type_text(bond_type), linkkey_type_text(link_key_type), enc_key_size,
            le_enc_key_size, is_device_authenticated() ? 'T' : 'F',
            is_le_device_authenticated() ? 'T' : 'F',
            is_le_link_16_digit_key_authenticated() ? 'T' : 'F', is_device_encrypted() ? 'T' : 'F',
            is_le_device_encrypted() ? 'T' : 'F', pairing_algorithm_text(pairing_algorithm),
            pairing_algorithm_text(ble_pairing_algorithm));
  }
};

namespace std {
template <>
struct formatter<tSECURITY_STATE> : string_formatter<tSECURITY_STATE, &security_state_text> {};
}  // namespace std
