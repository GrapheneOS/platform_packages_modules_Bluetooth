/*
 * Copyright 2023 The Android Open Source Project
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
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "osi/include/allocator.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/list.h"
#include "stack/acl/acl.h"
#include "stack/btm/btm_ble_int_types.h"
#include "stack/btm/btm_sco.h"
#include "stack/btm/neighbor_inquiry.h"
#include "stack/btm/security_device_record.h"
#include "stack/include/bt_octets.h"
#include "stack/include/btm_ble_api_types.h"
#include "stack/include/rfcdefs.h"
#include "stack/include/security_client_callbacks.h"
#include "types/raw_address.h"

/*
 * Local device configuration
 */
typedef struct {
  tBTM_LOC_BD_NAME bd_name; /* local Bluetooth device name */
  bool pin_type;            /* true if PIN type is fixed */
  uint8_t pin_code_len;     /* Bonding information */
  PIN_CODE pin_code;        /* PIN CODE if pin type is fixed */
} tBTM_CFG;

/* Pairing State */
enum {
  BTM_PAIR_STATE_IDLE, /* Idle                                         */
  BTM_PAIR_STATE_GET_REM_NAME, /* Getting the remote name (to check for SM4) */
  BTM_PAIR_STATE_WAIT_PIN_REQ, /* Started authentication, waiting for PIN req
                                  (PIN is pre-fetched) */
  BTM_PAIR_STATE_WAIT_LOCAL_PIN,       /* Waiting for local PIN code */
  BTM_PAIR_STATE_WAIT_NUMERIC_CONFIRM, /* Waiting user 'yes' to numeric
                                          confirmation   */
  BTM_PAIR_STATE_KEY_ENTRY, /* Key entry state (we are a keyboard)          */
  BTM_PAIR_STATE_WAIT_LOCAL_OOB_RSP, /* Waiting for local response to peer OOB
                                        data  */
  BTM_PAIR_STATE_WAIT_LOCAL_IOCAPS, /* Waiting for local IO capabilities and OOB
                                       data */
  BTM_PAIR_STATE_INCOMING_SSP, /* Incoming SSP (got peer IO caps when idle) */
  BTM_PAIR_STATE_WAIT_AUTH_COMPLETE, /* All done, waiting authentication
                                        cpmplete    */
  BTM_PAIR_STATE_WAIT_DISCONNECT     /* Waiting to disconnect the ACL */
};
typedef uint8_t tBTM_PAIRING_STATE;

#define BTM_PAIR_FLAGS_WE_STARTED_DD \
  0x01 /* We want to do dedicated bonding              */
#define BTM_PAIR_FLAGS_PEER_STARTED_DD \
  0x02 /* Peer initiated dedicated bonding             */
#define BTM_PAIR_FLAGS_DISC_WHEN_DONE 0x04 /* Disconnect when done     */
#define BTM_PAIR_FLAGS_PIN_REQD \
  0x08 /* set this bit when pin_callback is called     */
#define BTM_PAIR_FLAGS_PRE_FETCH_PIN \
  0x10 /* set this bit when pre-fetch pin     */
#define BTM_PAIR_FLAGS_REJECTED_CONNECT \
  0x20 /* set this bit when rejected incoming connection  */
#define BTM_PAIR_FLAGS_WE_CANCEL_DD \
  0x40 /* set this bit when cancelling a bonding procedure */
#define BTM_PAIR_FLAGS_LE_ACTIVE \
  0x80 /* use this bit when SMP pairing is active */

typedef struct {
  bool is_mux;
  RawAddress bd_addr;
  uint16_t psm;
  bool is_orig;
  tBTM_SEC_CALLBACK* p_callback;
  tSMP_SIRK_CALLBACK* p_sirk_callback;
  void* p_ref_data;
  uint16_t rfcomm_security_requirement;
  tBT_TRANSPORT transport;
  tBTM_BLE_SEC_ACT sec_act;
} tBTM_SEC_QUEUE_ENTRY;

/* Define the Device Management control structure
 */
typedef struct tBTM_SEC_DEVCB {
  tBTM_CMPL_CB*
      p_stored_link_key_cmpl_cb; /* Read/Write/Delete stored link key    */

  tBTM_BLE_LOCAL_ID_KEYS id_keys;   /* local BLE ID keys */
  Octet16 ble_encryption_key_value; /* BLE encryption key */

#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
  bool no_disc_if_pair_fail;
  bool enable_test_mac_val;
  BT_OCTET8 test_mac;
  bool enable_test_local_sign_cntr;
  uint32_t test_local_sign_cntr;
#endif

  tBTM_IO_CAP loc_io_caps;    /* IO capability of the local device */
  tBTM_AUTH_REQ loc_auth_req; /* the auth_req flag  */
} tBTM_SEC_DEVCB;

typedef struct tBTM_SEC_CB {
  tBTM_CFG cfg; /* Device configuration */

  /*****************************************************
  **      Device control
  *****************************************************/
  tBTM_SEC_DEVCB devcb;

  /*****************************************************
  **      BLE Device controllers
  *****************************************************/
  tBTM_BLE_CB ble_ctr_cb;

 private:
  friend void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                                        const Octet16& stk);
  friend tBTM_STATUS btm_ble_start_encrypt(const RawAddress& bda, bool use_stk,
                                           Octet16* p_stk);
  friend void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                                        const Octet16& stk);
  uint16_t enc_handle{0};

  friend void btm_ble_ltk_request(uint16_t handle, uint8_t rand[8],
                                  uint16_t ediv);
  BT_OCTET8 enc_rand; /* received rand value from LTK request*/

  uint16_t ediv{0}; /* received ediv value from LTK request */

  uint8_t key_size{0};

 public:
  /*****************************************************
  **      Security Management
  *****************************************************/
  tBTM_APPL_INFO api;

  tBTM_SEC_DEV_REC* p_collided_dev_rec{nullptr};
  alarm_t* sec_collision_timer{nullptr};
  uint64_t collision_start_time{0};
  uint32_t dev_rec_count{0}; /* Counter used for device record timestamp */
  uint8_t security_mode{0};
  bool pairing_disabled{false};
  bool security_mode_changed{false}; /* mode changed during bonding */
  bool pin_type_changed{false};      /* pin type changed during bonding */
  bool sec_req_pending{false};       /*   true if a request is pending */

  uint8_t pin_code_len{0}; /* for legacy devices */
  PIN_CODE pin_code;       /* for legacy devices */
  tBTM_PAIRING_STATE pairing_state{
      BTM_PAIR_STATE_IDLE};               /* The current pairing state    */
  uint8_t pairing_flags{0};               /* The current pairing flags    */
  RawAddress pairing_bda;                 /* The device currently pairing */
  alarm_t* pairing_timer{nullptr};        /* Timer for pairing process    */
  alarm_t* execution_wait_timer{nullptr}; /* To avoid concurrent auth request */
  tBTM_SEC_SERV_REC sec_serv_rec[BTM_SEC_MAX_SERVICE_RECORDS];
  list_t* sec_dev_rec{nullptr}; /* list of tBTM_SEC_DEV_REC */
  tBTM_SEC_SERV_REC* p_out_serv{nullptr};
  tBTM_MKEY_CALLBACK* mkey_cback{nullptr};

  RawAddress connecting_bda;
  DEV_CLASS connecting_dc;
  uint8_t trace_level;

  fixed_queue_t* sec_pending_q{nullptr}; /* pending sequrity requests in
                                            tBTM_SEC_QUEUE_ENTRY format */

  void Init(uint8_t initial_security_mode) {
    memset(&cfg, 0, sizeof(cfg));
    memset(&devcb, 0, sizeof(devcb));
    memset(&ble_ctr_cb, 0, sizeof(ble_ctr_cb));
    memset(&enc_rand, 0, sizeof(enc_rand));
    memset(&api, 0, sizeof(api));
    memset(&pin_code, 0, sizeof(pin_code));
    memset(sec_serv_rec, 0, sizeof(sec_serv_rec));

    connecting_bda = RawAddress::kEmpty;
    memset(&connecting_dc, 0, sizeof(connecting_dc));

    sec_pending_q = fixed_queue_new(SIZE_MAX);
    sec_collision_timer = alarm_new("btm.sec_collision_timer");
    pairing_timer = alarm_new("btm.pairing_timer");
    execution_wait_timer = alarm_new("btm.execution_wait_timer");

#if defined(BTM_INITIAL_TRACE_LEVEL)
    trace_level = BTM_INITIAL_TRACE_LEVEL;
#else
    trace_level = BT_TRACE_LEVEL_NONE; /* No traces */
#endif
    security_mode = initial_security_mode;
    pairing_bda = RawAddress::kAny;
    sec_dev_rec = list_new([](void* ptr) {
      // Invoke destructor for all record objects and reset to default
      // initialized value so memory may be properly freed
      *((tBTM_SEC_DEV_REC*)ptr) = {};
      osi_free(ptr);
    });

    // devcb.Init();
  }

  void Free() {
    // devcb.Free();

    fixed_queue_free(sec_pending_q, nullptr);
    sec_pending_q = nullptr;

    list_free(sec_dev_rec);
    sec_dev_rec = nullptr;

    alarm_free(sec_collision_timer);
    sec_collision_timer = nullptr;

    alarm_free(pairing_timer);
    pairing_timer = nullptr;

    alarm_free(execution_wait_timer);
    execution_wait_timer = nullptr;
  }
} tBTM_SEC_CB;

/* security action for L2CAP COC channels */
#define BTM_SEC_OK 1
#define BTM_SEC_ENCRYPT 2         /* encrypt the link with current key */
#define BTM_SEC_ENCRYPT_NO_MITM 3 /* unauthenticated encryption or better */
#define BTM_SEC_ENCRYPT_MITM 4    /* authenticated encryption */
#define BTM_SEC_ENC_PENDING 5     /* wait for link encryption pending */

typedef uint8_t tBTM_SEC_ACTION;

extern tBTM_SEC_CB btm_sec_cb;
