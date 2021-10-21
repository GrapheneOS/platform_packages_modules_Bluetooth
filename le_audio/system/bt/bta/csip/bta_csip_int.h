/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

/******************************************************************************
 *
 *  This file contains BTA CSIP Client internal definitions
 *
 ******************************************************************************/

#ifndef BTA_CSIP_INT_H
#define BTA_CSIP_INT_H

#include "bta_csip_api.h"
#include "bta_gatt_api.h"
#include "bta_sys.h"
#include "btm_ble_api_types.h"

/* Max CSIP supported devices (control blocks) */
#define BTA_CSIP_MAX_DEVICE 32

/* Max CSIP supported coordinated sets */
#define BTA_MAX_SUPPORTED_SETS 16

/* Maximum number of apps that can be registered with CSIP*/
#define BTA_CSIP_MAX_SUPPORTED_APPS 16

/* Max Supported coordinated sets per device*/
#define MAX_SUPPORTED_SETS_PER_DEVICE 5

/* Status of the CSIS Discovery*/
#define BTA_CSIP_DISC_SUCCESS 0
#define BTA_CSIP_INVALID_SIRK_FORMAT 1
#define BTA_CSIP_INVALID_KEY 2
#define BTA_CSIP_INVALID_KEY_TYPE 3
#define BTA_CSIP_ALL_MEMBERS_DISCOVERED 4
#define BTA_CSIP_RSRC_EXHAUSTED 5

using bluetooth::Uuid;

/* state machine events, these events are handled by the state machine */
enum {
  BTA_CSIP_API_OPEN_EVT = BTA_SYS_EVT_START(BTA_ID_GROUP),
  BTA_CSIP_API_CLOSE_EVT,
  BTA_CSIP_GATT_OPEN_EVT,
  BTA_CSIP_GATT_CLOSE_EVT,
  BTA_CSIP_OPEN_FAIL_EVT,
  BTA_CSIP_OPEN_CMPL_EVT,
  BTA_CSIP_START_ENC_EVT,
  BTA_CSIP_ENC_CMPL_EVT,
  BTA_CSIP_GATT_ENC_CMPL_EVT,

  /* common events: not handled by execute state machine */
  BTA_CSIP_API_ENABLE_EVT,
  BTA_CSIP_API_DISABLE_EVT,
  BTA_CSIP_DISC_CMPL_EVT,
  BTA_CSIP_SET_LOCK_VALUE_EVT,
};

/* CSIP device state machine states */
enum {
  BTA_CSIP_IDLE_ST,
  BTA_CSIP_W4_CONN_ST,
  BTA_CSIP_W4_SEC,
  BTA_CSIP_CONN_ST,
  BTA_CSIP_DISCONNECTING_ST,
};

typedef uint8_t tBTA_CSIP_STATE;


/* CSIP Command request parameters in BTA */

/* Find Coordinated set parameters*/
typedef struct {
  BT_HDR hdr;
  uint16_t conn_id;
  tGATT_STATUS status;
  RawAddress addr;
} tBTA_CSIP_DISC_SET;

/* Connection Request parameters */
typedef struct {
  BT_HDR hdr;
  RawAddress bd_addr;
  uint8_t app_id;
} tBTA_CSIP_API_CONN;

/* Lock request parameters */
typedef struct {
  BT_HDR hdr;
  tBTA_SET_LOCK_PARAMS lock_req;
} tBTA_CSIP_LOCK_PARAMS;


typedef struct {
  BT_HDR hdr;
  tBTA_CSIP_CBACK* p_csip_cb;
  tBTA_CSIP_CLT_REG_CB* reg_cb;
} tBTA_CSIP_APP_REG_PARAMS;

typedef struct {
  BT_HDR hdr;
  tBTA_CSIP_CBACK *p_cback;
} tBTA_CSIP_ENABLE;

typedef struct {
  BT_HDR hdr;
} tBTA_CSIP_CMD;

typedef union {
  BT_HDR hdr;
  tBTA_CSIP_API_CONN conn_param;
  tBTA_CSIP_LOCK_PARAMS lock_req;
  tBTA_CSIP_APP_REG_PARAMS reg_param;
  tBTA_CSIP_ENABLE enable_param;
  tBTA_GATTC_OPEN gatt_open_param;
  tBTA_GATTC_CLOSE gatt_close_param;
  tBTA_CSIP_CMD cmd;
} tBTA_CSIP_REQ_DATA;

typedef struct {
  bool in_use;
  uint8_t set_id = BTA_MAX_SUPPORTED_SETS;
  uint16_t conn_id;   /* GATT conn_id used for service discovery */
  RawAddress bd_addr;

  uint16_t service_handle;  /* Handle of this CSIS service */
  uint16_t sirk_handle;     /* SIRK characteristic value handle */
  uint16_t size_handle;     /* size characteristic value handle */
  uint16_t lock_handle;     /* lock characteristic value handle */
  uint16_t rank_handle;     /* rank characteristic value handle */

  uint16_t sirk_ccd_handle; /* SIRK CCCD handle*/
  uint16_t size_ccd_handle; /* size CCCD handle */
  uint16_t lock_ccd_handle; /* lock CCCD handle */

  uint8_t sirk[SIRK_SIZE];  /* Coordinated set SIRK */
  uint8_t size;             /* size of the coordinated set */
  uint8_t lock;             /* lock status of the set member */
  uint8_t rank;             /* rank of the set member*/
  uint8_t discovery_status = BTA_CSIP_DISC_SUCCESS; /* status of the CSIS discovery*/
  bluetooth::Uuid including_srvc_uuid; /* uuid of the service which includes CSIS*/

  /* Lock mamangement details*/
  std::vector<uint8_t> lock_applist;    /* Apps those have locked this set */
  std::vector<uint8_t> unrsp_applist;   /* Apps to which unresponsive res is sent */
  std::vector<uint8_t> denied_applist;  /* Apps to which lock was denied */
} tBTA_CSIS_SRVC_INFO;

typedef struct {
  bool in_use;
  RawAddress addr;                  /* Remote device address */
  uint16_t conn_id;                 /* GATT Connection ID */
  uint8_t sec_mask = (BTM_SEC_IN_ENCRYPT | BTM_SEC_OUT_ENCRYPT); /* Security Mask for CSIP*/
  bool security_pending;
  bool is_disc_external = false;    /* if discovery is started by external App*/
  uint8_t state;                    /* connection state */
  uint8_t csis_instance_count;      /* number of CSIS instances on remote device */
  uint8_t total_instance_disc;      /* total number of instances discovered */

  /* CSIS services found on remote device*/
  tBTA_CSIS_SRVC_INFO csis_srvc[MAX_SUPPORTED_SETS_PER_DEVICE];

  // list of applications which initiated CSIP connect for this device
  std::vector<uint8_t> conn_applist; /* List of Apps that sent connection request*/
  std::string set_info = "";
  bool unresponsive;                 /* if remote is unresponsive to GATT request */
} tBTA_CSIP_DEV_CB;

typedef struct {
  uint8_t app_id;
  uint8_t set_id;
  uint8_t value;
  int8_t cur_idx;
  std::vector<RawAddress> members_addr;
} tBTA_LOCK_REQUEST;

typedef struct {
  bool in_use;
  uint8_t set_id = BTA_MAX_SUPPORTED_SETS;
  uint8_t sirk[SIRK_SIZE];
  uint16_t set_member_tout = 500;
  bool request_in_progress;
  tBTA_CSIP_DEV_CB* cur_dev_cb;
  alarm_t* unresp_timer;
  tBTA_LOCK_REQUEST cur_lock_req;
  tBTA_LOCK_STATUS_CHANGED cur_lock_res;
  std::map<uint8_t, RawAddress> ordered_members;
  std::queue<tBTA_SET_LOCK_PARAMS> lock_req_queue;
} tBTA_CSET_CB;

typedef struct {
  uint8_t app_id;
  bool in_use;
  tBTA_CSIP_CBACK* p_cback;
} tBTA_CSIP_RCB;

typedef struct {
  tGATT_IF gatt_if;
  tBTA_CSIP_CBACK* p_cback;                /* callbacks for btif layer */
  std::vector<tBTA_CSIP_DEV_CB> dev_cb;    /* device control block */
  tBTA_CSIP_RCB app_rcb[BTA_CSIP_MAX_SUPPORTED_APPS];
  std::vector<tBTA_CSIP_CSET> csets;
  tBTA_CSET_CB csets_cb[BTA_MAX_SUPPORTED_SETS];
} tBTA_CSIP_CB;

/*****************************************************************************
 *  Global data
 ****************************************************************************/

/* CSIP control block */
extern tBTA_CSIP_CB bta_csip_cb;

/*****************************************************************************
 *  Function prototypes
 ****************************************************************************/
void bta_csip_sm_execute(tBTA_CSIP_DEV_CB* p_cb, uint16_t event,
                         tBTA_CSIP_REQ_DATA* p_data);


//action api's
extern bool bta_csip_hdl_event(BT_HDR* p_msg);
extern void bta_csip_api_enable(tBTA_CSIP_CBACK *p_cback);
extern void bta_csip_api_disable();
extern void bta_csip_app_register (const Uuid& app_uuid, tBTA_CSIP_CBACK* p_cback,
                                   BtaCsipAppRegisteredCb cb);
extern void bta_csip_gattc_register();
extern void bta_csip_app_unregister(uint8_t app_id);
extern void bta_csip_gatt_disc_cmpl_act(tBTA_CSIP_DISC_SET *disc_params);
extern void bta_csip_api_open_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_api_close_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_gatt_open_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_gatt_close_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_gatt_open_fail_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_open_cmpl_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_start_sec_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_sec_cmpl_act (tBTA_CSIP_DEV_CB* p_cb, tBTA_CSIP_REQ_DATA* p_data);
extern void bta_csip_close_csip_conn (tBTA_CSIP_DEV_CB* p_cb);
extern void bta_csip_process_set_lock_act(tBTA_SET_LOCK_PARAMS lock_req);
extern void bta_csip_send_lock_req_act(tBTA_CSET_CB* cset_cb);
extern void bta_csip_handle_lock_denial(tBTA_CSET_CB* cset_cb);
extern bool bta_csip_validate_req_for_denied_sm (tBTA_CSET_CB* cset_cb);
extern void bta_csip_form_lock_request(tBTA_SET_LOCK_PARAMS lock_param,
                                            tBTA_CSET_CB* cset_cb);
extern void bta_csip_send_unlock_req_act(tBTA_CSET_CB* cset_cb);
extern void bta_csip_set_member_lock_timeout(void* p_data);
extern void bta_csip_load_coordinated_sets_from_storage();

// bta_csip_utils
extern tBTA_CSIP_DEV_CB* bta_csip_find_dev_cb_by_bda(const RawAddress& bda);
extern tBTA_CSIP_DEV_CB* bta_csip_get_dev_cb_by_cid(uint16_t conn_id);
extern tBTA_CSIP_DEV_CB* bta_csip_create_dev_cb_for_bda(const RawAddress& bda);
extern tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_service_cb(tBTA_CSIP_DEV_CB* dev_cb);
extern bool bta_csip_is_csis_supported(tBTA_CSIP_DEV_CB* dev_cb);
extern tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_service_by_handle(tBTA_CSIP_DEV_CB* dev_cb,
                                                                uint16_t service_handle);
extern tBTA_CSIS_SRVC_INFO* bta_csip_find_csis_srvc_by_lock_handle(tBTA_CSIP_DEV_CB* dev_cb,
                                                                   uint16_t lock_handle);
extern tBTA_CSIP_CSET* bta_csip_get_or_create_cset (uint8_t set_id, bool existing);
extern bool bta_csip_validate_set_params(tBTA_SET_LOCK_PARAMS* lock_req);
extern bool bta_csip_is_valid_lock_request(tBTA_SET_LOCK_PARAMS* lock_req);
extern std::vector<RawAddress> bta_csip_arrange_set_members_by_order(
    uint8_t set_id, std::vector<RawAddress>& req_sm, bool ascending);
extern tBTA_CSIP_CSET bta_csip_get_coordinated_set (uint8_t set_id);
extern bool bta_csip_update_set_member (uint8_t set_id, RawAddress addr);
extern tBTA_CSET_CB* bta_csip_get_cset_cb ();
extern tBTA_CSET_CB* bta_csip_get_cset_cb_by_id (uint8_t set_id);
extern uint8_t bta_csip_find_set_id_by_sirk (uint8_t* sirk);
extern tBTA_CSIS_SRVC_INFO* bta_csip_get_csis_instance(tBTA_CSIP_DEV_CB* dev_cb, uint8_t set_id);
extern bool bta_csip_is_locked_by_other_apps(tBTA_CSIS_SRVC_INFO* srvc, uint8_t app_id);
extern std::vector<RawAddress> bta_csip_get_set_member_by_order(uint8_t set_id,
                                                                bool ascending);
extern bool bta_csip_is_member_locked_by_app (uint8_t app_id, tBTA_CSIS_SRVC_INFO* srvc);
extern void bta_csip_get_next_lock_request(tBTA_CSET_CB* cset_cb);
extern uint16_t bta_csip_get_cccd_handle (uint16_t conn_id, uint16_t char_handle);
extern bool bta_csip_is_app_reg(uint8_t app_id);
extern tBTA_CSIP_RCB* bta_csip_get_rcb (uint8_t app_id);
extern void bta_csip_remove_set_member (RawAddress addr);
extern void bta_csip_handle_notification(tBTA_GATTC_NOTIFY* ntf);
extern void bta_csip_handle_lock_value_notif(tBTA_CSIP_DEV_CB* p_cb,
                                             uint16_t handle, uint8_t value);
extern void bta_csip_add_app_to_applist(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id);
extern void bta_csip_handle_unresponsive_sm_res(tBTA_CSIS_SRVC_INFO* srvc,
                                                tGATT_STATUS status);
extern void bta_csip_remove_app_from_conn_list(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id);
extern bool bta_csip_is_app_from_applist(tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id);
extern void bta_csip_send_conn_state_changed_cb(tBTA_CSIP_DEV_CB* p_cb,
                                             uint8_t state, uint8_t status);
extern void bta_csip_send_conn_state_changed_cb (tBTA_CSIP_DEV_CB* p_cb, uint8_t app_id,
                                               uint8_t state, uint8_t status);
extern void bta_csip_send_lock_req_cmpl_cb (tBTA_LOCK_STATUS_CHANGED cset_cb);
extern void bta_csip_write_cccd (tBTA_CSIP_DEV_CB* p_cb, uint16_t char_handle,
                                 uint16_t cccd_handle);
extern void bta_csip_preserve_cset (tBTA_CSIS_SRVC_INFO* srvc);
extern Octet16 bta_csip_get_salt();
extern Octet16 bta_csip_compute_T(Octet16 salt, Octet16 K);
extern Octet16 bta_csip_compute_k1(Octet16 T);
extern void  bta_csip_get_decrypted_sirk(Octet16 k1, uint8_t *enc_sirk, uint8_t *sirk);
extern Octet16 bta_csip_get_aes_cmac_result(const Octet16& key, const Octet16& message);
extern Octet16 bta_csip_get_aes_cmac_result(const Octet16& key, const uint8_t* input,
                                            uint16_t length);
extern void hex_string_to_byte_arr(char *str, uint8_t* byte_arr, uint8_t len);
extern void byte_arr_to_hex_string(uint8_t* byte_arr, char* str, uint8_t len);
extern bool is_key_empty(Octet16& key);
#endif
