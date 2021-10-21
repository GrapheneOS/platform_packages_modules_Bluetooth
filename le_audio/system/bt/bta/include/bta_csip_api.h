/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

/******************************************************************************
 *
 *  This is the public interface file to provide CSIP API's.
 *
 ******************************************************************************/

#ifndef BTA_CSIP_API_H
#define BTA_CSIP_API_H

//#include "bta_api.h"
#include <bluetooth/uuid.h>
#include <raw_address.h>

#include "bta_gatt_api.h" //temp

#include <vector>

#define SIRK_SIZE 16        // SIRK Size
#define UNLOCK_VALUE 0x01   // UNLOCK Value
#define LOCK_VALUE   0x02   // LOCK Value
#define ENCRYPTED_SIRK 0x00     // Encrypted SIRK Type
#define PLAINTEXT_SIRK 0x01     // Plain Text SIRK
#define INVALID_SET_ID 0x10 // Invalid set id

/* status for applications for LOCK Status changed callback*/
enum {
  LOCK_RELEASED,                      // (LOCK Released successfully)
  LOCK_RELEASED_TIMEOUT,              // (LOCK Released by timeout)
  ALL_LOCKS_ACQUIRED,                 // (LOCK Acquired for all requested set members)
  SOME_LOCKS_ACQUIRED_REASON_TIMEOUT, // (Request timeout for some set members)
  SOME_LOCKS_ACQUIRED_REASON_DISC,    // (Some of the set members were disconnected)
  LOCK_DENIED,                        // (Denied by one of the set members)
  INVALID_REQUEST_PARAMS,             // (Upper layer provided invalid parameters)
  LOCK_RELEASE_NOT_ALLOWED,           // (Response from remote (PTS))
  INVALID_VALUE,                      // (Response from remote (PTS))
};

/* LOCK Request Error Codes from set members */
#define CSIP_LOCK_DENIED 0x80
#define CSIP_LOCK_RELEASE_NOT_ALLOWED 0x81
#define CSIP_INVALID_LOCK_VALUE 0x82
#define CSIP_LOCK_ALREADY_GRANTED 0x84

/* Events when CSIP operations are completed */
#define BTA_CSIP_NEW_SET_FOUND_EVT 1
#define BTA_CSIP_SET_MEMBER_FOUND_EVT 2
#define BTA_CSIP_CONN_STATE_CHG_EVT 3
#define BTA_CSIP_LOCK_STATUS_CHANGED_EVT 4
#define BTA_CSIP_LOCK_AVAILABLE_EVT 5
#define BTA_CSIP_SET_SIZE_CHANGED 6
#define BTA_CSIP_SET_SIRK_CHANGED 7

/* CSIP operation completed event*/
typedef uint8_t tBTA_CSIP_EVT;

enum {
  BTA_CSIP_SUCCESS,
  BTA_CSIP_FAILURE,
};

/* CSIP Operation Status*/
typedef uint8_t tBTA_CSIP_STATUS;

/* CSIP GATT Connection States (to be notified to upper layer)*/
/* Mapping to BluetoothProfile Connection States*/
enum {
  BTA_CSIP_DISCONNECTED,
  BTA_CSIP_CONNECTED = 0x02,
};

 /* CSIP device GATT Connection state */
typedef uint8_t tBTA_CSIP_CONN_STATE;

enum {
  BTA_CSIP_CONN_ESTABLISHED = 0x40, // reason values to be decided
  BTA_CSIP_CONN_ESTABLISHMENT_FAILED,
  BTA_CSIP_APP_ALREADY_CONNECTED,
  BTA_CSIP_APP_ALREADY_DISCONNECTED,
  BTA_CSIP_APP_DISCONNECTED,
  BTA_CSIP_DISCONNECT_WITHOUT_CONNECT,
  BTA_CSIP_COORDINATED_SET_NOT_SUPPORTED,
};

/* CSIP device GATT Connection state */
typedef uint8_t tBTA_CSIP_CONN_STATUS;

/* Params in callback to requesting app when lock status has been changed */
typedef struct {
  uint8_t app_id;
  uint8_t set_id;
  uint8_t value = UNLOCK_VALUE;
  uint8_t status;
  std::vector<RawAddress> addr;
} tBTA_LOCK_STATUS_CHANGED;

/* Params in callback to registered app when coordinated set member is discovered */
typedef struct {
  uint8_t set_id;
  bluetooth::Uuid uuid;
  RawAddress addr;
} tBTA_SET_MEMBER_FOUND;

/* Params in callback to registered app when discovery for coordinated set is completed */
/*TODO: not required, to be removed */
typedef struct {
  uint8_t set_id;
  bluetooth::Uuid uuid;
  std::vector<RawAddress> addr;
} tBTA_SET_DISC_CMPL;

/* params in callback to app when lock is available on earlier denied member*/
typedef struct {
  uint8_t app_id;
  uint8_t set_id;
  RawAddress addr;
} tBTA_LOCK_AVAILABLE;

/* params in callback to app space when new set is found*/
typedef struct {
  uint8_t set_id;
  uint8_t sirk[SIRK_SIZE];
  uint8_t size;
  bool lock_support;
  RawAddress addr;
  bluetooth::Uuid including_srvc_uuid;
} tBTA_CSIP_NEW_SET_FOUND;

/* params in callback to app when set size is changed */
typedef struct {
  uint8_t set_id;
  uint8_t size;
  RawAddress addr;
} tBTA_CSIP_SET_SIZE_CHANGED;

/* params in callback to app when set sirk is changed */
typedef struct {
  uint8_t set_id;
  uint8_t* sirk;
  RawAddress addr;
} tBTA_CSIP_SET_SIRK_CHANGED;

/* params in callback to app when connection state has been changed */
typedef struct {
  uint8_t app_id;
  RawAddress addr;
  tBTA_CSIP_CONN_STATE state;
  tBTA_CSIP_CONN_STATUS status;
} tBTA_CSIP_CONN_STATE_CHANGED;

/* callbacks params on completion of CSIP operations */
typedef union {
  tBTA_LOCK_STATUS_CHANGED lock_status_param;
  tBTA_CSIP_CONN_STATE_CHANGED conn_params;
  tBTA_SET_MEMBER_FOUND set_member_param;
  tBTA_SET_DISC_CMPL set_disc_cmpl_param;
  tBTA_LOCK_AVAILABLE lock_available_param;
  tBTA_CSIP_NEW_SET_FOUND new_set_params;
  tBTA_CSIP_CONN_STATE_CHANGED conn_chg_params;
  tBTA_CSIP_SET_SIZE_CHANGED size_chg_params;
  tBTA_CSIP_SET_SIRK_CHANGED sirk_chg_params;
} tBTA_CSIP_DATA;

/* CSIP callbacks to be given to upper layers*/

/* Callback given when one of the operation mentioned in */
typedef void (tBTA_CSIP_CBACK) (tBTA_CSIP_EVT event, tBTA_CSIP_DATA* p_data);

/* Callback when application is registered with CSIP */
typedef void (tBTA_CSIP_CLT_REG_CB) (tBTA_CSIP_STATUS status, uint8_t app_id);

/* parameters used for api BTA_CsipSetLockValue() */
typedef struct {
  uint8_t app_id;
  uint8_t set_id;
  uint8_t lock_value;
  std::vector<RawAddress> members_addr;
} tBTA_SET_LOCK_PARAMS;

/* Coordinated set details */
typedef struct {
  uint8_t set_id;
  uint8_t size;
  uint8_t total_discovered;
  bool lock_support;
  std::vector<RawAddress> set_members;
  bluetooth::Uuid p_srvc_uuid;
} tBTA_CSIP_CSET;

using BtaCsipAppRegisteredCb =
    base::Callback<void(uint8_t /* status */, uint8_t /* app_id */)>;

/*********************************************************************************
 *
 * Function         BTA_RegisterCsipApp
 *
 * Description      This function is called to register application or module to
 *                  to register with CSIP for using CSIP functionalities.
 *
 * Parameters       p_csip_cb: callback to be received in registering app when
 *                             required CSIP operation is completed.
 *                  reg_cb   : callback when app/module is registered with CSIP.
 *
 * Returns          None
 *
 *********************************************************************************/
extern void BTA_RegisterCsipApp(tBTA_CSIP_CBACK* p_csip_cb,
                              BtaCsipAppRegisteredCb reg_cb);

/*********************************************************************************
 *
 * Function         BTA_UnregisterCsipApp
 *
 * Description      This function is called to register application or module to
 *                  to register with CSIP for using CSIP functionalities.
 *
 * Parameters       app_id: Identifier of the app that needs to be unregistered.
 *
 * Returns          None
 *
 *********************************************************************************/
extern void BTA_UnregisterCsipApp(uint8_t app_id);

/*********************************************************************************
 *
 * Function         BTA_CsipSetLockValue
 *
 * Description      This function is called to request or release lock for the
 *                  coordinated set.
 *
 * Parameters       lock_param: parameters to acquire or release lock.
 *                             (tBTA_SET_LOCK_PARAMS).
 *
 * Returns          None
 *
 *********************************************************************************/
extern void BTA_CsipSetLockValue(tBTA_SET_LOCK_PARAMS lock_param);

/*********************************************************************************
 *
 * Function         BTA_CsipGetCoordinatedSet
 *
 * Description      This function is called to fetch details of the coordinated set.
 *
 * Parameters       set_id: identifier of the coordinated set whose details are
 *                          required to be fetched.
 *
 * Returns          tBTA_CSIP_CSET (containing details of coordinated set).
 *
 *********************************************************************************/
extern tBTA_CSIP_CSET BTA_CsipGetCoordinatedSet(uint8_t set_id);

/*********************************************************************************
 *
 * Function         BTA_CsipSetLockValue
 *
 * Description      This function is called to request or release lock for the
 *                  coordinated set.
 *
 * Parameters       None.
 *
 * Returns          vector<tBTIF_CSIP_CSET>: (all discovered coordinated set)
 *
 *********************************************************************************/
extern std::vector<tBTA_CSIP_CSET> BTA_CsipGetDiscoveredSets();

/*********************************************************************************
 *
 * Function         BTA_CsipConnect
 *
 * Description      This function is called to establish GATT Connection.
 *
 * Parameters       bd_addr : Address of the remote device.
 *
 * Returns          None.
 *
 * Note             This shouldnt be used by registered module. CSIP Profile
 *                  internally manages GATT Connection.
 *
 *********************************************************************************/
extern void BTA_CsipConnect (uint8_t app_id, const RawAddress& bd_addr);

/*********************************************************************************
 *
 * Function         BTA_CsipConnect
 *
 * Description      This function is called to establish GATT Connection.
 *
 * Parameters       bd_addr : Address of the remote device.
 *
 * Returns          None.
 *
 * Note             This shouldnt be used by registered module. CSIP Profile
 *                  internally manages GATT Connection.
 *
 *********************************************************************************/
extern void BTA_CsipDisconnect (uint8_t app_id, const RawAddress& bd_addr);


/*********************************************************************************
 *
 * Function         BTA_CsipEnable
 *
 * Description      This function is invoked to initialize CSIP in BTA layer.
 *
 * Parameters       p_cback: callbacks registered with btif_csip module.
 *
 * Returns          None.
 *
 * Note             This API shouldn't be used by other BT modules.
 *
 *********************************************************************************/
extern void BTA_CsipEnable(tBTA_CSIP_CBACK *p_cback);

/*********************************************************************************
 *
 * Function         BTA_CsipEnable
 *
 * Description      This function is invoked to deinitialize CSIP in BTA layer.
 *
 * Parameters       None.
 *
 * Returns          None.
 *
 * Note             This API shouldn't be used by other BT modules.
 *
 *********************************************************************************/
extern void BTA_CsipDisable();

/*********************************************************************************
 *
 * Function         BTA_CsipFindCsisInstance
 *
 * Description      This function is invoked to find presence of CSIS service on
 *                  remote device and start coordinated set discovery.
 *
 * Parameters       conn_id: GATT Connection ID used for getting remote services
 *                  status : Status of the discovery procedure
 *
 * Returns          None.
 *
 * Note             This API shouldn't be used by other BT modules.
 *
 *********************************************************************************/
extern void BTA_CsipFindCsisInstance(uint16_t conn_id, tGATT_STATUS status,
                                     RawAddress& bd_addr);

/*********************************************************************************
 *
 * Function         BTA_CsipRemoveUnpairedSetMember
 *
 * Description      This function is called when a given set member is unpaired.
 *
 * Parameters       addr: BD Address of the set member.
 *
 * Returns          None.
 *
 * Note             This API shouldn't be used by other BT modules.
 *
 *********************************************************************************/
void BTA_CsipRemoveUnpairedSetMember(RawAddress addr);

/*********************************************************************************
 *
 * Function         BTA_CsipGetDeviceSetId
 *
 * Description      This API is used to get set id of the remote device.
 *
 * Parameters       addr: BD Address of the set member.
 *                  uuid: UUID of the service which includes CSIS service.
 *
 * Returns          None.
 *
 *********************************************************************************/
uint8_t BTA_CsipGetDeviceSetId(RawAddress addr, bluetooth::Uuid uuid);


#endif /* BTA_CSIP_API_H */
