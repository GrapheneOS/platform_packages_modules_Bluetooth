/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#ifndef ANDROID_INCLUDE_BT_CSIP_H
#define ANDROID_INCLUDE_BT_CSIP_H

#include <stdint.h>
#include <bluetooth/uuid.h>
#include <vector>

__BEGIN_DECLS

#define BT_PROFILE_CSIP_CLIENT_ID "csip_client"

/** Callback when app has registered with CSIP Client module
 */
typedef void (* btcsip_csip_app_registered_callback)(uint8_t status, uint8_t app_id,
                                                     const bluetooth::Uuid& app_uuid);

/** Callback when connection state is changed for CSIP Profile
 */
typedef void (* btcsip_csip_connection_state_callback)(uint8_t app_id, RawAddress& bd_addr,
                                                       uint8_t state, uint8_t status);

/** Callback when new set has been identified on remote device
 */
typedef void (* btcsip_new_set_found_callback) (uint8_t set_id, RawAddress& bd_addr,
                                                uint8_t size, uint8_t* sirk,
                                                const bluetooth::Uuid& p_srvc_uuid,
                                                bool lock_support);

/** Callback when new set member has been identified
 */
typedef void (* btcsip_new_set_member_found_callback) (uint8_t set_id,
                                                       RawAddress& bd_addr);

/** Callback for lock status changed event to requesting client
 */
typedef void (* btcsip_lock_state_changed_callback) (uint8_t app_id, uint8_t set_id,
                                                     uint8_t value, uint8_t status,
                                                     std::vector<RawAddress> addr);

/** Callback when lock is available on earlier denying set member
 */
typedef void (* btcsip_lock_available_callback) (uint8_t app_id, uint8_t set_id,
                                                 RawAddress& bd_addr);

/** Callback when size of coordinated set has been changed
 */
typedef void (* btcsip_set_size_changed_callback) (uint8_t set_id, uint8_t size,
                                                   RawAddress& bd_addr);

/** Callback when SIRK of coordinated set has been changed
 */
typedef void (* btcsip_set_sirk_changed_callback) (uint8_t set_id, uint8_t* sirk,
                                                   RawAddress& bd_addr);

/** BT-CSIP callback structure. */
typedef struct {
    size_t size;
    btcsip_csip_app_registered_callback   app_registered_cb;
    btcsip_csip_connection_state_callback conn_state_cb;
    btcsip_new_set_found_callback         new_set_found_cb;
    btcsip_new_set_member_found_callback  new_set_member_cb;
    btcsip_lock_state_changed_callback    lock_status_cb;
    btcsip_lock_available_callback        lock_available_cb;
    btcsip_set_size_changed_callback      size_changed_cb;
    btcsip_set_sirk_changed_callback      sirk_changed_cb;
} btcsip_callbacks_t;

/** Represents the standard BT-CSIP interface. */
typedef struct {

    /** set to sizeof(BtCsipInterface) */
    size_t size;

    /** Register the BtCsipInterface callbacks
     */
    bt_status_t (*init) (btcsip_callbacks_t* callbacks);

    /** CSIP opportunistic gatt client connection*/
    bt_status_t (*connect) (uint8_t app_id, RawAddress *bd_addr);

    /** disconnect csip gatt connection */
    bt_status_t (*disconnect) (uint8_t app_id, RawAddress *bd_addr );

    /** register app/module with CSIP profile*/
    bt_status_t (*register_csip_app) (const bluetooth::Uuid& app_uuid);

    /** unregister app/module with CSIP profile */
    bt_status_t (*unregister_csip_app) (uint8_t app_id);

    /** change lock value */
    bt_status_t (*set_lock_value) (uint8_t app_id, uint8_t set_id, uint8_t lock_value,
                                  std::vector<RawAddress> devices);

    /** Closes the interface. */
    void  (*cleanup) (void);

} btcsip_interface_t;
__END_DECLS

#endif /* ANDROID_INCLUDE_BT_CSIP_H */
