/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#ifndef ANDROID_INCLUDE_BT_BAP_BA_H
#define ANDROID_INCLUDE_BT_BAP_BA_H

#include <hardware/bluetooth.h>
#include "hardware/bt_av.h"

__BEGIN_DECLS

#define BT_PROFILE_BAP_BROADCAST_ID "bap_broadcast"

/* Bluetooth BAP BROADCAST states */
typedef enum {
    BTBAP_BROADCAST_STATE_IDLE = 0, //Idle
    BTBAP_BROADCAST_STATE_CONFIGURED, //Configured
    BTBAP_BROADCAST_STATE_STREAMING, //Streaming
} btbap_broadcast_state_t;

/* Bluetooth BAP BROADCAST Audio states */
typedef enum {
    BTBAP_BROADCAST_AUDIO_STATE_STOPPED = 0,
    BTBAP_BROADCAST__AUDIO_STATE_STARTED,
} btbap_broadcast_audio_state_t;

/** Callback for broadcast state change.
 *  state will have one of the values from btbap_broadcast_state_t
 */
typedef void (* bap_broadcast_state_callback)(int adv_id,
                                           btbap_broadcast_state_t state);

/** Callback for audiopath state change.
 *  state will have one of the values from btbap_broadcast_audio_state_t
 */
typedef void (* bap_broadcast_audio_state_callback)(int adv_id,
                                           btbap_broadcast_audio_state_t state);

/** Callback for audio configuration change.
 */
typedef void (* bap_broadcast_audio_config_callback)(int adv_id,
                               btav_a2dp_codec_config_t codec_config,
                               std::vector<btav_a2dp_codec_config_t> codec_capabilities);

/** Callback for Iso datapath setup or removed.
 */
//typedef void (* bap_broadcast_iso_datapath_callback) (int big_handle, int enabled);

/** Callback for encryption key generation notification
 */
typedef void (* bap_broadcast_enckey_callback) (std::string key);

/** Callback to create/terminate BIG
 */

typedef void (* bap_broadcast_setup_big_callback) (int enable, int adv_id, int big_handle,
                                                       int num_bises, std::vector<uint16_t> bis_handles);

typedef void (* bap_broadcast_bid_callback) (std::vector<uint8_t> broadcast_id);

/** BT-BAP-BROADCAST callback structure. */
typedef struct {
    /** set to sizeof(btbap_broadcast_callbacks_t) */
    size_t      size;
    bap_broadcast_state_callback  broadcast_state_cb;
    bap_broadcast_audio_state_callback audio_state_cb;
    bap_broadcast_audio_config_callback audio_config_cb;
    //bap_broadcast_iso_datapath_callback iso_datapath_cb;
    bap_broadcast_enckey_callback enc_key_cb;
    bap_broadcast_setup_big_callback create_big_cb;
    bap_broadcast_bid_callback broadcast_id_cb;
} btbap_broadcast_callbacks_t;

typedef struct {

    /** set to sizeof(btav_source_interface_t) */
    size_t          size;
    /**
     * Register the btbap_broadcast callbacks.
     */
    bt_status_t (*init)(btbap_broadcast_callbacks_t* callbacks,
                int max_broadcast, btav_a2dp_codec_config_t config, int mode);

    /** Enable broadcast with provided codec config */
    bt_status_t (*enable_broadcast)(btav_a2dp_codec_config_t config);

    /** disable broadcast to move the state machine to idle state */
    bt_status_t (*disable_broadcast)(int adv_id);

    /** sets bap broadcast as active session */
    bt_status_t (*set_broadcast_active)(bool enable, uint8_t adv_id);

    /** configure the codecs settings preferences */
    bt_status_t (*codec_config_change)(uint8_t adv_id, btav_a2dp_codec_config_t config);

    /** Disable ISO datapath */
    bt_status_t (*setup_audiopath)(bool enable, uint8_t adv_id, uint8_t big_handle, int num_bises, int* bis_handles);

    /** Get stored encryption key */
    std::string (*get_encryption_key)( void );

    /** Set Encryption with encryption lenght provided */
    bt_status_t (*set_encryption) (bool enabled, uint8_t key_length);

    /** Closes the interface. */
    void  (*cleanup)( void );

} btbap_broadcast_interface_t;
__END_DECLS
#endif /*ANDROID_INCLUDE_BT_BAP_BA_H*/

