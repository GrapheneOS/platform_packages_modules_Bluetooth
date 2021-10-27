/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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


#ifndef ANDROID_INCLUDE_BT_APM_H
#define ANDROID_INCLUDE_BT_APM_H

#define BT_APM_MODULE_ID "apm"

#include <vector>

#include <hardware/bluetooth.h>

__BEGIN_DECLS

/* Bluetooth APM Audio Types */
typedef enum {
    BTAPM_VOICE_AUDIO = 0,
    BTAPM_MEDIA_AUDIO,
    BTAPM_BROADCAST_AUDIO
} btapm_audio_type_t;

void call_active_profile_info(const RawAddress& bd_addr, uint16_t audio_type);
int get_active_profile(const RawAddress& bd_addr, uint16_t audio_type);
typedef int (*btapm_active_profile_callback)(const RawAddress& bd_addr, uint16_t audio_type);


typedef struct {
        size_t          size;
        btapm_active_profile_callback active_profile_cb;
}btapm_initiator_callbacks_t;



/** APM interface
 */
typedef struct {

    /** set to sizeof(bt_apm_interface_t) */
    size_t          size;
    /**
     * Register the BtAv callbacks.
     */
    bt_status_t (*init)(btapm_initiator_callbacks_t* callbacks);

    /** updates new active device to stack */
    bt_status_t (*active_device_change)(const RawAddress& bd_addr, uint16_t profile, uint16_t audio_type);

    /** send content control id to stack */
    bt_status_t (*set_content_control_id)(uint16_t content_control_id, uint16_t audio_type);

    /** Closes the interface. */
    void  (*cleanup)( void );

}bt_apm_interface_t;

__END_DECLS

#endif /* ANDROID_INCLUDE_BT_APM_H */

