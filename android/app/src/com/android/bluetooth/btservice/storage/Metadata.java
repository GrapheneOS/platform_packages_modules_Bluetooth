/*
 * Copyright 2019 The Android Open Source Project
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

package com.android.bluetooth.btservice.storage;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;

import androidx.annotation.NonNull;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

import java.util.ArrayList;
import java.util.List;

@Entity(tableName = "metadata")
class Metadata {
    @PrimaryKey
    @NonNull
    private String address;

    public boolean migrated;

    @Embedded
    public ProfilePrioritiesEntity profilePriorites;

    @Embedded
    @NonNull
    public CustomizedMetaEntity publicMeta;

    public int a2dpSupportsOptionalCodecs;
    public int a2dpOptionalCodecsEnabled;

    Metadata(String address) {
        this.address = address;
        migrated = false;
        profilePriorites = new ProfilePrioritiesEntity();
        publicMeta = new CustomizedMetaEntity();
        a2dpSupportsOptionalCodecs = BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED;
        a2dpOptionalCodecsEnabled = BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED;
    }

    String getAddress() {
        return address;
    }

    void setProfilePriority(int profile, int priority) {
        switch (profile) {
            case BluetoothProfile.A2DP:
                profilePriorites.a2dp_priority = priority;
                break;
            case BluetoothProfile.A2DP_SINK:
                profilePriorites.a2dp_sink_priority = priority;
                break;
            case BluetoothProfile.HEADSET:
                profilePriorites.hfp_priority = priority;
                break;
            case BluetoothProfile.HEADSET_CLIENT:
                profilePriorites.hfp_client_priority = priority;
                break;
            case BluetoothProfile.HID_HOST:
                profilePriorites.hid_host_priority = priority;
                break;
            case BluetoothProfile.PAN:
                profilePriorites.pan_priority = priority;
                break;
            case BluetoothProfile.PBAP:
                profilePriorites.pbap_priority = priority;
                break;
            case BluetoothProfile.MAP:
                profilePriorites.map_priority = priority;
                break;
            case BluetoothProfile.MAP_CLIENT:
                profilePriorites.map_client_priority = priority;
                break;
            case BluetoothProfile.SAP:
                profilePriorites.sap_priority = priority;
                break;
            case BluetoothProfile.HEARING_AID:
                profilePriorites.hearing_aid_priority = priority;
                break;
            default:
                throw new IllegalArgumentException("invalid profile " + profile);
        }
    }

    int getProfilePriority(int profile) {
        switch (profile) {
            case BluetoothProfile.A2DP:
                return profilePriorites.a2dp_priority;
            case BluetoothProfile.A2DP_SINK:
                return profilePriorites.a2dp_sink_priority;
            case BluetoothProfile.HEADSET:
                return profilePriorites.hfp_priority;
            case BluetoothProfile.HEADSET_CLIENT:
                return profilePriorites.hfp_client_priority;
            case BluetoothProfile.HID_HOST:
                return profilePriorites.hid_host_priority;
            case BluetoothProfile.PAN:
                return profilePriorites.pan_priority;
            case BluetoothProfile.PBAP:
                return profilePriorites.pbap_priority;
            case BluetoothProfile.MAP:
                return profilePriorites.map_priority;
            case BluetoothProfile.MAP_CLIENT:
                return profilePriorites.map_client_priority;
            case BluetoothProfile.SAP:
                return profilePriorites.sap_priority;
            case BluetoothProfile.HEARING_AID:
                return profilePriorites.hearing_aid_priority;
        }
        return BluetoothProfile.PRIORITY_UNDEFINED;
    }

    void setCustomizedMeta(int key, String value) {
        switch (key) {
            case BluetoothDevice.METADATA_MANUFACTURER_NAME:
                publicMeta.manufacturer_name = value;
                break;
            case BluetoothDevice.METADATA_MODEL_NAME:
                publicMeta.model_name = value;
                break;
            case BluetoothDevice.METADATA_SOFTWARE_VERSION:
                publicMeta.software_version = value;
                break;
            case BluetoothDevice.METADATA_HARDWARE_VERSION:
                publicMeta.hardware_version = value;
                break;
            case BluetoothDevice.METADATA_COMPANION_APP:
                publicMeta.companion_app = value;
                break;
            case BluetoothDevice.METADATA_MAIN_ICON:
                publicMeta.main_icon = value;
                break;
            case BluetoothDevice.METADATA_IS_UNTHETHERED_HEADSET:
                publicMeta.is_unthethered_headset = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_ICON:
                publicMeta.unthethered_left_icon = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_ICON:
                publicMeta.unthethered_right_icon = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_ICON:
                publicMeta.unthethered_case_icon = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_BATTERY:
                publicMeta.unthethered_left_battery = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_BATTERY:
                publicMeta.unthethered_right_battery = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_BATTERY:
                publicMeta.unthethered_case_battery = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_CHARGING:
                publicMeta.unthethered_left_charging = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_CHARGING:
                publicMeta.unthethered_right_charging = value;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_CHARGING:
                publicMeta.unthethered_case_charging = value;
                break;
            case BluetoothDevice.METADATA_ENHANCED_SETTINGS_UI_URI:
                publicMeta.enhanced_settings_ui_uri = value;
                break;
        }
    }

    String getCustomizedMeta(int key) {
        String value = null;
        switch (key) {
            case BluetoothDevice.METADATA_MANUFACTURER_NAME:
                value = publicMeta.manufacturer_name;
                break;
            case BluetoothDevice.METADATA_MODEL_NAME:
                value = publicMeta.model_name;
                break;
            case BluetoothDevice.METADATA_SOFTWARE_VERSION:
                value = publicMeta.software_version;
                break;
            case BluetoothDevice.METADATA_HARDWARE_VERSION:
                value = publicMeta.hardware_version;
                break;
            case BluetoothDevice.METADATA_COMPANION_APP:
                value = publicMeta.companion_app;
                break;
            case BluetoothDevice.METADATA_MAIN_ICON:
                value = publicMeta.main_icon;
                break;
            case BluetoothDevice.METADATA_IS_UNTHETHERED_HEADSET:
                value = publicMeta.is_unthethered_headset;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_ICON:
                value = publicMeta.unthethered_left_icon;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_ICON:
                value = publicMeta.unthethered_right_icon;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_ICON:
                value = publicMeta.unthethered_case_icon;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_BATTERY:
                value = publicMeta.unthethered_left_battery;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_BATTERY:
                value = publicMeta.unthethered_right_battery;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_BATTERY:
                value = publicMeta.unthethered_case_battery;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_LEFT_CHARGING:
                value = publicMeta.unthethered_left_charging;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_RIGHT_CHARGING:
                value = publicMeta.unthethered_right_charging;
                break;
            case BluetoothDevice.METADATA_UNTHETHERED_CASE_CHARGING:
                value = publicMeta.unthethered_case_charging;
                break;
            case BluetoothDevice.METADATA_ENHANCED_SETTINGS_UI_URI:
                value = publicMeta.enhanced_settings_ui_uri;
                break;
        }
        return value;
    }

    List<Integer> getChangedCustomizedMeta() {
        List<Integer> list = new ArrayList<>();
        if (publicMeta.manufacturer_name != null) {
            list.add(BluetoothDevice.METADATA_MANUFACTURER_NAME);
        }
        if (publicMeta.model_name != null) {
            list.add(BluetoothDevice.METADATA_MODEL_NAME);
        }
        if (publicMeta.software_version != null) {
            list.add(BluetoothDevice.METADATA_SOFTWARE_VERSION);
        }
        if (publicMeta.hardware_version != null) {
            list.add(BluetoothDevice.METADATA_HARDWARE_VERSION);
        }
        if (publicMeta.companion_app != null) {
            list.add(BluetoothDevice.METADATA_COMPANION_APP);
        }
        if (publicMeta.main_icon != null) {
            list.add(BluetoothDevice.METADATA_MAIN_ICON);
        }
        if (publicMeta.is_unthethered_headset != null) {
            list.add(BluetoothDevice.METADATA_IS_UNTHETHERED_HEADSET);
        }
        if (publicMeta.unthethered_left_icon != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_LEFT_ICON);
        }
        if (publicMeta.unthethered_right_icon != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_RIGHT_ICON);
        }
        if (publicMeta.unthethered_case_icon != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_CASE_ICON);
        }
        if (publicMeta.unthethered_left_battery != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_LEFT_BATTERY);
        }
        if (publicMeta.unthethered_right_battery != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_RIGHT_BATTERY);
        }
        if (publicMeta.unthethered_case_battery != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_CASE_BATTERY);
        }
        if (publicMeta.unthethered_left_charging != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_LEFT_CHARGING);
        }
        if (publicMeta.unthethered_right_charging != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_RIGHT_CHARGING);
        }
        if (publicMeta.unthethered_case_charging != null) {
            list.add(BluetoothDevice.METADATA_UNTHETHERED_CASE_CHARGING);
        }
        if (publicMeta.enhanced_settings_ui_uri != null) {
            list.add(BluetoothDevice.METADATA_ENHANCED_SETTINGS_UI_URI);
        }
        return list;
    }
}
