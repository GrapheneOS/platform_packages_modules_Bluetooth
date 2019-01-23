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

package com.android.bluetooth.btservice;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothProfile;

import androidx.annotation.NonNull;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "metadata")
class Metadata {
    @PrimaryKey
    @NonNull
    private String address;

    public boolean migrated;

    @Embedded
    public ProfilePrioritiesEntity profilePriorites;

    @Embedded
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
}
