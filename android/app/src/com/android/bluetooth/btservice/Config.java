/*
 * Copyright (C) 2012 The Android Open Source Project
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

import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.os.SystemProperties;
import android.sysprop.BluetoothProperties;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.a2dpsink.A2dpSinkService;
import com.android.bluetooth.avrcp.AvrcpTargetService;
import com.android.bluetooth.avrcpcontroller.AvrcpControllerService;
import com.android.bluetooth.bas.BatteryService;
import com.android.bluetooth.bass_client.BassClientService;
import com.android.bluetooth.csip.CsipSetCoordinatorService;
import com.android.bluetooth.gatt.GattService;
import com.android.bluetooth.hap.HapClientService;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.hfpclient.HeadsetClientService;
import com.android.bluetooth.hid.HidDeviceService;
import com.android.bluetooth.hid.HidHostService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.bluetooth.map.BluetoothMapService;
import com.android.bluetooth.mapclient.MapClientService;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.opp.BluetoothOppService;
import com.android.bluetooth.pan.PanService;
import com.android.bluetooth.pbap.BluetoothPbapService;
import com.android.bluetooth.pbapclient.PbapClientService;
import com.android.bluetooth.sap.SapService;
import com.android.bluetooth.tbs.TbsService;
import com.android.bluetooth.vc.VolumeControlService;
import com.android.internal.annotations.VisibleForTesting;

import java.util.Arrays;
import java.util.HashSet;

public class Config {
    private static final String TAG = "AdapterServiceConfig";

    private static final String LE_AUDIO_DYNAMIC_SWITCH_PROPERTY =
            "ro.bluetooth.leaudio_switcher.supported";
    private static final String LE_AUDIO_BROADCAST_DYNAMIC_SWITCH_PROPERTY =
            "ro.bluetooth.leaudio_broadcast_switcher.supported";
    private static final String LE_AUDIO_SWITCHER_DISABLED_PROPERTY =
            "persist.bluetooth.leaudio_switcher.disabled";

    private static class ProfileConfig {
        Class mClass;
        boolean mSupported;
        long mMask;

        ProfileConfig(Class theClass, boolean supported, long mask) {
            mClass = theClass;
            mSupported = supported;
            mMask = mask;
        }
    }

    /** List of profile services related to LE audio */
    private static final HashSet<Class> LE_AUDIO_UNICAST_PROFILES =
            new HashSet<Class>(
                    Arrays.asList(
                            LeAudioService.class,
                            VolumeControlService.class,
                            McpService.class,
                            CsipSetCoordinatorService.class,
                            TbsService.class));

    /**
     * List of profile services with the profile-supported resource flag and bit mask.
     */
    private static final ProfileConfig[] PROFILE_SERVICES_AND_FLAGS = {
            new ProfileConfig(A2dpService.class, A2dpService.isEnabled(),
                    (1 << BluetoothProfile.A2DP)),
            new ProfileConfig(A2dpSinkService.class, A2dpSinkService.isEnabled(),
                    (1 << BluetoothProfile.A2DP_SINK)),
            new ProfileConfig(AvrcpTargetService.class, AvrcpTargetService.isEnabled(),
                    (1 << BluetoothProfile.AVRCP)),
            new ProfileConfig(AvrcpControllerService.class, AvrcpControllerService.isEnabled(),
                    (1 << BluetoothProfile.AVRCP_CONTROLLER)),
            new ProfileConfig(BassClientService.class, BassClientService.isEnabled(),
                    (1 << BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT)),
            new ProfileConfig(BatteryService.class, BatteryService.isEnabled(),
                    (1 << BluetoothProfile.BATTERY)),
            new ProfileConfig(CsipSetCoordinatorService.class,
                    CsipSetCoordinatorService.isEnabled(),
                    (1 << BluetoothProfile.CSIP_SET_COORDINATOR)),
            new ProfileConfig(HapClientService.class, HapClientService.isEnabled(),
                    (1 << BluetoothProfile.HAP_CLIENT)),
            new ProfileConfig(HeadsetService.class, HeadsetService.isEnabled(),
                    (1 << BluetoothProfile.HEADSET)),
            new ProfileConfig(HeadsetClientService.class, HeadsetClientService.isEnabled(),
                    (1 << BluetoothProfile.HEADSET_CLIENT)),
            new ProfileConfig(HearingAidService.class, HearingAidService.isEnabled(),
                    (1 << BluetoothProfile.HEARING_AID)),
            new ProfileConfig(HidDeviceService.class, HidDeviceService.isEnabled(),
                    (1 << BluetoothProfile.HID_DEVICE)),
            new ProfileConfig(HidHostService.class, HidHostService.isEnabled(),
                    (1 << BluetoothProfile.HID_HOST)),
            new ProfileConfig(GattService.class, GattService.isEnabled(),
                    (1 << BluetoothProfile.GATT)),
            new ProfileConfig(LeAudioService.class, LeAudioService.isEnabled(),
                    (1 << BluetoothProfile.LE_AUDIO)),
            new ProfileConfig(TbsService.class, TbsService.isEnabled(),
                    (1 << BluetoothProfile.LE_CALL_CONTROL)),
            new ProfileConfig(BluetoothMapService.class, BluetoothMapService.isEnabled(),
                    (1 << BluetoothProfile.MAP)),
            new ProfileConfig(MapClientService.class, MapClientService.isEnabled(),
                    (1 << BluetoothProfile.MAP_CLIENT)),
            new ProfileConfig(McpService.class, McpService.isEnabled(),
                    (1 << BluetoothProfile.MCP_SERVER)),
            new ProfileConfig(BluetoothOppService.class, BluetoothOppService.isEnabled(),
                    (1 << BluetoothProfile.OPP)),
            new ProfileConfig(PanService.class, PanService.isEnabled(),
                    (1 << BluetoothProfile.PAN)),
            new ProfileConfig(BluetoothPbapService.class, BluetoothPbapService.isEnabled(),
                    (1 << BluetoothProfile.PBAP)),
            new ProfileConfig(PbapClientService.class, PbapClientService.isEnabled(),
                    (1 << BluetoothProfile.PBAP_CLIENT)),
            new ProfileConfig(SapService.class, SapService.isEnabled(),
                    (1 << BluetoothProfile.SAP)),
            new ProfileConfig(VolumeControlService.class, VolumeControlService.isEnabled(),
                    (1 << BluetoothProfile.VOLUME_CONTROL)),
    };

    /**
     * A test function to allow for dynamic enabled
     */
    @VisibleForTesting
    public static void setProfileEnabled(Class profileClass, boolean enabled) {
        if (profileClass == null) {
            return;
        }
        for (ProfileConfig profile : PROFILE_SERVICES_AND_FLAGS) {
            if (profileClass.equals(profile.mClass)) {
                profile.mSupported = enabled;
            }
        }
    }

    static void init(Context ctx) {
        if (LeAudioService.isBroadcastEnabled()) {
            updateSupportedProfileMask(
                    true, LeAudioService.class, BluetoothProfile.LE_AUDIO_BROADCAST);
        }

        final boolean leAudioDynamicSwitchSupported =
                SystemProperties.getBoolean(LE_AUDIO_DYNAMIC_SWITCH_PROPERTY, false);

        if (leAudioDynamicSwitchSupported) {
            final String leAudioSwitcherDisabled = SystemProperties
                    .get(LE_AUDIO_SWITCHER_DISABLED_PROPERTY, "none");
            if (leAudioSwitcherDisabled.equals("true")) {
                setLeAudioProfileStatus(false);
            } else if (leAudioSwitcherDisabled.equals("false")) {
                setLeAudioProfileStatus(true);
            }
        }

        // Disable ASHA on Automotive, TV, and Watch devices if the system property is not set
        // This means that the OS will not automatically enable ASHA on these platforms, but these
        // platforms can choose to enable ASHA themselves
        if (BluetoothProperties.isProfileAshaCentralEnabled().isEmpty()) {
            if (Utils.isAutomotive(ctx) || Utils.isTv(ctx) || Utils.isWatch(ctx)) {
                setProfileEnabled(HearingAidService.class, false);
            }
        }

        // Disable ASHA if BLE is not supported on this platform even if the platform enabled ASHA
        // accidentally
        if (!Utils.isBleSupported(ctx)) {
            setProfileEnabled(HearingAidService.class, false);
        }

        for (ProfileConfig config : PROFILE_SERVICES_AND_FLAGS) {
            Log.i(
                    TAG,
                    String.format(
                            "init: profile=%s, enabled=%s",
                            config.mClass.getSimpleName(), config.mSupported));
        }
    }

    static void setLeAudioProfileStatus(Boolean enable) {
        setProfileEnabled(CsipSetCoordinatorService.class, enable);
        setProfileEnabled(HapClientService.class, enable);
        setProfileEnabled(LeAudioService.class, enable);
        setProfileEnabled(TbsService.class, enable);
        setProfileEnabled(McpService.class, enable);
        setProfileEnabled(VolumeControlService.class, enable);

        final boolean broadcastDynamicSwitchSupported =
                SystemProperties.getBoolean(LE_AUDIO_BROADCAST_DYNAMIC_SWITCH_PROPERTY, false);

        if (broadcastDynamicSwitchSupported) {
            setProfileEnabled(BassClientService.class, enable);
            updateSupportedProfileMask(
                    enable, LeAudioService.class, BluetoothProfile.LE_AUDIO_BROADCAST);
        }
    }

    static void updateSupportedProfileMask(Boolean enable, Class profile, int supportedProfile) {
        for (ProfileConfig config : PROFILE_SERVICES_AND_FLAGS) {
            if (config.mClass == profile) {
                if (enable) {
                    config.mMask |= 1 << supportedProfile;
                } else {
                    config.mMask &= ~(1 << supportedProfile);
                }
                return;
            }
        }
    }

    static HashSet<Class> getLeAudioUnicastProfiles() {
        return LE_AUDIO_UNICAST_PROFILES;
    }

    static Class[] getSupportedProfiles() {
        return Arrays.stream(PROFILE_SERVICES_AND_FLAGS)
                .filter(config -> config.mSupported)
                .map(config -> config.mClass)
                .toArray(Class[]::new);
    }

    static long getSupportedProfilesBitMask() {
        long mask = 0;
        for (ProfileConfig config : PROFILE_SERVICES_AND_FLAGS) {
            if (config.mSupported) {
                mask |= config.mMask;
            }
        }
        return mask;
    }
}
