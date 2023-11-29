/*
 * Copyright 2023 The Android Open Source Project
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

import static android.bluetooth.IBluetoothLeAudio.LE_AUDIO_GROUP_ID_INVALID;

import android.annotation.NonNull;
import android.annotation.RequiresPermission;
import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHearingAid;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothSinkAudioPolicy;
import android.media.AudioDeviceCallback;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.ArrayMap;
import android.util.Log;
import android.util.SparseArray;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.btservice.storage.DatabaseManager;
import com.android.bluetooth.flags.FeatureFlags;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class AudioRoutingManager extends ActiveDeviceManager {
    private static final String TAG = AudioRoutingManager.class.getSimpleName();
    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
    @VisibleForTesting static final int A2DP_HFP_SYNC_CONNECTION_TIMEOUT_MS = 5_000;

    private final AdapterService mAdapterService;
    private DatabaseManager mDbManager;
    private final ServiceFactory mFactory;
    private HandlerThread mHandlerThread = null;
    private AudioRoutingHandler mHandler = null;
    private final AudioManager mAudioManager;
    private final AudioManagerAudioDeviceCallback mAudioManagerAudioDeviceCallback;

    @Override
    public void onBluetoothStateChange(int prevState, int newState) {
        mHandler.post(() -> handleAdapterStateChanged(newState));
    }

    /**
     * Called when audio profile connection state changed
     *
     * @param profile The Bluetooth profile of which connection state changed
     * @param device The device of which connection state was changed
     * @param fromState The previous connection state of the device
     * @param toState The new connection state of the device
     */
    @Override
    public void profileConnectionStateChanged(
            int profile, BluetoothDevice device, int fromState, int toState) {
        if (toState == BluetoothProfile.STATE_CONNECTED) {
            mHandler.post(() -> mHandler.handleProfileConnected(profile, device));
        } else if (fromState == BluetoothProfile.STATE_CONNECTED) {
            mHandler.post(() -> mHandler.handleProfileDisconnected(profile, device));
        }
    }

    /**
     * Requests to activate a specific profile for the given device.
     *
     * @param device The device to be activated.
     * @param profile The profile to be activated
     */
    public void activateDeviceProfile(BluetoothDevice device, int profile) {
        mHandler.post(
                () ->
                        mHandler.activateDeviceProfile(
                                mHandler.getAudioRoutingDevice(device), profile));
    }

    /**
     * Requests to remove active device for a specific profile.
     *
     * @param profile The profile to be deactivated
     */
    public void removeActiveDevice(int profile, boolean hasFallbackDevice) {
        mHandler.post(() -> mHandler.removeActiveDevice(profile, hasFallbackDevice));
    }

    /**
     * Called when active state of audio profiles changed
     *
     * @param profile The Bluetooth profile of which active state changed
     * @param device The device currently activated. {@code null} if no device is active
     */
    @Override
    public void profileActiveDeviceChanged(int profile, BluetoothDevice device) {
        mHandler.post(() -> mHandler.handleProfileActiveDeviceChanged(profile, device));
    }

    private void handleAdapterStateChanged(int currentState) {
        if (DBG) {
            Log.d(TAG, "handleAdapterStateChanged: currentState=" + currentState);
        }
        if (currentState == BluetoothAdapter.STATE_ON) {
            mHandler.resetState();
        }
    }

    AudioRoutingManager(AdapterService service, ServiceFactory factory, FeatureFlags featureFlags) {
        super(service, factory, featureFlags);
        mAdapterService = service;
        mDbManager = mAdapterService.getDatabase();
        mFactory = factory;
        mAudioManager = service.getSystemService(AudioManager.class);
        mAudioManagerAudioDeviceCallback = new AudioManagerAudioDeviceCallback();
    }

    @Override
    void start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }

        mHandlerThread = new HandlerThread("BluetoothActiveDeviceManager");
        BluetoothMethodProxy mp = BluetoothMethodProxy.getInstance();
        mp.threadStart(mHandlerThread);
        mHandler = new AudioRoutingHandler(mp.handlerThreadGetLooper(mHandlerThread));

        mAudioManager.registerAudioDeviceCallback(mAudioManagerAudioDeviceCallback, mHandler);
        mAdapterService.registerBluetoothStateCallback((command) -> mHandler.post(command), this);
    }

    @Override
    void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }

        mAudioManager.unregisterAudioDeviceCallback(mAudioManagerAudioDeviceCallback);
        mAdapterService.unregisterBluetoothStateCallback(this);
        if (mHandlerThread != null) {
            mHandlerThread.quit();
            mHandlerThread = null;
        }
        mHandler.resetState();
    }

    /**
     * Get the {@link Looper} for the handler thread. This is used in testing and helper objects
     *
     * @return {@link Looper} for the handler thread
     */
    @VisibleForTesting
    @Override
    public Looper getHandlerLooper() {
        if (mHandler == null) {
            return null;
        }
        return mHandler.getLooper();
    }

    List<BluetoothDevice> getActiveDevices(int profile) {
        List<BluetoothDevice> devices = mHandler.mActiveDevices.get(profile);
        return devices == null ? Collections.emptyList() : devices;
    }

    /**
     * Checks whether it is Okay to activate HFP when the device is connected.
     *
     * @param device the remote device
     * @return {@code true} if the device should be activated when connected.
     */
    private boolean shouldActivateWhenConnected(BluetoothDevice device) {
        // Check CoD
        BluetoothClass deviceClass = device.getBluetoothClass();
        if (deviceClass != null
                && deviceClass.getDeviceClass() == BluetoothClass.Device.WEARABLE_WRIST_WATCH) {
            Log.i(TAG, "Do not set profile active for watch device when connected: " + device);
            return false;
        }
        // Check the audio device policy
        HeadsetService service = mFactory.getHeadsetService();
        BluetoothSinkAudioPolicy audioPolicy = service.getHfpCallAudioPolicy(device);
        if (audioPolicy != null
                && audioPolicy.getActiveDevicePolicyAfterConnection()
                        == BluetoothSinkAudioPolicy.POLICY_NOT_ALLOWED) {
            Log.i(
                    TAG,
                    "The device's HFP call audio policy doesn't allow it to be activated when"
                            + " connected: "
                            + device);
            return false;
        }

        // Check metadata
        byte[] deviceType = mDbManager.getCustomMeta(device, BluetoothDevice.METADATA_DEVICE_TYPE);
        if (deviceType == null) {
            return true;
        }
        String deviceTypeStr = new String(deviceType);
        if (deviceTypeStr.equals(BluetoothDevice.DEVICE_TYPE_WATCH)) {
            Log.i(TAG, "Do not set profile active for watch device when connected: " + device);
            return false;
        }
        return true;
    }

    /** Notifications of audio device connection and disconnection events. */
    @SuppressLint("AndroidFrameworkRequiresPermission")
    private class AudioManagerAudioDeviceCallback extends AudioDeviceCallback {
        private boolean isWiredAudioHeadset(AudioDeviceInfo deviceInfo) {
            switch (deviceInfo.getType()) {
                case AudioDeviceInfo.TYPE_WIRED_HEADSET:
                case AudioDeviceInfo.TYPE_WIRED_HEADPHONES:
                case AudioDeviceInfo.TYPE_USB_HEADSET:
                    return true;
                default:
                    break;
            }
            return false;
        }

        // Called in mHandler thread. See AudioRoutingManager.start()
        @Override
        public void onAudioDevicesAdded(AudioDeviceInfo[] addedDevices) {
            if (DBG) {
                Log.d(TAG, "onAudioDevicesAdded");
            }
            boolean hasAddedWiredDevice = false;
            for (AudioDeviceInfo deviceInfo : addedDevices) {
                if (DBG) {
                    Log.d(
                            TAG,
                            "Audio device added: "
                                    + deviceInfo.getProductName()
                                    + " type: "
                                    + deviceInfo.getType());
                }
                if (isWiredAudioHeadset(deviceInfo)) {
                    hasAddedWiredDevice = true;
                    break;
                }
            }
            if (hasAddedWiredDevice) {
                mHandler.wiredAudioDeviceConnected();
            }
        }

        // TODO: check whether BT headset is properly activated when a wired headset removed.
        @Override
        public void onAudioDevicesRemoved(AudioDeviceInfo[] removedDevices) {}
    }

    private class AudioRoutingHandler extends Handler {
        private final ArrayMap<BluetoothDevice, AudioRoutingDevice> mConnectedDevices =
                new ArrayMap<>();
        private final SparseArray<List<BluetoothDevice>> mActiveDevices = new SparseArray<>();

        AudioRoutingHandler(Looper looper) {
            super(looper);
        }

        public void handleProfileConnected(int profile, BluetoothDevice device) {
            if (DBG) {
                Log.d(
                        TAG,
                        "handleProfileConnected(device="
                                + device
                                + ", profile="
                                + BluetoothProfile.getProfileName(profile)
                                + ")");
            }
            AudioRoutingDevice arDevice = getAudioRoutingDevice(device);
            if (arDevice.connectedProfiles.contains(profile)) {
                if (DBG) {
                    Log.d(TAG, "This device is already connected: " + device);
                }
                return;
            }
            arDevice.connectedProfiles.add(profile);
            if (!shouldActivateWhenConnected(device)) {
                return;
            }
            if (!arDevice.canActivateNow(profile)) {
                if (DBG) {
                    Log.d(TAG, "Can not activate now: " + BluetoothProfile.getProfileName(profile));
                }
                mHandler.postDelayed(
                        () -> activateDeviceProfile(arDevice, profile),
                        arDevice,
                        A2DP_HFP_SYNC_CONNECTION_TIMEOUT_MS);
                return;
            }
            activateDeviceProfile(arDevice, profile);
        }

        public void handleProfileDisconnected(int profile, BluetoothDevice device) {
            if (DBG) {
                Log.d(
                        TAG,
                        "handleProfileDisconnected(device="
                                + device
                                + ", profile="
                                + BluetoothProfile.getProfileName(profile)
                                + ")");
            }
            AudioRoutingDevice arDevice = getAudioRoutingDevice(device);
            arDevice.connectedProfiles.remove(profile);
            if (arDevice.connectedProfiles.isEmpty()) {
                mConnectedDevices.remove(device);
            }
            List<BluetoothDevice> activeDevices = mActiveDevices.get(profile);
            if (activeDevices != null && activeDevices.contains(device)) {
                activeDevices.remove(device);
                if (activeDevices.size() == 0) {
                    if (!setFallbackDeviceActive()) {
                        removeActiveDevice(profile, false);
                    }
                }
            }
        }

        // TODO: check the IllegalStateException is not happening after refactoring.
        public void handleProfileActiveDeviceChanged(int profile, BluetoothDevice device) {
            if (device == null && !mActiveDevices.contains(profile)) return;
            List<BluetoothDevice> activeDevices = mActiveDevices.get(profile);
            if (activeDevices != null && activeDevices.contains(device)) return;
            throw new IllegalStateException(
                    "Unexpected deactivation events: "
                            + BluetoothProfile.getProfileName(profile)
                            + ", device="
                            + device);
        }

        private boolean setFallbackDeviceActive() {
            if (DBG) {
                Log.d(TAG, "setFallbackDeviceActive");
            }
            List<BluetoothDevice> candidates = new ArrayList<>();
            int audioMode = mAudioManager.getMode();
            for (AudioRoutingDevice arDevice : mConnectedDevices.values()) {
                for (int profile : arDevice.connectedProfiles) {
                    if (audioMode == AudioManager.MODE_NORMAL) {
                        if (profile != BluetoothProfile.HEADSET) {
                            candidates.add(arDevice.device);
                            break;
                        }
                    } else {
                        if (profile != BluetoothProfile.A2DP) {
                            candidates.add(arDevice.device);
                            break;
                        }
                    }
                }
            }
            AudioRoutingDevice deviceToActivate = null;
            BluetoothDevice device = mDbManager.getMostRecentlyConnectedDevicesInList(candidates);
            if (device != null) {
                deviceToActivate = getAudioRoutingDevice(device);
            }
            if (deviceToActivate != null) {
                if (DBG) {
                    Log.d(TAG, "activateDevice: device=" + deviceToActivate.device);
                }
                // Try to activate hearing aid and LE audio first
                if (deviceToActivate.connectedProfiles.contains(BluetoothProfile.HEARING_AID)) {
                    return activateDeviceProfile(deviceToActivate, BluetoothProfile.HEARING_AID);
                } else if (deviceToActivate.connectedProfiles.contains(BluetoothProfile.LE_AUDIO)) {
                    return activateDeviceProfile(deviceToActivate, BluetoothProfile.LE_AUDIO);
                } else if (deviceToActivate.connectedProfiles.contains(BluetoothProfile.A2DP)) {
                    return activateDeviceProfile(deviceToActivate, BluetoothProfile.A2DP);
                } else if (deviceToActivate.connectedProfiles.contains(BluetoothProfile.HEADSET)) {
                    return activateDeviceProfile(deviceToActivate, BluetoothProfile.HEADSET);
                }
                Log.w(
                        TAG,
                        "Fail to activate the device: "
                                + deviceToActivate.device
                                + ", no connected audio profiles");
            }
            return false;
        }

        // TODO: handle the connection policy change events.
        private AudioRoutingDevice getAudioRoutingDevice(@NonNull BluetoothDevice device) {
            Objects.requireNonNull(device);
            AudioRoutingDevice arDevice = mConnectedDevices.get(device);
            if (arDevice != null) {
                return arDevice;
            }
            arDevice = new AudioRoutingDevice();
            arDevice.device = device;
            arDevice.supportedProfiles = new HashSet<>();
            arDevice.connectedProfiles = new HashSet<>();
            if (mDbManager.getProfileConnectionPolicy(device, BluetoothProfile.HEADSET)
                    == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                arDevice.supportedProfiles.add(BluetoothProfile.HEADSET);
            } else {
                arDevice.supportedProfiles.remove(BluetoothProfile.HEADSET);
            }
            if (mDbManager.getProfileConnectionPolicy(device, BluetoothProfile.A2DP)
                    == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                arDevice.supportedProfiles.add(BluetoothProfile.A2DP);
            } else {
                arDevice.supportedProfiles.remove(BluetoothProfile.A2DP);
            }
            if (mDbManager.getProfileConnectionPolicy(device, BluetoothProfile.HEARING_AID)
                    == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                arDevice.supportedProfiles.add(BluetoothProfile.HEARING_AID);
            } else {
                arDevice.supportedProfiles.remove(BluetoothProfile.HEARING_AID);
            }
            if (mDbManager.getProfileConnectionPolicy(device, BluetoothProfile.LE_AUDIO)
                    == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                arDevice.supportedProfiles.add(BluetoothProfile.LE_AUDIO);
            } else {
                arDevice.supportedProfiles.remove(BluetoothProfile.LE_AUDIO);
            }
            mConnectedDevices.put(device, arDevice);
            return arDevice;
        }

        /**
         * Activate the given profile and related profiles if possible. A2DP and HFP would be
         * activated together if possible. If there are any activated profiles that can't be
         * activated together, they will be deactivated.
         *
         * @param arDevice the device of which one or more profiles to be activated
         * @param profile the profile requited to be activated
         * @return true if any profile was activated or the given profile was already active.
         */
        @SuppressLint("MissingPermission")
        public boolean activateDeviceProfile(@NonNull AudioRoutingDevice arDevice, int profile) {
            mHandler.removeCallbacksAndMessages(arDevice);
            if (DBG) {
                Log.d(
                        TAG,
                        "activateDeviceProfile("
                                + arDevice.device
                                + ", "
                                + BluetoothProfile.getProfileName(profile)
                                + ")");
            }

            List<BluetoothDevice> activeDevices = mActiveDevices.get(profile);
            if (activeDevices != null && activeDevices.contains(arDevice.device)) {
                return true;
            }

            HashSet<Integer> profilesToActivate = new HashSet<>();
            HashSet<Integer> profilesToDeactivate = new HashSet<>();
            for (int i = 0; i < mActiveDevices.size(); i++) {
                profilesToDeactivate.add(mActiveDevices.keyAt(i));
            }

            profilesToActivate.add(profile);
            profilesToDeactivate.remove(profile);

            boolean checkLeAudioActive;
            switch (profile) {
                case BluetoothProfile.A2DP:
                    profilesToDeactivate.remove(BluetoothProfile.HEADSET);
                    checkLeAudioActive =
                            !arDevice.supportedProfiles.contains(BluetoothProfile.HEADSET);
                    if (arDevice.connectedProfiles.contains(BluetoothProfile.HEADSET)) {
                        profilesToActivate.add(BluetoothProfile.HEADSET);
                        checkLeAudioActive = true;
                    }
                    if (checkLeAudioActive
                            && Utils.isDualModeAudioEnabled()
                            && arDevice.connectedProfiles.contains(BluetoothProfile.LE_AUDIO)) {
                        profilesToActivate.add(BluetoothProfile.LE_AUDIO);
                        profilesToDeactivate.remove(BluetoothProfile.LE_AUDIO);
                    }
                    break;
                case BluetoothProfile.HEADSET:
                    profilesToDeactivate.remove(BluetoothProfile.A2DP);
                    checkLeAudioActive =
                            !arDevice.supportedProfiles.contains(BluetoothProfile.A2DP);
                    if (arDevice.connectedProfiles.contains(BluetoothProfile.A2DP)) {
                        profilesToActivate.add(BluetoothProfile.A2DP);
                        checkLeAudioActive = true;
                    }
                    if (checkLeAudioActive
                            && Utils.isDualModeAudioEnabled()
                            && arDevice.connectedProfiles.contains(BluetoothProfile.LE_AUDIO)) {
                        profilesToActivate.add(BluetoothProfile.LE_AUDIO);
                        profilesToDeactivate.remove(BluetoothProfile.LE_AUDIO);
                    }
                    break;
                case BluetoothProfile.LE_AUDIO:
                    if (Utils.isDualModeAudioEnabled()) {
                        if (arDevice.connectedProfiles.contains(BluetoothProfile.A2DP)) {
                            profilesToActivate.add(BluetoothProfile.A2DP);
                            profilesToDeactivate.remove(BluetoothProfile.A2DP);
                        }
                        if (arDevice.connectedProfiles.contains(BluetoothProfile.HEADSET)) {
                            profilesToActivate.add(BluetoothProfile.HEADSET);
                            profilesToDeactivate.remove(BluetoothProfile.HEADSET);
                        }
                    }
                    break;
            }
            boolean isAnyProfileActivated = false;
            for (int p : profilesToActivate) {
                activeDevices = mActiveDevices.get(p);
                if (activeDevices == null || !activeDevices.contains(arDevice.device)) {
                    isAnyProfileActivated |= setActiveDevice(p, arDevice.device);
                } else {
                    isAnyProfileActivated = true;
                }
            }
            // Do not deactivate profiles if no profiles were activated.
            if (!isAnyProfileActivated) return false;
            if (profilesToActivate.contains(BluetoothProfile.LE_AUDIO)
                    || profilesToActivate.contains(BluetoothProfile.HEARING_AID)) {
                // Deactivate activated profiles if it doesn't contain the arDevice.
                for (int i = 0; i < mActiveDevices.size(); i++) {
                    if (!mActiveDevices.valueAt(i).contains(arDevice.device)) {
                        profilesToDeactivate.add(mActiveDevices.keyAt(i));
                    }
                }
            }
            for (int p : profilesToDeactivate) {
                removeActiveDevice(p, true);
            }
            return true;
        }

        @SuppressLint("MissingPermission")
        private boolean setActiveDevice(int profile, BluetoothDevice device) {
            if (DBG) {
                Log.d(
                        TAG,
                        "setActiveDevice("
                                + BluetoothProfile.getProfileName(profile)
                                + ", "
                                + device
                                + ")");
            }
            boolean activated = switch (profile) {
                case BluetoothProfile.A2DP -> {
                    A2dpService service = mFactory.getA2dpService();
                    yield service == null ? false : service.setActiveDevice(device);
                }
                case BluetoothProfile.HEADSET -> {
                    HeadsetService service = mFactory.getHeadsetService();
                    yield service == null ? false : service.setActiveDevice(device);
                }
                case BluetoothProfile.LE_AUDIO -> {
                    LeAudioService service = mFactory.getLeAudioService();
                    yield service == null ? false : service.setActiveDevice(device);
                }
                case BluetoothProfile.HEARING_AID -> {
                    HearingAidService service = mFactory.getHearingAidService();
                    yield service == null ? false : service.setActiveDevice(device);
                }
                default -> false;
            };
            if (activated) {
                List<BluetoothDevice> activeDevices = mActiveDevices.get(profile);
                if (activeDevices == null) {
                    activeDevices = new ArrayList<>();
                    mActiveDevices.put(profile, activeDevices);
                }
                if (!canActivateTogether(profile, device, activeDevices)) {
                    activeDevices.clear();
                }
                activeDevices.add(device);
            }
            return activated;
        }

        private boolean removeActiveDevice(int profile, boolean hasFallbackDevice) {
            if (DBG) {
                Log.d(
                        TAG,
                        "removeActiveDevice("
                                + BluetoothProfile.getProfileName(profile)
                                + ", hadFallbackDevice="
                                + hasFallbackDevice
                                + ")");
            }
            mActiveDevices.remove(profile);
            return switch (profile) {
                case BluetoothProfile.A2DP -> {
                    A2dpService service = mFactory.getA2dpService();
                    yield service == null ? false : service.removeActiveDevice(!hasFallbackDevice);
                }
                case BluetoothProfile.HEADSET -> {
                    HeadsetService service = mFactory.getHeadsetService();
                    yield service == null ? false : service.setActiveDevice(null);
                }
                case BluetoothProfile.LE_AUDIO -> {
                    LeAudioService service = mFactory.getLeAudioService();
                    yield service == null ? false : service.removeActiveDevice(hasFallbackDevice);
                }
                case BluetoothProfile.HEARING_AID -> {
                    HearingAidService service = mFactory.getHearingAidService();
                    yield service == null ? false : service.removeActiveDevice(!hasFallbackDevice);
                }
                default -> false;
            };
        }

        private boolean canActivateTogether(
                int profile, BluetoothDevice device, List<BluetoothDevice> group) {
            if (device == null || group == null || group.isEmpty()) {
                return false;
            }
            switch (profile) {
                case BluetoothProfile.LE_AUDIO:
                    {
                        final LeAudioService leAudioService = mFactory.getLeAudioService();
                        if (leAudioService == null) {
                            return false;
                        }
                        int groupId = leAudioService.getGroupId(device);
                        if (groupId != LE_AUDIO_GROUP_ID_INVALID
                                && groupId == leAudioService.getGroupId(group.get(0))) {
                            return true;
                        }
                        break;
                    }
                case BluetoothProfile.HEARING_AID:
                    {
                        final HearingAidService hearingAidService = mFactory.getHearingAidService();
                        if (hearingAidService == null) {
                            return false;
                        }
                        long hiSyncId = hearingAidService.getHiSyncId(device);
                        if (hiSyncId != BluetoothHearingAid.HI_SYNC_ID_INVALID
                                && hiSyncId == hearingAidService.getHiSyncId(group.get(0))) {
                            return true;
                        }
                        break;
                    }
            }
            return false;
        }

        /**
         * Called when a wired audio device is connected. It might be called multiple times each
         * time a wired audio device is connected.
         */
        @VisibleForTesting
        @RequiresPermission(android.Manifest.permission.MODIFY_PHONE_STATE)
        void wiredAudioDeviceConnected() {
            if (DBG) {
                Log.d(TAG, "wiredAudioDeviceConnected");
            }
            removeActiveDevice(BluetoothProfile.A2DP, true);
            removeActiveDevice(BluetoothProfile.HEADSET, true);
            removeActiveDevice(BluetoothProfile.HEARING_AID, true);
            removeActiveDevice(BluetoothProfile.LE_AUDIO, true);
        }

        private void resetState() {
            mConnectedDevices.clear();
            mActiveDevices.clear();
        }

        private static class AudioRoutingDevice {
            public BluetoothDevice device;
            public Set<Integer> supportedProfiles;
            public Set<Integer> connectedProfiles;

            public boolean canActivateNow(int profile) {
                if (!connectedProfiles.contains(profile)) return false;
                // TODO: Return false if there are another active remote streaming an audio.
                return switch (profile) {
                    case BluetoothProfile.HEADSET -> !supportedProfiles.contains(
                                    BluetoothProfile.A2DP)
                            || connectedProfiles.contains(BluetoothProfile.A2DP);
                    case BluetoothProfile.A2DP -> !supportedProfiles.contains(
                                    BluetoothProfile.HEADSET)
                            || connectedProfiles.contains(BluetoothProfile.HEADSET);
                    case BluetoothProfile.LE_AUDIO -> !Utils.isDualModeAudioEnabled()
                            // Check all supported A2DP and HFP are connected if dual mode enabled
                            || ((connectedProfiles.contains(BluetoothProfile.A2DP)
                                            || !supportedProfiles.contains(BluetoothProfile.A2DP))
                                    && (connectedProfiles.contains(BluetoothProfile.HEADSET)
                                            || !supportedProfiles.contains(
                                                    BluetoothProfile.HEADSET)));
                    default -> true;
                };
            }
        }
    }
}
