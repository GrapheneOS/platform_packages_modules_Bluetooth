/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package com.android.bluetooth.hap;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.Manifest.permission.BLUETOOTH_PRIVILEGED;

import android.bluetooth.BluetoothCsipSetCoordinator;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHapClient;
import android.bluetooth.BluetoothHapPresetInfo;
import android.bluetooth.BluetoothLeAudio;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothHapClient;
import android.content.AttributionSource;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.HandlerThread;
import android.os.ParcelUuid;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.bluetooth.csip.CsipSetCoordinatorService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.internal.annotations.VisibleForTesting;
import com.android.modules.utils.SynchronousResultReceiver;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Objects;

/**
 * Provides Bluetooth Hearing Access profile, as a service.
 * @hide
 */
public class HapClientService extends ProfileService {
    private static final boolean DBG = true;
    private static final String TAG = "HapClientService";

    // Upper limit of all HearingAccess devices: Bonded or Connected
    private static final int MAX_HEARING_ACCESS_STATE_MACHINES = 10;
    private static HapClientService sHapClient;
    private final Map<BluetoothDevice, HapClientStateMachine> mStateMachines =
            new HashMap<>();
    @VisibleForTesting
    HapClientNativeInterface mHapClientNativeInterface;
    private AdapterService mAdapterService;
    private HandlerThread mStateMachinesThread;
    private BroadcastReceiver mBondStateChangedReceiver;
    private BroadcastReceiver mConnectionStateChangedReceiver;

    private final Map<BluetoothDevice, Integer> mDeviceCurrentPresetMap = new HashMap<>();
    private final Map<BluetoothDevice, Integer> mDeviceFeaturesMap = new HashMap<>();
    private final Map<BluetoothDevice, ArrayList<BluetoothHapPresetInfo>> mPresetsMap =
            new HashMap<>();

    @VisibleForTesting
    ServiceFactory mFactory = new ServiceFactory();

    private static synchronized void setHapClient(HapClientService instance) {
        if (DBG) {
            Log.d(TAG, "setHapClient(): set to: " + instance);
        }
        sHapClient = instance;
    }

    /**
     * Get the HapClientService instance
     * @return HapClientService instance
     */
    public static synchronized HapClientService getHapClientService() {
        if (sHapClient == null) {
            Log.w(TAG, "getHapClientService(): service is NULL");
            return null;
        }

        if (!sHapClient.isAvailable()) {
            Log.w(TAG, "getHapClientService(): service is not available");
            return null;
        }
        return sHapClient;
    }

    @Override
    protected void create() {
        if (DBG) {
            Log.d(TAG, "create()");
        }
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothHapClientBinder(this);
    }

    @Override
    protected boolean start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }

        if (sHapClient != null) {
            throw new IllegalStateException("start() called twice");
        }

        // Get AdapterService, HapClientNativeInterface, AudioManager.
        // None of them can be null.
        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when HapClientService starts");
        mHapClientNativeInterface = Objects.requireNonNull(
                HapClientNativeInterface.getInstance(),
                "HapClientNativeInterface cannot be null when HapClientService starts");

        // Start handler thread for state machines
        mStateMachines.clear();
        mStateMachinesThread = new HandlerThread("HapClientService.StateMachines");
        mStateMachinesThread.start();

        mDeviceCurrentPresetMap.clear();
        mDeviceFeaturesMap.clear();
        mPresetsMap.clear();

        // Setup broadcast receivers
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        mBondStateChangedReceiver = new BondStateChangedReceiver();
        registerReceiver(mBondStateChangedReceiver, filter);
        filter = new IntentFilter();
        filter.addAction(BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED);
        mConnectionStateChangedReceiver = new ConnectionStateChangedReceiver();
        registerReceiver(mConnectionStateChangedReceiver, filter, Context.RECEIVER_NOT_EXPORTED);

        // Mark service as started
        setHapClient(this);

        // Initialize native interface
        mHapClientNativeInterface.init();

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }
        if (sHapClient == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        // Cleanup GATT interface
        mHapClientNativeInterface.cleanup();
        mHapClientNativeInterface = null;

        // Marks service as stopped
        setHapClient(null);

        // Unregister broadcast receivers
        unregisterReceiver(mBondStateChangedReceiver);
        mBondStateChangedReceiver = null;
        unregisterReceiver(mConnectionStateChangedReceiver);
        mConnectionStateChangedReceiver = null;

        // Destroy state machines and stop handler thread
        synchronized (mStateMachines) {
            for (HapClientStateMachine sm : mStateMachines.values()) {
                sm.doQuit();
                sm.cleanup();
            }
            mStateMachines.clear();
        }

        mDeviceCurrentPresetMap.clear();
        mDeviceFeaturesMap.clear();
        mPresetsMap.clear();

        if (mStateMachinesThread != null) {
            mStateMachinesThread.quitSafely();
            mStateMachinesThread = null;
        }

        // Clear AdapterService
        mAdapterService = null;

        return true;
    }

    @VisibleForTesting
    void bondStateChanged(BluetoothDevice device, int bondState) {
        if (DBG) {
            Log.d(TAG, "Bond state changed for device: " + device + " state: " + bondState);
        }

        // Remove state machine if the bonding for a device is removed
        if (bondState != BluetoothDevice.BOND_NONE) {
            return;
        }

        mDeviceCurrentPresetMap.remove(device);
        mDeviceFeaturesMap.remove(device);
        mPresetsMap.remove(device);

        synchronized (mStateMachines) {
            HapClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                return;
            }
            if (sm.getConnectionState() != BluetoothProfile.STATE_DISCONNECTED) {
                return;
            }
            removeStateMachine(device);
        }
    }

    private void removeStateMachine(BluetoothDevice device) {
        synchronized (mStateMachines) {
            HapClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                Log.w(TAG, "removeStateMachine: device " + device
                        + " does not have a state machine");
                return;
            }
            Log.i(TAG, "removeStateMachine: removing state machine for device: " + device);
            sm.doQuit();
            sm.cleanup();
            mStateMachines.remove(device);
        }
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_CONNECT, "Need BLUETOOTH_CONNECT permission");
        ArrayList<BluetoothDevice> devices = new ArrayList<>();
        if (states == null) {
            return devices;
        }
        final BluetoothDevice[] bondedDevices = mAdapterService.getBondedDevices();
        if (bondedDevices == null) {
            return devices;
        }
        synchronized (mStateMachines) {
            for (BluetoothDevice device : bondedDevices) {
                final ParcelUuid[] featureUuids = device.getUuids();
                if (!Utils.arrayContains(featureUuids, BluetoothUuid.HAS)) {
                    continue;
                }
                int connectionState = BluetoothProfile.STATE_DISCONNECTED;
                HapClientStateMachine sm = mStateMachines.get(device);
                if (sm != null) {
                    connectionState = sm.getConnectionState();
                }
                for (int state : states) {
                    if (connectionState == state) {
                        devices.add(device);
                        break;
                    }
                }
            }
            return devices;
        }
    }

    List<BluetoothDevice> getConnectedDevices() {
        synchronized (mStateMachines) {
            List<BluetoothDevice> devices = new ArrayList<>();
            for (HapClientStateMachine sm : mStateMachines.values()) {
                if (sm.isConnected()) {
                    devices.add(sm.getDevice());
                }
            }
            return devices;
        }
    }

    /**
     * Get the current connection state of the profile
     *
     * @param device is the remote bluetooth device
     * @return {@link BluetoothProfile#STATE_DISCONNECTED} if this profile is disconnected,
     * {@link BluetoothProfile#STATE_CONNECTING} if this profile is being connected,
     * {@link BluetoothProfile#STATE_CONNECTED} if this profile is connected, or
     * {@link BluetoothProfile#STATE_DISCONNECTING} if this profile is being disconnected
     */
    public int getConnectionState(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_CONNECT, "Need BLUETOOTH_CONNECT permission");
        synchronized (mStateMachines) {
            HapClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return sm.getConnectionState();
        }
    }

    /**
     * Set connection policy of the profile and connects it if connectionPolicy is
     * {@link BluetoothProfile#CONNECTION_POLICY_ALLOWED} or disconnects if connectionPolicy is
     * {@link BluetoothProfile#CONNECTION_POLICY_FORBIDDEN}
     *
     * <p> The device should already be paired.
     * Connection policy can be one of:
     * {@link BluetoothProfile#CONNECTION_POLICY_ALLOWED},
     * {@link BluetoothProfile#CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile#CONNECTION_POLICY_UNKNOWN}
     *
     * @param device           the remote device
     * @param connectionPolicy is the connection policy to set to for this profile
     * @return true on success, otherwise false
     */
    public boolean setConnectionPolicy(BluetoothDevice device, int connectionPolicy) {
        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
                "Need BLUETOOTH_PRIVILEGED permission");
        if (DBG) {
            Log.d(TAG, "Saved connectionPolicy " + device + " = " + connectionPolicy);
        }
        mAdapterService.getDatabase()
                .setProfileConnectionPolicy(device, BluetoothProfile.HAP_CLIENT,
                        connectionPolicy);
        if (connectionPolicy == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
            connect(device);
        } else if (connectionPolicy == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            disconnect(device);
        }
        return true;
    }

    /**
     * Get the connection policy of the profile.
     *
     * <p> The connection policy can be any of:
     * {@link BluetoothProfile#CONNECTION_POLICY_ALLOWED},
     * {@link BluetoothProfile#CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile#CONNECTION_POLICY_UNKNOWN}
     *
     * @param device Bluetooth device
     * @return connection policy of the device
     * @hide
     */
    public int getConnectionPolicy(BluetoothDevice device) {
        return mAdapterService.getDatabase()
                .getProfileConnectionPolicy(device, BluetoothProfile.HAP_CLIENT);
    }

    /**
     * Check whether can connect to a peer device.
     * The check considers a number of factors during the evaluation.
     *
     * @param device the peer device to connect to
     * @return true if connection is allowed, otherwise false
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean okToConnect(BluetoothDevice device) {
        // Check if this is an incoming connection in Quiet mode.
        if (mAdapterService.isQuietModeEnabled()) {
            Log.e(TAG, "okToConnect: cannot connect to " + device + " : quiet mode enabled");
            return false;
        }
        // Check connection policy and accept or reject the connection.
        int connectionPolicy = getConnectionPolicy(device);
        int bondState = mAdapterService.getBondState(device);
        // Allow this connection only if the device is bonded. Any attempt to connect while
        // bonding would potentially lead to an unauthorized connection.
        if (bondState != BluetoothDevice.BOND_BONDED) {
            Log.w(TAG, "okToConnect: return false, bondState=" + bondState);
            return false;
        } else if (connectionPolicy != BluetoothProfile.CONNECTION_POLICY_UNKNOWN
                && connectionPolicy != BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
            // Otherwise, reject the connection if connectionPolicy is not valid.
            Log.w(TAG, "okToConnect: return false, connectionPolicy=" + connectionPolicy);
            return false;
        }
        return true;
    }

    @VisibleForTesting
    synchronized void connectionStateChanged(BluetoothDevice device, int fromState,
                                             int toState) {
        if ((device == null) || (fromState == toState)) {
            Log.e(TAG, "connectionStateChanged: unexpected invocation. device=" + device
                    + " fromState=" + fromState + " toState=" + toState);
            return;
        }

        // Check if the device is disconnected - if unbond, remove the state machine
        if (toState == BluetoothProfile.STATE_DISCONNECTED) {
            int bondState = mAdapterService.getBondState(device);
            if (bondState == BluetoothDevice.BOND_NONE) {
                if (DBG) {
                    Log.d(TAG, device + " is unbond. Remove state machine");
                }
                removeStateMachine(device);
            }
        }
    }

    /**
     * Connects the hearing access service client to the passed in device
     *
     * @param device is the device with which we will connect the hearing access service client
     * @return true if hearing access service client successfully connected, false otherwise
     */
    public boolean connect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
                "Need BLUETOOTH_PRIVILEGED permission");
        if (DBG) {
            Log.d(TAG, "connect(): " + device);
        }
        if (device == null) {
            return false;
        }

        if (getConnectionPolicy(device) == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            return false;
        }
        ParcelUuid[] featureUuids = mAdapterService.getRemoteUuids(device);
        if (!Utils.arrayContains(featureUuids, BluetoothUuid.HAS)) {
            Log.e(TAG, "Cannot connect to " + device
                    + " : Remote does not have Hearing Access Service UUID");
            return false;
        }
        synchronized (mStateMachines) {
            HapClientStateMachine smConnect = getOrCreateStateMachine(device);
            if (smConnect == null) {
                Log.e(TAG, "Cannot connect to " + device + " : no state machine");
            }
            smConnect.sendMessage(HapClientStateMachine.CONNECT);
        }

        return true;
    }

    /**
     * Disconnects hearing access service client for the passed in device
     *
     * @param device is the device with which we want to disconnect the hearing access service
     * client
     * @return true if hearing access service client successfully disconnected, false otherwise
     */
    public boolean disconnect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
                "Need BLUETOOTH_PRIVILEGED permission");
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device);
        }
        if (device == null) {
            return false;
        }
        synchronized (mStateMachines) {
            HapClientStateMachine sm = mStateMachines.get(device);
            if (sm != null) {
                sm.sendMessage(HapClientStateMachine.DISCONNECT);
            }
        }

        return true;
    }

    private HapClientStateMachine getOrCreateStateMachine(BluetoothDevice device) {
        if (device == null) {
            Log.e(TAG, "getOrCreateStateMachine failed: device cannot be null");
            return null;
        }
        synchronized (mStateMachines) {
            HapClientStateMachine sm = mStateMachines.get(device);
            if (sm != null) {
                return sm;
            }
            // Limit the maximum number of state machines to avoid DoS attack
            if (mStateMachines.size() >= MAX_HEARING_ACCESS_STATE_MACHINES) {
                Log.e(TAG, "Maximum number of HearingAccess state machines reached: "
                        + MAX_HEARING_ACCESS_STATE_MACHINES);
                return null;
            }
            if (DBG) {
                Log.d(TAG, "Creating a new state machine for " + device);
            }
            sm = HapClientStateMachine.make(device, this,
                    mHapClientNativeInterface, mStateMachinesThread.getLooper());
            mStateMachines.put(device, sm);
            return sm;
        }
    }

    /**
     * Gets the hearing access device group of the passed device
     *
     * @param device is the device with which we want to get the group identifier for
     * @return group ID if device is part of the coordinated group, 0 otherwise
     */
    public int getHapGroup(BluetoothDevice device) {
        CsipSetCoordinatorService csipClient = mFactory.getCsipSetCoordinatorService();

        if (csipClient != null) {
            Map<Integer, ParcelUuid> groups = csipClient.getGroupUuidMapByDevice(device);
            for (Map.Entry<Integer, ParcelUuid> entry : groups.entrySet()) {
                if (entry.getValue().equals(BluetoothUuid.CAP)) {
                    return entry.getKey();
                }
            }
        }
        return BluetoothCsipSetCoordinator.GROUP_ID_INVALID;
    }

    /**
     * Gets the currently active preset index for a HA device
     *
     * @param device is the device for which we want to get the currently active preset
     * @return true if valid request was sent, false otherwise
     */
    public boolean getActivePresetIndex(BluetoothDevice device) {
        notifyActivePresetIndex(device, mDeviceCurrentPresetMap.getOrDefault(device,
                BluetoothHapClient.PRESET_INDEX_UNAVAILABLE));
        return true;
    }

    /**
     * Selects the currently active preset for a HA device
     *
     * @param device is the device for which we want to set the active preset
     * @param presetIndex is an index of one of the available presets
     * @return true if valid request was sent, false otherwise
     */
    public boolean selectActivePreset(BluetoothDevice device, int presetIndex) {
        if (presetIndex == BluetoothHapClient.PRESET_INDEX_UNAVAILABLE) return false;
        mHapClientNativeInterface.selectActivePreset(device, presetIndex);
        return true;
    }

    /**
     * Selects the currently active preset for a HA device group.
     *
     * @param groupId is the device group identifier for which want to set the active preset
     * @param presetIndex is an index of one of the available presets
     * @return true if valid group request was sent, false otherwise
     */
    public boolean groupSelectActivePreset(int groupId, int presetIndex) {
        if (presetIndex == BluetoothHapClient.PRESET_INDEX_UNAVAILABLE
                || groupId == BluetoothCsipSetCoordinator.GROUP_ID_INVALID) {
            return false;
        }

        mHapClientNativeInterface.groupSelectActivePreset(groupId, presetIndex);
        return true;
    }

    /**
     * Sets the next preset as a currently active preset for a HA device
     *
     * @param device is the device for which we want to set the active preset
     * @return true if valid request was sent, false otherwise
     */
    public boolean nextActivePreset(BluetoothDevice device) {
        mHapClientNativeInterface.nextActivePreset(device);
        return true;
    }

    /**
     * Sets the next preset as a currently active preset for a HA device group
     *
     * @param groupId is the device group identifier for which want to set the active preset
     * @return true if valid group request was sent, false otherwise
     */
    public boolean groupNextActivePreset(int groupId) {
        if (groupId == BluetoothCsipSetCoordinator.GROUP_ID_INVALID) return false;

        mHapClientNativeInterface.groupNextActivePreset(groupId);
        return true;
    }

    /**
     * Sets the previous preset as a currently active preset for a HA device
     *
     * @param device is the device for which we want to set the active preset
     * @return true if valid request was sent, false otherwise
     */
    public boolean previousActivePreset(BluetoothDevice device) {
        mHapClientNativeInterface.previousActivePreset(device);
        return true;
    }

    /**
     * Sets the previous preset as a currently active preset for a HA device group
     *
     * @param groupId is the device group identifier for which want to set the active preset
     * @return true if valid group request was sent, false otherwise
     */
    public boolean groupPreviousActivePreset(int groupId) {
        if (groupId == BluetoothCsipSetCoordinator.GROUP_ID_INVALID) return false;

        mHapClientNativeInterface.groupPreviousActivePreset(groupId);
        return true;
    }

    /**
     * Requests the preset name
     *
     * @param device is the device for which we want to get the preset name
     * @param presetIndex is an index of one of the available presets
     * @return true if valid request was sent, false otherwise
     */
    public boolean getPresetInfo(BluetoothDevice device, int presetIndex) {
        if (presetIndex == BluetoothHapClient.PRESET_INDEX_UNAVAILABLE) return false;
        mHapClientNativeInterface.getPresetInfo(device, presetIndex);
        return true;
    }

    /**
     * Requests all presets info
     *
     * @param device is the device for which we want to get all presets info
     * @return true if request was processed, false otherwise
     */
    public boolean getAllPresetsInfo(BluetoothDevice device) {
        if (mPresetsMap.containsKey(device)) {
            notifyPresets(device, BluetoothHapClient.PRESET_INFO_REASON_ALL_PRESET_INFO,
                    mPresetsMap.get(device));
            return true;
        }
        return false;
    }

    /**
     * Requests features
     *
     * @param device is the device for which we want to get features
     * @return true if request was processed, false otherwise
     */
    public boolean getFeatures(BluetoothDevice device) {
        if (mDeviceFeaturesMap.containsKey(device)) {
            notifyFeatures(device, mDeviceFeaturesMap.get(device));
            return true;
        }
        return false;
    }

    private void notifyPresets(BluetoothDevice device, int infoReason,
            ArrayList<BluetoothHapPresetInfo> presets) {
        Intent intent = null;

        intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO);
        if (intent != null) {
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
            intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO_REASON, infoReason);
            intent.putParcelableArrayListExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO, presets);
            sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
        }
    }

    private void notifyPresets(int groupId, int infoReason,
            ArrayList<BluetoothHapPresetInfo> presets) {
        Intent intent = null;

        intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO);
        if (intent != null) {
            intent.putExtra(BluetoothHapClient.EXTRA_HAP_GROUP_ID, groupId);
            intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO_REASON, infoReason);
            intent.putParcelableArrayListExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO, presets);
            sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
        }
    }

    private void notifyFeatures(BluetoothDevice device, int features) {
        Intent intent = null;

        intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_DEVICE_FEATURES);
        if (intent != null) {
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
            intent.putExtra(BluetoothHapClient.EXTRA_HAP_FEATURES, features);
            sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
        }
    }

    /**
     * Sets the preset name
     *
     * @param device is the device for which we want to get the preset name
     * @param presetIndex is an index of one of the available presets
     * @param name is a new name for a preset
     * @return true if valid request was sent, false otherwise
     */
    public boolean setPresetName(BluetoothDevice device, int presetIndex, String name) {
        if (presetIndex == BluetoothHapClient.PRESET_INDEX_UNAVAILABLE) return false;
        mHapClientNativeInterface.setPresetName(device, presetIndex, name);
        return true;
    }

    /**
     * Sets the preset name
     *
     * @param groupId is the device group identifier
     * @param presetIndex is an index of one of the available presets
     * @param name is a new name for a preset
     * @return true if valid request was sent, false otherwise
     */
    public boolean groupSetPresetName(int groupId, int presetIndex, String name) {
        if (groupId == BluetoothCsipSetCoordinator.GROUP_ID_INVALID) return false;
        if (presetIndex == BluetoothHapClient.PRESET_INDEX_UNAVAILABLE) return false;
        mHapClientNativeInterface.groupSetPresetName(groupId, presetIndex, name);
        return true;
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        for (HapClientStateMachine sm : mStateMachines.values()) {
            sm.dump(sb);
        }
    }

    private boolean isPresetCoordinationSupported(BluetoothDevice device) {
        Integer features = mDeviceFeaturesMap.getOrDefault(device, 0x00);
        return BigInteger.valueOf(features).testBit(
                HapClientStackEvent.FEATURE_BIT_NUM_SYNCHRONIZATED_PRESETS);
    }

    void notifyActivePresetIndex(BluetoothDevice device, int presetIndex) {
        Intent intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, presetIndex);
        sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
    }

    void notifyActivePresetIndex(int groupId, int presetIndex) {
        Intent intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET);
        intent.putExtra(BluetoothHapClient.EXTRA_HAP_GROUP_ID, groupId);
        intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, presetIndex);
        sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
    }

    void updateDevicePresetsCache(BluetoothDevice device, int infoReason,
            ArrayList<BluetoothHapPresetInfo> presets) {
        switch (infoReason) {
            case BluetoothHapClient.PRESET_INFO_REASON_ALL_PRESET_INFO:
                mPresetsMap.put(device, presets);
                break;
            case BluetoothHapClient.PRESET_INFO_REASON_PRESET_INFO_UPDATE:
            case BluetoothHapClient.PRESET_INFO_REASON_PRESET_AVAILABILITY_CHANGED:
            case BluetoothHapClient.PRESET_INFO_REASON_PRESET_INFO_REQUEST_RESPONSE: {
                ArrayList current_presets = mPresetsMap.get(device);
                if (current_presets != null) {
                    ListIterator<BluetoothHapPresetInfo> iter = current_presets.listIterator();
                    for (BluetoothHapPresetInfo new_preset : presets) {
                        while (iter.hasNext()) {
                            if (iter.next().getIndex() == new_preset.getIndex()) {
                                iter.remove();
                            }
                        }
                    }
                    current_presets.addAll(presets);
                    mPresetsMap.put(device, current_presets);
                } else {
                    mPresetsMap.put(device, presets);
                }
            }
                break;

            case BluetoothHapClient.PRESET_INFO_REASON_PRESET_DELETED: {
                ArrayList current_presets = mPresetsMap.get(device);
                if (current_presets != null) {
                    ListIterator<BluetoothHapPresetInfo> iter = current_presets.listIterator();
                    for (BluetoothHapPresetInfo new_preset : presets) {
                        while (iter.hasNext()) {
                            if (iter.next().getIndex() == new_preset.getIndex()) {
                                iter.remove();
                            }
                        }
                    }
                    mPresetsMap.put(device, current_presets);
                }
            }
                break;

            default:
                break;
        }
    }

    /**
     * Handle messages from native (JNI) to Java
     *
     * @param stackEvent the event that need to be handled
     */
    public void messageFromNative(HapClientStackEvent stackEvent) {
        // Decide which event should be sent to the state machine
        if (stackEvent.type == HapClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED) {
            resendToStateMachine(stackEvent);
            return;
        }

        Intent intent = null;
        BluetoothDevice device = stackEvent.device;

        switch (stackEvent.type) {
            case (HapClientStackEvent.EVENT_TYPE_DEVICE_AVAILABLE): {
                int features = stackEvent.valueInt1;

                if (device != null) {
                    mDeviceFeaturesMap.put(device, features);

                    intent = new Intent(BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE);
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                    intent.putExtra(BluetoothHapClient.EXTRA_HAP_FEATURES, features);
                }
            } break;

            case (HapClientStackEvent.EVENT_TYPE_DEVICE_FEATURES): {
                int features = stackEvent.valueInt1;

                if (device != null) {
                    mDeviceFeaturesMap.put(device, features);
                    notifyFeatures(device, features);
                }
            } return;

            case (HapClientStackEvent.EVENT_TYPE_ON_ACTIVE_PRESET_SELECTED): {
                int currentPresetIndex = stackEvent.valueInt1;
                int groupId = stackEvent.valueInt2;

                if (device != null) {
                    mDeviceCurrentPresetMap.put(device, currentPresetIndex);
                    notifyActivePresetIndex(device, currentPresetIndex);

                } else if (groupId != BluetoothCsipSetCoordinator.GROUP_ID_INVALID) {
                    // TODO: Fix missing CSIS service API to decouple from LeAudioService
                    LeAudioService le_audio_service = mFactory.getLeAudioService();
                    if (le_audio_service != null) {
                        int group_id = le_audio_service.getGroupId(device);
                        if (group_id != BluetoothLeAudio.GROUP_ID_INVALID) {
                            List<BluetoothDevice> all_group_devices =
                                    le_audio_service.getGroupDevices(group_id);
                            for (BluetoothDevice dev : all_group_devices) {
                                mDeviceCurrentPresetMap.put(dev, currentPresetIndex);
                            }
                        }
                    }
                    notifyActivePresetIndex(groupId, currentPresetIndex);
                }
            } return;

            case (HapClientStackEvent.EVENT_TYPE_ON_ACTIVE_PRESET_SELECT_ERROR): {
                int statusCode = stackEvent.valueInt1;
                int groupId = stackEvent.valueInt2;

                intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET_SELECT_ERROR);
                intent.putExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, statusCode);

                if (device != null) {
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                } else if (groupId != BluetoothCsipSetCoordinator.GROUP_ID_INVALID) {
                    intent.putExtra(BluetoothHapClient.EXTRA_HAP_GROUP_ID, groupId);
                }
            } break;

            case (HapClientStackEvent.EVENT_TYPE_ON_PRESET_INFO): {
                int presetIndex = stackEvent.valueInt1;
                int infoReason = stackEvent.valueInt2;
                int groupId = stackEvent.valueInt3;
                ArrayList presets = stackEvent.valueList;

                if (device != null) {
                    updateDevicePresetsCache(device, infoReason, presets);
                    notifyPresets(device, infoReason, presets);

                } else if (groupId != BluetoothCsipSetCoordinator.GROUP_ID_INVALID) {
                    // TODO: Fix missing CSIS service API to decouple from LeAudioService
                    LeAudioService le_audio_service = mFactory.getLeAudioService();
                    if (le_audio_service != null) {
                        int group_id = le_audio_service.getGroupId(device);
                        if (group_id != BluetoothLeAudio.GROUP_ID_INVALID) {
                            List<BluetoothDevice> all_group_devices =
                                    le_audio_service.getGroupDevices(group_id);
                            for (BluetoothDevice dev : all_group_devices) {
                                updateDevicePresetsCache(dev, infoReason, presets);
                            }
                        }
                    }
                    notifyPresets(groupId, infoReason, presets);
                }

            } return;

            case (HapClientStackEvent.EVENT_TYPE_ON_PRESET_NAME_SET_ERROR): {
                int statusCode = stackEvent.valueInt1;
                int presetIndex = stackEvent.valueInt2;

                intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_PRESET_NAME_SET_ERROR);
                intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, presetIndex);
                intent.putExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, statusCode);

                if (device != null) {
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                } else {
                    int groupId = stackEvent.valueInt3;
                    intent.putExtra(BluetoothHapClient.EXTRA_HAP_GROUP_ID, groupId);
                }
            } break;

            case (HapClientStackEvent.EVENT_TYPE_ON_PRESET_INFO_ERROR): {
                int statusCode = stackEvent.valueInt1;
                int presetIndex = stackEvent.valueInt2;

                intent = new Intent(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO_GET_ERROR);
                intent.putExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, presetIndex);
                intent.putExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, statusCode);

                if (device != null) {
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                } else {
                    int groupId = stackEvent.valueInt3;
                    intent.putExtra(BluetoothHapClient.EXTRA_HAP_GROUP_ID, groupId);
                }
            } break;

            default:
                return;
        }

        if (intent != null) {
            sendBroadcast(intent, BLUETOOTH_PRIVILEGED);
        }
    }

    private void resendToStateMachine(HapClientStackEvent stackEvent) {
        synchronized (mStateMachines) {
            BluetoothDevice device = stackEvent.device;
            HapClientStateMachine sm = mStateMachines.get(device);

            if (sm == null) {
                if (stackEvent.type == HapClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED) {
                    switch (stackEvent.valueInt1) {
                        case HapClientStackEvent.CONNECTION_STATE_CONNECTED:
                        case HapClientStackEvent.CONNECTION_STATE_CONNECTING:
                            sm = getOrCreateStateMachine(device);
                            break;
                        default:
                            break;
                    }
                }
            }
            if (sm == null) {
                Log.e(TAG, "Cannot process stack event: no state machine: " + stackEvent);
                return;
            }
            sm.sendMessage(HapClientStateMachine.STACK_EVENT, stackEvent);
        }
    }

    /**
     * Binder object: must be a static class or memory leak may occur
     */
    @VisibleForTesting
    static class BluetoothHapClientBinder extends IBluetoothHapClient.Stub
            implements IProfileServiceBinder {
        private HapClientService mService;

        BluetoothHapClientBinder(HapClientService svc) {
            mService = svc;
        }

        private HapClientService getService(AttributionSource source) {
            if (!Utils.checkCallerIsSystemOrActiveUser(TAG)
                    || !Utils.checkServiceAvailable(mService, TAG)
                    || !Utils.checkConnectPermissionForDataDelivery(mService, source, TAG)) {
                Log.w(TAG, "Hearing Access call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        @Override
        public void cleanup() {
            mService = null;
        }

        @Override
        public void connect(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.connect(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void disconnect(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.disconnect(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getConnectedDevices(AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                List<BluetoothDevice> defaultValue = new ArrayList<>();
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getConnectedDevices();
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getDevicesMatchingConnectionStates(int[] states,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                List<BluetoothDevice> defaultValue = new ArrayList<>();
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getDevicesMatchingConnectionStates(states);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getConnectionState(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                int defaultValue = BluetoothProfile.STATE_DISCONNECTED;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getConnectionState(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void setConnectionPolicy(BluetoothDevice device, int connectionPolicy,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.setConnectionPolicy(device, connectionPolicy);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getConnectionPolicy(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                int defaultValue = BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getConnectionPolicy(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getActivePresetIndex(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getActivePresetIndex(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getHapGroup(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                int defaultValue = BluetoothCsipSetCoordinator.GROUP_ID_INVALID;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getHapGroup(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void selectActivePreset(BluetoothDevice device, int presetIndex,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.selectActivePreset(device, presetIndex);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void groupSelectActivePreset(int groupId, int presetIndex,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.groupSelectActivePreset(groupId, presetIndex);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void nextActivePreset(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.nextActivePreset(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void groupNextActivePreset(int groupId, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.groupNextActivePreset(groupId);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void previousActivePreset(BluetoothDevice device, AttributionSource source,
                SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.previousActivePreset(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void groupPreviousActivePreset(int groupId, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.groupPreviousActivePreset(groupId);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getPresetInfo(BluetoothDevice device, int presetIndex,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getPresetInfo(device, presetIndex);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getAllPresetsInfo(BluetoothDevice device, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getAllPresetsInfo(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getFeatures(BluetoothDevice device, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.getFeatures(device);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void setPresetName(BluetoothDevice device, int presetIndex, String name,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.setPresetName(device, presetIndex, name);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void groupSetPresetName(int groupId, int presetIndex, String name,
                AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                HapClientService service = getService(source);
                if (service != null) {
                    defaultValue = service.groupSetPresetName(groupId, presetIndex, name);
                }
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }
    }

    // Remove state machine if the bonding for a device is removed
    private class BondStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                    BluetoothDevice.ERROR);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            Objects.requireNonNull(device, "ACTION_BOND_STATE_CHANGED with no EXTRA_DEVICE");
            bondStateChanged(device, state);
        }
    }

    private class ConnectionStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED.equals(
                    intent.getAction())) {
                return;
            }
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            int toState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
            int fromState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
            connectionStateChanged(device, fromState, toState);
        }
    }
}
