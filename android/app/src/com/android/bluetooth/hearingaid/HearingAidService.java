/*
 * Copyright 2018 The Android Open Source Project
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

package com.android.bluetooth.hearingaid;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHearingAid;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothHearingAid;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.HandlerThread;
import android.os.ParcelUuid;
import android.provider.Settings;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Provides Bluetooth HearingAid profile, as a service in the Bluetooth application.
 * @hide
 */
public class HearingAidService extends ProfileService {
    private static final boolean DBG = false;
    private static final String TAG = "HearingAidService";

    private static HearingAidService sHearingAidService;

    private BluetoothAdapter mAdapter;
    private AdapterService mAdapterService;
    private HandlerThread mStateMachinesThread;

    private BluetoothDevice mActiveDevice;

    private final Map<BluetoothDevice, Integer> mDeviceMap = new HashMap<>();

    private BroadcastReceiver mBondStateChangedReceiver;
    private BroadcastReceiver mConnectionStateChangedReceiver;

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothHearingAidBinder(this);
    }

    @Override
    protected void create() {
        if (DBG) {
            Log.d(TAG, "create()");
        }
    }

    @Override
    protected boolean start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }
        if (sHearingAidService != null) {
            throw new IllegalStateException("start() called twice");
        }

        // Get BluetoothAdapter, AdapterService, A2dpNativeInterface, AudioManager.
        // None of them can be null.
        mAdapter = Objects.requireNonNull(BluetoothAdapter.getDefaultAdapter(),
                "BluetoothAdapter cannot be null when HearingAidService starts");
        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when HearingAidService starts");
        // TODO: Add native interface

        // Start handler thread for state machines
        // TODO: Clear state machines
        mStateMachinesThread = new HandlerThread("HearingAidService.StateMachines");
        mStateMachinesThread.start();

        // Initialize native interface
        // TODO: Init native interface

        // Setup broadcast receivers
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        mBondStateChangedReceiver = new BondStateChangedReceiver();
        registerReceiver(mBondStateChangedReceiver, filter);
        filter = new IntentFilter();
        filter.addAction(BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED);
        mConnectionStateChangedReceiver = new ConnectionStateChangedReceiver();
        registerReceiver(mConnectionStateChangedReceiver, filter);

        // Mark service as started
        setHearingAidService(this);

        // Clear active device
        setActiveDevice(null);

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }
        if (sHearingAidService == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        // Clear active device
        setActiveDevice(null);

        // Mark service as stopped
        setHearingAidService(null);

        // Unregister broadcast receivers
        unregisterReceiver(mBondStateChangedReceiver);
        mBondStateChangedReceiver = null;
        unregisterReceiver(mConnectionStateChangedReceiver);
        mConnectionStateChangedReceiver = null;

        // Cleanup native interface
        // TODO: Cleanup native interface

        // Destroy state machines and stop handler thread
        // TODO: Implement me: destroy state machine
        if (mStateMachinesThread != null) {
            mStateMachinesThread.quitSafely();
            mStateMachinesThread = null;
        }

        // Clear BluetoothAdapter, AdapterService, HearingAidNativeInterface
        // TODO: Set native interface to null
        mAdapterService = null;
        mAdapter = null;

        return true;
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }
    }

    /**
     * Get the HearingAidService instance
     * @return HearingAidService instance
     */
    public static synchronized HearingAidService getHearingAidService() {
        if (sHearingAidService == null) {
            Log.w(TAG, "getHearingAidService(): service is NULL");
            return null;
        }

        if (!sHearingAidService.isAvailable()) {
            Log.w(TAG, "getHearingAidService(): service is not available");
            return null;
        }
        return sHearingAidService;
    }

    private static synchronized void setHearingAidService(HearingAidService instance) {
        if (DBG) {
            Log.d(TAG, "setHearingAidService(): set to: " + instance);
        }
        sHearingAidService = instance;
    }

    boolean connect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        if (DBG) {
            Log.d(TAG, "connect(): " + device);
        }

        if (getPriority(device) == BluetoothProfile.PRIORITY_OFF) {
            return false;
        }
        ParcelUuid[] featureUuids = device.getUuids();
        if (!BluetoothUuid.isUuidPresent(featureUuids, BluetoothUuid.HearingAid)) {
            Log.e(TAG, "Cannot connect to " + device + " : Remote does not have HearingAid UUID");
            return false;
        }

        // TODO: Implement me
        return false;
    }

    boolean disconnect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device);
        }

        // TODO: Implement me
        return false;
    }

    List<BluetoothDevice> getConnectedDevices() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        // TODO: Implement me
        return new ArrayList<>();
    }

    /**
     * Check whether can connect to a peer device.
     * The check considers a number of factors during the evaluation.
     *
     * @param device the peer device to connect to
     * @return true if connection is allowed, otherwise false
     */
    boolean okToConnect(BluetoothDevice device) {
        throw new IllegalStateException("Implement me");
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        // TODO: Implement me
        return new ArrayList<>();
    }

    /**
     * Get the list of devices that have state machines.
     *
     * @return the list of devices that have state machines
     */
    @VisibleForTesting
    List<BluetoothDevice> getDevices() {
        // TODO: Implement me
        return new ArrayList<>();
    }

    int getConnectionState(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        // TODO: Implement me
        return BluetoothProfile.STATE_DISCONNECTED;
    }

    /**
     * Set the active device.
     *
     * @param device the active device
     * @return true on success, otherwise false
     */
    public synchronized boolean setActiveDevice(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        // TODO: Implement me
        return false;
    }

    /**
     * Get the active device.
     *
     * @return the active device or null if no device is active
     */
    public synchronized BluetoothDevice getActiveDevice() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        throw new IllegalStateException("Implement me");
    }

    private synchronized boolean isActiveDevice(BluetoothDevice device) {
        throw new IllegalStateException("Implement me");
    }

    /**
     * Set the priority of the Hearing Aid profile.
     *
     * @param device the remote device
     * @param priority the priority of the profile
     * @return true on success, otherwise false
     */
    public boolean setPriority(BluetoothDevice device, int priority) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        Settings.Global.putInt(getContentResolver(),
                Settings.Global.getBluetoothHearingAidPriorityKey(device.getAddress()), priority);
        if (DBG) {
            Log.d(TAG, "Saved priority " + device + " = " + priority);
        }
        return true;
    }
    /**
     * Get the priority of the Hearing Aid profile.
     *
     * @param device the remote device
     * @return the profile priority
     */
    public int getPriority(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        int priority = Settings.Global.getInt(getContentResolver(),
                Settings.Global.getBluetoothHearingAidPriorityKey(device.getAddress()),
                BluetoothProfile.PRIORITY_UNDEFINED);
        return priority;
    }

    private void broadcastActiveDevice(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "broadcastActiveDevice(" + device + ")");
        }

        Intent intent = new Intent(BluetoothHearingAid.ACTION_ACTIVE_DEVICE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
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
            if (DBG) {
                Log.d(TAG, "Bond state changed for device: " + device + " state: " + state);
            }
            if (state != BluetoothDevice.BOND_NONE) {
                return;
            }
            // TODO: Implement me
        }
    }

    /**
     * Process a change in the bonding state for a device.
     *
     * @param device the device whose bonding state has changed
     * @param bondState the new bond state for the device. Possible values are:
     * {@link BluetoothDevice#BOND_NONE},
     * {@link BluetoothDevice#BOND_BONDING},
     * {@link BluetoothDevice#BOND_BONDED}.
     */
    @VisibleForTesting
    void bondStateChanged(BluetoothDevice device, int bondState) {
        if (DBG) {
            Log.d(TAG, "Bond state changed for device: " + device + " state: " + bondState);
        }
        // Remove state machine if the bonding for a device is removed
        if (bondState != BluetoothDevice.BOND_NONE) {
            return;
        }
        // TODO: Implement me
    }

    private synchronized void connectionStateChanged(BluetoothDevice device, int fromState,
                                                     int toState) {
        // TODO: Implement me
    }

    private class ConnectionStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            int toState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
            int fromState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
            connectionStateChanged(device, fromState, toState);
        }
    }

    /**
     * Binder object: must be a static class or memory leak may occur
     */
    @VisibleForTesting
    static class BluetoothHearingAidBinder extends IBluetoothHearingAid.Stub
            implements IProfileServiceBinder {
        private HearingAidService mService;

        private HearingAidService getService() {
            if (!Utils.checkCaller()) {
                Log.w(TAG, "HearingAid call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        BluetoothHearingAidBinder(HearingAidService svc) {
            mService = svc;
        }

        @Override
        public void cleanup() {
            mService = null;
        }

        @Override
        public boolean connect(BluetoothDevice device) {
            HearingAidService service = getService();
            if (service == null) {
                return false;
            }
            return service.connect(device);
        }

        @Override
        public boolean disconnect(BluetoothDevice device) {
            HearingAidService service = getService();
            if (service == null) {
                return false;
            }
            return service.disconnect(device);
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            HearingAidService service = getService();
            if (service == null) {
                return new ArrayList<>(0);
            }
            return service.getConnectedDevices();
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            HearingAidService service = getService();
            if (service == null) {
                return new ArrayList<>(0);
            }
            return service.getDevicesMatchingConnectionStates(states);
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            HearingAidService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return service.getConnectionState(device);
        }

        @Override
        public boolean setPriority(BluetoothDevice device, int priority) {
            HearingAidService service = getService();
            if (service == null) {
                return false;
            }
            return service.setPriority(device, priority);
        }

        @Override
        public int getPriority(BluetoothDevice device) {
            HearingAidService service = getService();
            if (service == null) {
                return BluetoothProfile.PRIORITY_UNDEFINED;
            }
            return service.getPriority(device);
        }

        @Override
        public void setVolume(int volume) {
        }

        @Override
        public void adjustVolume(int direction) {
        }

        @Override
        public int getVolume() {
            return 0;
        }

        @Override
        public long getHiSyncId(BluetoothDevice device) {
            return 0;
        }

        @Override
        public int getDeviceSide(BluetoothDevice device) {
            return 0;
        }

        @Override
        public int getDeviceMode(BluetoothDevice device) {
            return 0;
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        ProfileService.println(sb, "mActiveDevice: " + mActiveDevice);
    }
}
