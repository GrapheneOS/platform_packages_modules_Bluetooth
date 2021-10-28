/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

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

package com.android.bluetooth.pc;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemProperties;
import android.os.UserManager;
import android.util.Log;

import com.android.bluetooth.BluetoothMetricsProto;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.MetricsLogger;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.internal.annotations.VisibleForTesting;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

public class PCService extends ProfileService{
    private static final String TAG = "PCService";
    private static final boolean DBG = true;
    private static final int MAX_PACS_STATE_MACHINES = 50;

    private HandlerThread mStateMachinesThread;
    private final HashMap<BluetoothDevice, PacsClientStateMachine> mStateMachines =
                new HashMap<>();
    private BroadcastReceiver mBondStateChangedReceiver;

    private AdapterService mAdapterService;
    private PacsClientNativeInterface mNativeInterface;
    private static PCService sInstance = null;

    public static final String ACTION_CONNECTION_STATE_CHANGED =
                "com.android.bluetooth.pacs.action.CONNECTION_STATE_CHANGED";

    /**
     * Get the PCService instance. Returns null if the service hasn't been initialized.
     */
    public static PCService get() {
        return sInstance;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return null;
    }

    @Override
    protected void create() {
        if (DBG) {
            Log.d(TAG, "create()");
        }
    }

    protected boolean start() {

        if (DBG) {
            Log.d(TAG, "start()");
        }
        if (sInstance != null) {
            Log.w(TAG, "PCService is already running");
            return true;
        }

        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when PCService starts");
        mNativeInterface = Objects.requireNonNull(PacsClientNativeInterface.getInstance(),
                "PacsClientNativeInterface cannot be null when PCService starts");

        // Start handler thread for state machines
        mStateMachines.clear();
        mStateMachinesThread = new HandlerThread("PCService.StateMachines");
        mStateMachinesThread.start();
        mNativeInterface.init();
        sInstance = this;

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        mBondStateChangedReceiver = new BondStateChangedReceiver();
        registerReceiver(mBondStateChangedReceiver, filter);

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }
        if (sInstance == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        unregisterReceiver(mBondStateChangedReceiver);

        // Mark service as stopped
        sInstance = null;

        // Destroy state machines and stop handler thread
        synchronized (mStateMachines) {
            for (PacsClientStateMachine sm : mStateMachines.values()) {
                sm.doQuit();
                sm.cleanup();
            }
            mStateMachines.clear();
        }

        if (mStateMachinesThread != null) {
            mStateMachinesThread.quitSafely();
            mStateMachinesThread = null;
        }

        // Cleanup native interface
        mNativeInterface.cleanup();
        mNativeInterface = null;

        // Clear AdapterService
        mAdapterService = null;
        return true;
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }
    }

    /**
   * Get the PCService instance
   * @return PCService instance
   */
    public static synchronized PCService getPCService() {
        if (sInstance == null) {
            Log.w(TAG, "getPCService(): service is NULL");
            return null;
        }

        return sInstance;
    }

    /**
     * Connects the pacs profile to the passed in device
     *
     * @param device is the device with which we will connect the pacs  profile
     * @return true if pacs profile successfully connected, false otherwise
     */

    public boolean connect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "connect(): " + device);
        }
        if (device == null) {
            return false;
        }

        synchronized (mStateMachines) {
            PacsClientStateMachine smConnect = getOrCreateStateMachine(device);
            if (smConnect == null) {
                Log.e(TAG, "Cannot connect to " + device + " : no state machine");
                return false;
            }
            smConnect.sendMessage(PacsClientStateMachine.CONNECT);
        }

        return true;
    }

    /**
     * Disconnects pacs profile for the passed in device
     *
     * @param device is the device with which we want to disconnected the pacs profile
     * @return true if pacs profile successfully disconnected, false otherwise
     */

    public boolean disconnect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device);
        }
        if (device == null) {
            return false;
        }
        synchronized (mStateMachines) {
            PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.w(TAG, "disconnect: device " + device + " not ever connected/connecting");
                return false;
            }
            int connectionState = stateMachine.getConnectionState();
            if (connectionState != BluetoothProfile.STATE_CONNECTED
                    && connectionState != BluetoothProfile.STATE_CONNECTING) {
                Log.w(TAG, "disconnect: device " + device
                        + " not connected/connecting, connectionState=" + connectionState);
                return false;
            }
            stateMachine.sendMessage(PacsClientStateMachine.DISCONNECT);
        }
        return true;
    }

    /**
     * start pacs disocvery for the passed in device
     *
     * @param device is the device with which we want to dicscoer the pacs
     * @return true if pacs discovery is successfull, false otherwise
     */

    public boolean startPacsDiscovery(BluetoothDevice device) {
           synchronized (mStateMachines) {
                Log.i(TAG, "startPacsDiscovery: device=" + device + ", " + Utils.getUidPidString());
                final PacsClientStateMachine stateMachine = mStateMachines.get(device);
                if (stateMachine == null) {
                    Log.w(TAG, "startPacsDiscovery: device " + device + " was never connected/connecting");
                    return false;
                }
                if (stateMachine.getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
                    Log.w(TAG, "startPacsDiscovery: profile not connected");
                    return false;
                }
                stateMachine.sendMessage(PacsClientStateMachine.START_DISCOVERY);
           }
           return true;
    }

    /**
     * get sink pacs for the passed in device
     *
     * @param device is the device with which we want to get sink pacs
     * @return sink pacs
     */

    public BluetoothCodecConfig[] getSinkPacs(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get Sink Pacs");
                return null;
            }
            return stateMachine.getSinkPacs();
        }
    }

    /**
     * get src pacs for the passed in device
     *
     * @param device is the device with which we want to get src pacs
     * @return src pacs
     */

    public BluetoothCodecConfig[] getSrcPacs(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get Src Pacs");
                return null;
            }
            return stateMachine.getSinkPacs();
        }
    }

    /**
     * get sink locations for the passed in device
     *
     * @param device is the device with which we want to get sink location
     * @return sink locations
     */

    public int getSinklocations(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get sink locations");
                return -1;
            }
            return stateMachine.getSinklocations();
        }
    }

    /**
     * get src locations for the passed in device
     *
     * @param device is the device with which we want to get src location
     * @return src locations
     */

    public int getSrclocations(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get src locations");
                return -1;
            }
            return stateMachine.getSrclocations();
        }
    }

    /**
     * get available contexts for the passed in device
     *
     * @param device is the device with which we want to get available contexts
     * @return avaialable contexts
     */

    public int getAvailableContexts(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get available contexts");
                return -1;
            }
            return stateMachine.getAvailableContexts();
        }
    }

    /**
     * get supported contexts for the passed in device
     *
     * @param device is the device with which we want to get supported contexts
     * @return supported contexts
     */

    public int getSupportedContexts(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final PacsClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.e(TAG, "Failed to get supported contexts");
                return -1;
            }
            return stateMachine.getSupportedContexts();
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
        synchronized (mStateMachines) {
            PacsClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return sm.getConnectionState();
        }
    }

    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean okToConnect(BluetoothDevice device) {

        int bondState = mAdapterService.getBondState(device);
        if (bondState != BluetoothDevice.BOND_BONDED) {
            Log.w(TAG, "okToConnect: return false, bondState=" + bondState);
            return false;
         }
        return true;
    }

    void messageFromNative(PacsClientStackEvent stackEvent) {
        Objects.requireNonNull(stackEvent.device,
                "Device should never be null, event: " + stackEvent);

        synchronized (mStateMachines) {
            BluetoothDevice device = stackEvent.device;
            PacsClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                if (stackEvent.type == PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED) {
                    switch (stackEvent.valueInt1) {
                        case PacsClientStackEvent.CONNECTION_STATE_CONNECTED:
                        case PacsClientStackEvent.CONNECTION_STATE_CONNECTING:
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
            sm.sendMessage(PacsClientStateMachine.STACK_EVENT, stackEvent);
        }
    }

    void onConnectionStateChangedFromStateMachine(BluetoothDevice device,
            int newState, int prevState) {
        Log.d(TAG, "onConnectionStateChangedFromStateMachine for device: " + device
                    + " newState: " + newState);

        synchronized (mStateMachines) {
            if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                int bondState = mAdapterService.getBondState(device);
                if (bondState == BluetoothDevice.BOND_NONE) {
                    removeStateMachine(device);
                 }
            } else if (newState == BluetoothProfile.STATE_CONNECTED) {
               Log.d(TAG, "PacsClient get connected with renderer device: " + device);
            }
        }
    }

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

        synchronized (mStateMachines) {
             PacsClientStateMachine sm = mStateMachines.get(device);
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
            PacsClientStateMachine sm = mStateMachines.get(device);
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

    private PacsClientStateMachine getOrCreateStateMachine(BluetoothDevice device) {
        if (device == null) {
            Log.e(TAG, "getOrCreateStateMachine failed: device cannot be null");
            return null;
        }
        synchronized (mStateMachines) {
            PacsClientStateMachine sm = mStateMachines.get(device);
            if (sm != null) {
                return sm;
            }
            if (mStateMachines.size() >= MAX_PACS_STATE_MACHINES) {
                Log.e(TAG, "Maximum number of PACS state machines reached: "
                        + MAX_PACS_STATE_MACHINES);
                return null;
            }
            if (DBG) {
                Log.d(TAG, "Creating a new state machine for " + device);
            }
            sm = PacsClientStateMachine.make(device, this,
                    mNativeInterface, mStateMachinesThread.getLooper());
            mStateMachines.put(device, sm);
            return sm;
        }
    }

}

