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

import android.bluetooth.BluetoothCsipSetCoordinator;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothHapClient;
import android.content.AttributionSource;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.annotations.VisibleForTesting;
import com.android.modules.utils.SynchronousResultReceiver;

import java.util.ArrayList;
import java.util.List;

/**
 * Provides Bluetooth Hearing Access profile, as a service.
 * @hide
 */
public class HapClientService extends ProfileService {
    private static final boolean DBG = true;
    private static final String TAG = "HapClientService";

    private static HapClientService sHapClient;

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

        // Mark service as started
        setHapClient(this);

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

        // Marks service as stopped
        setHapClient(null);

        return true;
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
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
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void groupPreviousActivePreset(int groupId, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
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
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getAllPresetsInfo(BluetoothDevice device, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }

        @Override
        public void getFeatures(BluetoothDevice device, AttributionSource source, SynchronousResultReceiver receiver) {
            try {
                boolean defaultValue = false;
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
                receiver.send(defaultValue);
            } catch (RuntimeException e) {
                receiver.propagateException(e);
            }
        }
    }
}
