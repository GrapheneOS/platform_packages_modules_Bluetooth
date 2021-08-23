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

package com.android.bluetooth.csip;

import android.annotation.NonNull;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothCsipSetCoordinator;
import android.bluetooth.IBluetoothCsipSetCoordinatorLockCallback;
import android.os.ParcelUuid;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Provides Bluetooth CSIP Set Coordinator profile, as a service.
 * @hide
 */
public class CsipSetCoordinatorService extends ProfileService {
    private static final boolean DBG = false;
    private static final String TAG = "CsipSetCoordinatorService";

    private static CsipSetCoordinatorService sCsipSetCoordinatorService;

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothCsisBinder(this);
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
        if (sCsipSetCoordinatorService != null) {
            throw new IllegalStateException("start() called twice");
        }

        // Mark service as started
        setCsipSetCoordinatorService(this);

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }
        if (sCsipSetCoordinatorService == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        // Mark service as stopped
        setCsipSetCoordinatorService(null);

        return true;
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }
    }

    /**
     * Get the CsipSetCoordinatorService instance
     * @return CsipSetCoordinatorService instance
     */
    public static synchronized CsipSetCoordinatorService getCsipSetCoordinatorService() {
        if (sCsipSetCoordinatorService == null) {
            Log.w(TAG, "getCsipSetCoordinatorService(): service is NULL");
            return null;
        }

        if (!sCsipSetCoordinatorService.isAvailable()) {
            Log.w(TAG, "getCsipSetCoordinatorService(): service is not available");
            return null;
        }
        return sCsipSetCoordinatorService;
    }

    private static synchronized void setCsipSetCoordinatorService(
            CsipSetCoordinatorService instance) {
        if (DBG) {
            Log.d(TAG, "setCsipSetCoordinatorService(): set to: " + instance);
        }
        sCsipSetCoordinatorService = instance;
    }

    /**
     * Binder object: must be a static class or memory leak may occur
     */
    @VisibleForTesting
    static class BluetoothCsisBinder
            extends IBluetoothCsipSetCoordinator.Stub implements IProfileServiceBinder {
        private CsipSetCoordinatorService mService;

        private CsipSetCoordinatorService getService() {
            if (!Utils.checkCaller()) {
                Log.w(TAG, "CSIS call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        BluetoothCsisBinder(CsipSetCoordinatorService svc) {
            mService = svc;
        }

        @Override
        public void cleanup() {
            mService = null;
        }

        @Override
        public boolean connect(BluetoothDevice device) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return false;
            }
            return false;
        }

        @Override
        public boolean disconnect(BluetoothDevice device) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return false;
            }
            return false;
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return new ArrayList<>();
            }
            return new ArrayList<>();
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return new ArrayList<>();
            }
            return new ArrayList<>();
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public boolean setConnectionPolicy(BluetoothDevice device, int connectionPolicy) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return false;
            }
            return false;
        }

        @Override
        public int getConnectionPolicy(BluetoothDevice device) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
            }
            return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
        }

        @Override
        public ParcelUuid groupLock(
                int groupId, @NonNull IBluetoothCsipSetCoordinatorLockCallback callback) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return null;
            }

            return null;
        }

        @Override
        public void groupUnlock(@NonNull ParcelUuid lockUuid) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return;
            }
        }

        @Override
        public List<Integer> getAllGroupIds(ParcelUuid uuid) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return new ArrayList<Integer>();
            }

            return new ArrayList<Integer>();
        }

        @Override
        public Map<Integer, ParcelUuid> getGroupUuidMapByDevice(BluetoothDevice device) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return null;
            }

            return null;
        }

        @Override
        public int getDesiredGroupSize(int groupId) {
            CsipSetCoordinatorService service = getService();
            if (service == null) {
                return IBluetoothCsipSetCoordinator.CSIS_GROUP_SIZE_UNKNOWN;
            }

            return IBluetoothCsipSetCoordinator.CSIS_GROUP_SIZE_UNKNOWN;
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
    }
}
