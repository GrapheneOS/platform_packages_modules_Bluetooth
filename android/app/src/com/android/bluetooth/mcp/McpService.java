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

package com.android.bluetooth.mcp;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.IBluetoothMcpServiceManager;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;

/**
 * Provides Media Control Profile, as a service in the Bluetooth application.
 * @hide
 */
public class McpService extends ProfileService {
    private static final boolean DBG = true;
    private static final boolean VDBG = false;
    private static final String TAG = "McpService";

    private static McpService sMcpService;

    private static synchronized void setMcpService(McpService instance) {
        if (VDBG) {
            Log.d(TAG, "setMcpService(): set to: " + instance);
        }
        sMcpService = instance;
    }

    public static synchronized McpService getMcpService() {
        if (sMcpService == null) {
            Log.w(TAG, "getMcpService(): service is NULL");
            return null;
        }

        if (!sMcpService.isAvailable()) {
            Log.w(TAG, "getMcpService(): service is not available");
            return null;
        }
        return sMcpService;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothMcpServiceBinder(this);
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

        if (sMcpService != null) {
            throw new IllegalStateException("start() called twice");
        }

        // Mark service as started
        setMcpService(this);

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }

        if (sMcpService == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        // Mark service as stopped
        setMcpService(null);

        return true;
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }
    }

    public void onDeviceUnauthorized(BluetoothDevice device) {
        // TODO: For now just reject authorization for other than LeAudio device already authorized.
        //       Consider intent based authorization mechanism for non-LeAudio devices.
        setDeviceAuthorized(device, false);
    }

    public int getDeviceAuthorization(BluetoothDevice device) {
        return BluetoothDevice.ACCESS_ALLOWED;
    }

    void setDeviceAuthorized(BluetoothDevice device, boolean isAuthorized) {

    }

    /**
     * Binder object: must be a static class or memory leak may occur
     */
    static class BluetoothMcpServiceBinder
            extends IBluetoothMcpServiceManager.Stub implements IProfileServiceBinder {
        private McpService mService;

        BluetoothMcpServiceBinder(McpService svc) {
            mService = svc;
        }

        private McpService getService() {
            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            Log.e(TAG, "getService() - Service requested, but not available!");
            return null;
        }

        @Override
        public void setDeviceAuthorized(BluetoothDevice device, boolean isAuthorized) {
            McpService service = getService();
            if (service == null) {
                return;
            }
            service.enforceCallingOrSelfPermission(
                    BLUETOOTH_PRIVILEGED, "Need BLUETOOTH_PRIVILEGED permission");
            service.setDeviceAuthorized(device, isAuthorized);
        }

        @Override
        public void cleanup() {
            mService = null;
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
    }
}
