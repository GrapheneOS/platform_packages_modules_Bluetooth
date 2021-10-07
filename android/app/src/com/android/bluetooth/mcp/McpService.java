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
import android.content.AttributionSource;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;

import java.util.HashMap;
import java.util.Map;

/**
 * Provides Media Control Profile, as a service in the Bluetooth application.
 * @hide
 */
public class McpService extends ProfileService {
    private static final boolean DBG = true;
    private static final boolean VDBG = false;
    private static final String TAG = "BluetoothMcpService";

    private static McpService sMcpService;

    private static MediaControlProfile mGmcs;
    private Map<BluetoothDevice, Integer> mDeviceAuthorizations = new HashMap<>();
    private Handler mHandler = new Handler(Looper.getMainLooper());

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

    public static void setMediaControlProfileForTesting(MediaControlProfile mediaControlProfile) {
        mGmcs = mediaControlProfile;
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

        if (mGmcs == null) {
            // Initialize the Media Control Service Server
            mGmcs = new MediaControlProfile(this);
            // Requires this service to be already started thus we have to make it an async call
            mHandler.post(() -> mGmcs.init());
        }

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

        if (mGmcs != null) {
            mGmcs.cleanup();
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
        Log.w(TAG, "onDeviceUnauthorized - authorization notification not implemented yet ");
    }

    public void setDeviceAuthorized(BluetoothDevice device, boolean isAuthorized) {
        Log.i(TAG, "setDeviceAuthorized(): device: " + device + ", isAuthorized: " + isAuthorized);
        int authorization = isAuthorized ? BluetoothDevice.ACCESS_ALLOWED
                : BluetoothDevice.ACCESS_REJECTED;
        mDeviceAuthorizations.put(device, authorization);

        mGmcs.onDeviceAuthorizationSet(device);
    }

    public int getDeviceAuthorization(BluetoothDevice device) {
        // TODO: For now just reject authorization for other than LeAudio device already authorized.
        //       Consider intent based authorization mechanism for non-LeAudio devices.
        return mDeviceAuthorizations.getOrDefault(device, BluetoothDevice.ACCESS_UNKNOWN);
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

        private McpService getService(AttributionSource source) {
            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            Log.e(TAG, "getService() - Service requested, but not available!");
            return null;
        }

        @Override
        public void setDeviceAuthorized(BluetoothDevice device, boolean isAuthorized,
                AttributionSource source) {
            McpService service = getService(source);
            if (service == null) {
                return;
            }
            Utils.enforceBluetoothPrivilegedPermission(service);
            service.setDeviceAuthorized(device, isAuthorized);
        }

        @Override
        public void cleanup() {
            if (mService != null) {
                mService.cleanup();
            }
            mService = null;
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        mGmcs.dump(sb);
    }
}
