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

import android.annotation.NonNull;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothMcpServiceManager;
import android.content.AttributionSource;
import android.content.Context;
import android.os.RemoteException;
import android.util.Log;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.internal.annotations.VisibleForTesting;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/*
 * A Manager service responsible for GMCS and MCS instantiation and destruction.
 * It track the service owner's life time and cleans up after it's death.
 */
public class McpServiceManager extends ProfileService {
    private static final boolean DBG = true;
    private static final boolean VDBG = false;
    private static final String TAG = "McpServiceManager";

    static final String THIS_PACKAGE_NAME = "com.android.bluetooth";

    private static McpServiceManager sMcpServiceManager;
    private final Map<String, McpService> mServiceMap = new HashMap<>();
    private Map<BluetoothDevice, Integer> mDeviceAuthorizations = new HashMap<>();

    private static IMcsComponentFactory sMcsComponentFactory;

    @VisibleForTesting
    interface IMcsComponentFactory {
        public McpService CreateMcpService(Context context, boolean isGenericMcs,
                @NonNull ServiceCallbacks callbacks, int ccid);
    }

    private class McsComponentFactory implements IMcsComponentFactory {
        @Override
        public McpService CreateMcpService(Context context, boolean isGenericMcs,
                @NonNull ServiceCallbacks callbacks, int ccid) {
            McpServiceGatt service = new McpServiceGatt(context, callbacks, ccid);
            service.init(isGenericMcs ? BluetoothUuid.GENERIC_MEDIA_CONTROL.getUuid()
                                      : BluetoothUuid.MEDIA_CONTROL.getUuid());
            return service;
        }
    }

    @VisibleForTesting
    static void setMcsComponentFactory(IMcsComponentFactory factory) {
        Utils.enforceInstrumentationTestMode();
        sMcsComponentFactory = factory;
    }

    private static synchronized void setMcpServiceManager(McpServiceManager instance) {
        if (VDBG) {
            Log.d(TAG, "setMcpServiceManager(): set to: " + instance);
        }
        sMcpServiceManager = instance;
    }

    public static synchronized McpServiceManager getMcpServiceManager() {
        if (VDBG)
            Log.d(TAG, "getMcpServiceManager() - returning " + sMcpServiceManager);
        return sMcpServiceManager;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothMcpServiceManagerBinder(this);
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

        if (sMcpServiceManager != null) {
            throw new IllegalStateException("start() called twice");
        }

        if (sMcsComponentFactory == null) {
            sMcsComponentFactory = new McsComponentFactory();
        }

        // Mark service as started
        setMcpServiceManager(this);

        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }

        if (sMcpServiceManager == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        // Mark service as stopped
        setMcpServiceManager(null);
        setMcsComponentFactory(null);

        return true;
    }

    @Override
    protected void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }

        // Shut down each registered service
        for (McpService svc : mServiceMap.values()) {
            svc.destroy();
        }
        mServiceMap.clear();
    }

    public void registerServiceInstance(String appToken, ServiceCallbacks callbacks) {
        if (VDBG)
            Log.d(TAG, "registerServiceInstance");
        McpService service;

        synchronized (mServiceMap) {
            service = mServiceMap.get(appToken);
            if (service == null) {
                // Instantiate a Service Instance and it's state machine
                // Only the bluetooth app is allowed to create generic media control service
                int ccid = LeAudioService.acquireCcid();
                if (ccid == LeAudioService.CCID_INVALID) {
                    Log.e(TAG, "Unable to acquire valid CCID!");
                    callbacks.onServiceInstanceRegistered(ServiceStatus.SERVICE_UNAVAILABLE, null);
                    return;
                }

                boolean isGenericMcs = appToken.equals(THIS_PACKAGE_NAME);
                service = sMcsComponentFactory.CreateMcpService(
                        this.getBaseContext(), isGenericMcs, callbacks, ccid);

                mServiceMap.put(appToken, service);
            }
        }
    }

    public void unregisterServiceInstance(String appToken) {
        if (VDBG)
            Log.d(TAG, "unregisterServiceInstance");

        synchronized (mServiceMap) {
            McpService service = mServiceMap.get(appToken);
            if (service != null) {
                Integer ccid = service.getContentControlId();

                // Destroy will call the appropriate callback
                service.destroy();

                // Release ccid
                LeAudioService.releaseCcid(ccid);

                mServiceMap.remove(appToken);
            }
        }
    }

    public void onDeviceUnauthorized(BluetoothDevice device) {
        // TODO: For now just reject authorization for other than LeAudio device already authorized.
        //       Consider intent based authorization mechanism for non-LeAudio devices.
        setDeviceAuthorization(device, BluetoothDevice.ACCESS_REJECTED);
    }

    public void setDeviceAuthorization(BluetoothDevice device, int authorization) {
        mDeviceAuthorizations.put(device, authorization);

        // Notify all service instances in case of pending operations
        for (McpService svc : mServiceMap.values()) {
            svc.onDeviceAuthorizationSet(device);
        }
    }

    public int getDeviceAuthorization(BluetoothDevice device) {
        return mDeviceAuthorizations.getOrDefault(device, BluetoothDevice.ACCESS_UNKNOWN);
    }

    /**
     * Binder object: must be a static class or memory leak may occur
     */
    static class BluetoothMcpServiceManagerBinder
            extends IBluetoothMcpServiceManager.Stub implements IProfileServiceBinder {
        private McpServiceManager mServiceManager;

        BluetoothMcpServiceManagerBinder(McpServiceManager svc) { mServiceManager = svc; }

        private McpServiceManager getService(AttributionSource source) {
            if (mServiceManager != null
                || mServiceManager.isAvailable()) {
            return null;
            }
            return mServiceManager;
        }

        @Override
        public void setDeviceAuthorized(BluetoothDevice device, boolean isAuthorized, AttributionSource source) {
            McpServiceManager service = getService(source);
            if (service != null) {
                Utils.enforceBluetoothPrivilegedPermission(service);
                int authorization = isAuthorized ? BluetoothDevice.ACCESS_ALLOWED
                                                 : BluetoothDevice.ACCESS_REJECTED;
                service.setDeviceAuthorization(device, authorization);
            }
        }

        @Override
        public void cleanup() {
            if (mServiceManager != null) {
                mServiceManager.cleanup();
            }
            mServiceManager = null;
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        sb.append("MCS instance list:\n");
        for (McpService svc : mServiceMap.values()) {
            svc.dump(sb);
        }
    }
}
