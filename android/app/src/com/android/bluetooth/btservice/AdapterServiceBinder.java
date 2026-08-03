/*
 * Copyright (C) 2025 The Android Open Source Project
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

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.Manifest.permission.BLUETOOTH_PRIVILEGED;
import static android.Manifest.permission.BLUETOOTH_SCAN;
import static android.Manifest.permission.DUMP;
import static android.Manifest.permission.MODIFY_PHONE_STATE;
import static android.bluetooth.BluetoothAdapter.SCAN_MODE_NONE;
import static android.bluetooth.BluetoothDevice.TRANSPORT_AUTO;
import static android.bluetooth.BluetoothDevice.TRANSPORT_BREDR;
import static android.bluetooth.BluetoothDevice.TRANSPORT_LE;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTED;

import static com.android.bluetooth.ChangeIds.BONDING_APIS_REQUIRE_PRIVILEGED_PERMISSION;
import static com.android.bluetooth.ChangeIds.ENFORCE_CONNECT;
import static com.android.bluetooth.Util.callerIsSystem;
import static com.android.bluetooth.Util.callerIsSystemOrActiveOrManagedUser;
import static com.android.bluetooth.Util.enforceConnectPermissionForDataDelivery;
import static com.android.bluetooth.Util.getBytesFromAddress;
import static com.android.bluetooth.Util.getUidPidString;

import static java.util.Objects.requireNonNull;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.app.PendingIntent;
import android.app.compat.CompatChanges;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAdapter.ActiveDeviceProfile;
import android.bluetooth.BluetoothAdapter.ActiveDeviceUse;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothDevice.BluetoothAddress;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothProtoEnums;
import android.bluetooth.BluetoothSinkAudioPolicy;
import android.bluetooth.BluetoothStatusCodes;
import android.bluetooth.BondStatus;
import android.bluetooth.EncryptionStatus;
import android.bluetooth.GattOffloadCapabilities;
import android.bluetooth.IBluetooth;
import android.bluetooth.IBluetoothActivityEnergyInfoListener;
import android.bluetooth.IBluetoothConnectionCallback;
import android.bluetooth.IBluetoothHciVendorSpecificCallback;
import android.bluetooth.IBluetoothMetadataListener;
import android.bluetooth.IBluetoothOobDataCallback;
import android.bluetooth.IBluetoothPreferredAudioProfilesCallback;
import android.bluetooth.IBluetoothProfileCallback;
import android.bluetooth.IBluetoothQualityReportReadyCallback;
import android.bluetooth.IBluetoothSocketManager;
import android.bluetooth.IncomingRfcommSocketInfo;
import android.bluetooth.OobData;
import android.bluetooth.State;
import android.content.AttributionSource;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelUuid;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.util.Log;

import com.android.bluetooth.BluetoothStatsLog;
import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.RemoteDevices.DeviceProperties;
import com.android.bluetooth.flags.Flags;
import com.android.bluetooth.le_scan.ScanUtil;
import com.android.bluetooth.metrics.MetricsLogger;

import libcore.util.SneakyThrow;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * There is no leak of this binder since it is never re-used and the process is systematically
 * killed
 */
class AdapterServiceBinder extends IBluetooth.Stub {
    private static final String TAG = Util.BT_PREFIX + AdapterServiceBinder.class.getSimpleName();

    private static final int MIN_ADVT_INSTANCES_FOR_MA = 5;

    private final AdapterService mService;

    AdapterServiceBinder(AdapterService svc) {
        mService = svc;
    }

    private AdapterService getService() {
        if (!mService.isAvailable()) {
            return null;
        }
        return mService;
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private AdapterService getServiceAndEnforceCallerUserAndConnect(
            AttributionSource source, String method) {
        return getServiceAndEnforceCallerUserAndConnectInternal(source, method, false);
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private AdapterService getServiceAndEnforceCallerUserAndConnectAllowPcc(
            AttributionSource source, String method) {
        return getServiceAndEnforceCallerUserAndConnectInternal(source, method, true);
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private AdapterService getServiceAndEnforceCallerUserAndConnectInternal(
            AttributionSource source, String method, boolean allowPccBypass) {
        var service = getService();
        if (service == null
                || !callerIsSystemOrActiveOrManagedUser(service, TAG, method)
                || !enforceConnectPermissionForDataDelivery(
                        service, source, TAG, method, allowPccBypass)) {
            return null;
        }
        return service;
    }

    @RequiresPermission(BLUETOOTH_CONNECT)
    private AdapterService getServiceAndEnforceConnect(AttributionSource source, String method) {
        var service = getService();
        if (service == null
                || !enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return null;
        }
        return service;
    }

    @RequiresPermission(BLUETOOTH_SCAN)
    private AdapterService getServiceAndEnforceCallerUserAndScan(
            AttributionSource source, String method) {
        var service = getService();
        if (service == null
                || !callerIsSystemOrActiveOrManagedUser(service, TAG, method)
                || !Util.enforceScanPermissionForDataDelivery(service, source, TAG, method)) {
            return null;
        }
        return service;
    }

    @Override
    public List<ParcelUuid> getUuids(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getUuids");
        if (service == null) {
            return Collections.emptyList();
        }

        ParcelUuid[] parcels = service.getAdapterProperties().getUuids();
        if (parcels == null) {
            parcels = new ParcelUuid[0];
        }
        return Arrays.asList(parcels);
    }

    @Override
    public String getIdentityAddress(String address, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getIdentityAddress");
        if (service == null) {
            return null;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getIdentityAddress(address);
    }

    @Override
    @NonNull
    public BluetoothAddress getIdentityAddressWithType(
            @NonNull String address, AttributionSource source) {
        var method = "getIdentityAddressWithType";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return new BluetoothAddress(null, BluetoothDevice.ADDRESS_TYPE_UNKNOWN);
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getIdentityAddressWithType(address);
    }

    @Override
    public int getNameLengthForAdvertise(AttributionSource source) {
        AdapterService service = getService();
        if (service == null
                || !callerIsSystemOrActiveOrManagedUser(service, TAG, "getNameLengthForAdvertise")
                || !Util.enforceAdvertisePermissionForDataDelivery(service, source, TAG)) {
            return -1;
        }

        return service.getNameLengthForAdvertise();
    }

    @Override
    public int getScanMode(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "getScanMode");
        if (service == null) {
            return SCAN_MODE_NONE;
        }

        return service.getScanMode();
    }

    @Override
    public int setScanMode(int mode, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "setScanMode");
        if (service == null) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_SCAN_PERMISSION;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        String logCaller = getUidPidString() + " packageName=" + source.getPackageName();
        CompletableFuture<Boolean> future = new CompletableFuture<>();
        mService.getHandler()
                .post(
                        () ->
                                future.complete(
                                        service.getState() == State.ON
                                                && service.setScanMode(mode, logCaller)));
        return future.join() ? BluetoothStatusCodes.SUCCESS : BluetoothStatusCodes.ERROR_UNKNOWN;
    }

    @Override
    public long getDiscoverableTimeout(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "getDiscoverableTimeout");
        if (service == null) {
            return -1;
        }

        return service.getAdapterProperties().getDiscoverableTimeout();
    }

    @Override
    public int setDiscoverableTimeout(long timeout, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "setDiscoverableTimeout");
        if (service == null) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_SCAN_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getAdapterProperties().setDiscoverableTimeout((int) timeout)
                ? BluetoothStatusCodes.SUCCESS
                : BluetoothStatusCodes.ERROR_UNKNOWN;
    }

    @Override
    public boolean startDiscovery(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "startDiscovery");
        if (service == null) {
            return false;
        }

        Log.i(TAG, "startDiscovery: from " + getUidPidString());
        return service.startDiscovery(source);
    }

    @Override
    public boolean cancelDiscovery(AttributionSource source) {
        var user = Binder.getCallingUserHandle();
        var service = getServiceAndEnforceCallerUserAndScan(source, "cancelDiscovery");
        if (service == null) {
            return false;
        }

        Log.i(TAG, "cancelDiscovery: from " + getUidPidString());
        return service.cancelDiscovery(source, user);
    }

    @Override
    public boolean isDiscovering(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndScan(source, "isDiscovering");
        if (service == null) {
            return false;
        }

        return service.isDiscovering();
    }

    @Override
    public long getDiscoveryEndMillis(AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getDiscoveryEndMillis");
        if (service == null) {
            return -1;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getAdapterProperties().discoveryEndMillis();
    }

    @Override
    public List<BluetoothDevice> getMostRecentlyConnectedDevices(AttributionSource source) {
        // don't check caller, may be called from system UI
        var service = getServiceAndEnforceConnect(source, "getMostRecentlyConnectedDevices");
        if (service == null) {
            return Collections.emptyList();
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        return service.getMostRecentlyConnectedDevices();
    }

    @Override
    public List<BluetoothDevice> getBondedDevices(AttributionSource source) {
        // don't check caller, may be called from system UI
        var service = getServiceAndEnforceConnect(source, "getBondedDevices");
        if (service == null) {
            return Collections.emptyList();
        }

        return List.copyOf(service.getBondedDevices());
    }

    @Override
    public int getAdapterConnectionState() {
        // don't check caller, may be called from system UI
        AdapterService service = getService();
        if (service == null) {
            return BluetoothAdapter.STATE_DISCONNECTED;
        }

        return service.getAdapterProperties().getConnectionState();
    }

    /**
     * This method has an associated binder cache. The invalidation methods must be changed if the
     * logic behind this method changes.
     */
    @Override
    public int getProfileConnectionState(int profile, AttributionSource source) {
        AdapterService service = getService();
        boolean checkConnect = false;
        final int callingUid = Binder.getCallingUid();
        final long token = Binder.clearCallingIdentity();
        try {
            checkConnect = CompatChanges.isChangeEnabled(ENFORCE_CONNECT, callingUid);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
        if (service == null
                || !callerIsSystemOrActiveOrManagedUser(service, TAG, "getProfileConnectionState")
                || (checkConnect
                        && !enforceConnectPermissionForDataDelivery(
                                service, source, TAG, "getProfileConnectionState"))) {
            return STATE_DISCONNECTED;
        }

        return service.getAdapterProperties().getProfileConnectionState(profile);
    }

    @Override
    public boolean createBond(BluetoothDevice device, int transport, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "createBond");
        if (service == null) {
            return false;
        }

        Log.i(
                TAG,
                "createBond:"
                        + (" device=" + device)
                        + (" transport=" + transport)
                        + (" from " + getUidPidString()));
        return service.createBond(device, transport, null, null, source.getPackageName());
    }

    @Override
    public boolean createBondOutOfBand(
            BluetoothDevice device,
            int transport,
            OobData remoteP192Data,
            OobData remoteP256Data,
            AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "createBondOutOfBand");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        Log.i(
                TAG,
                "createBondOutOfBand:"
                        + (" device=" + device)
                        + (" transport=" + transport)
                        + (" from " + getUidPidString()));
        return service.createBond(
                device, transport, remoteP192Data, remoteP256Data, source.getPackageName());
    }

    private boolean bondingInitiator(DeviceProperties deviceProp, AttributionSource source) {
        AdapterService service = getService();

        if (service == null) return false;

        if (deviceProp == null) {
            return false;
        }

        Optional<String> packageName =
                service.getCallingPackageName(deviceProp.getDevice().getAddress());

        if (packageName.isEmpty()) {
            return false;
        }

        if (!deviceProp.isBondingInitiatedLocally()) {
            return false;
        }

        return (source.getPackageName().equals(packageName.get()));
    }

    @Override
    public boolean cancelBondProcess(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "cancelBondProcess");
        if (service == null) {
            return false;
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);

        if (!Utils.isBluetoothPairingHardeningSupported()
                || !bondingInitiator(deviceProp, source)) {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        }

        Log.i(TAG, "cancelBondProcess: device=" + device + ", from " + getUidPidString());

        if (deviceProp != null) {
            deviceProp.setBondingInitiatedLocally(false);
        }

        service.logUserBondResponse(device, false, source);
        return service.getNative().cancelBond(getBytesFromAddress(device.getAddress()));
    }

    @Override
    public boolean removeBond(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "removeBond");
        if (service == null) {
            return false;
        }

        if (Utils.isBluetoothPairingHardeningSupported()) {
            boolean checkPrivileged = false;
            final int callingUid = Binder.getCallingUid();
            final long token = Binder.clearCallingIdentity();

            try {
                checkPrivileged =
                        CompatChanges.isChangeEnabled(
                                BONDING_APIS_REQUIRE_PRIVILEGED_PERMISSION, callingUid);
            } finally {
                Binder.restoreCallingIdentity(token);
            }

            if (checkPrivileged) {
                service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
            }
        }

        Log.i(TAG, "removeBond: device=" + device + ", from " + getUidPidString());
        service.logUserBondResponse(device, false, source);
        return service.syncPost(() -> service.removeBond(device), false);
    }

    @Override
    public int getBondState(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        // don't check caller, may be called from system UI
        var service = getServiceAndEnforceConnect(source, "getBondState");
        if (service == null) {
            return BluetoothDevice.BOND_NONE;
        }

        return service.getBondState(device);
    }

    @Override
    public boolean isBondingInitiatedLocally(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        // don't check caller, may be called from system UI
        var service = getServiceAndEnforceConnect(source, "isBondingInitiatedLocally");
        if (service == null) {
            return false;
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        return deviceProp != null && deviceProp.isBondingInitiatedLocally();
    }

    @Override
    public void generateLocalOobData(
            int transport, IBluetoothOobDataCallback callback, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "generateLocalOobData");
        if (service == null) {
            return;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.generateLocalOobData(transport, callback);
    }

    @Override
    public int[] getSupportedProfiles(AttributionSource source) {
        var service = getServiceAndEnforceConnect(source, "getSupportedProfiles");
        if (service == null) {
            return new int[0];
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return Config.getSupportedProfiles();
    }

    @Override
    public int getConnectionState(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "getConnectionState");
        if (service == null) {
            return BluetoothDevice.CONNECTION_STATE_DISCONNECTED;
        }

        return service.getConnectionState(device);
    }

    @Override
    public int getConnectionHandle(
            BluetoothDevice device, int transport, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getConnectionHandle");
        if (service == null) {
            return BluetoothDevice.ERROR;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getConnectionHandle(device, transport);
    }

    @Override
    public boolean canBondWithoutDialog(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "canBondWithoutDialog");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.canBondWithoutDialog(device);
    }

    @Override
    public String getPackageNameOfBondingApplication(
            BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "getPackageNameOfBondingApplication");
        if (service == null) {
            return null;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getPackageNameOfBondingApplication(device);
    }

    @Override
    public boolean removeActiveDevice(@ActiveDeviceUse int profiles, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "removeActiveDevice");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(MODIFY_PHONE_STATE, null);
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        Log.i(TAG, "removeActiveDevice: profiles=" + profiles + ", from " + getUidPidString());
        return service.setActiveDevice(null, profiles);
    }

    @Override
    public boolean setActiveDevice(
            BluetoothDevice device, @ActiveDeviceUse int profiles, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setActiveDevice");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(MODIFY_PHONE_STATE, null);
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        Log.i(
                TAG,
                "setActiveDevice: device="
                        + device
                        + ", profiles="
                        + profiles
                        + ", from "
                        + getUidPidString());

        return service.setActiveDevice(device, profiles);
    }

    @Override
    public List<BluetoothDevice> getActiveDevices(
            @ActiveDeviceProfile int profile, AttributionSource source) {
        var method = "getActiveDevices";
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, method);
        if (service == null) {
            return Collections.emptyList();
        }

        try {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } catch (SecurityException e) {
            /* see android.bluetooth.BluetoothAdapter#getActiveDevices */
            Utils.enforceBluetoothPrivilegedAndroidAutoOrThrow(service, e);
        }

        return service.getActiveDevices(profile);
    }

    @Override
    // TODO: remove SuppressWarnings as part of gattConnSettings flag removal
    @SuppressWarnings("MissingOrMismatchedRequiresPermissionAnnotation")
    public int connectAllEnabledProfiles(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null || !service.isEnabled()) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }

        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "connectAllEnabledProfiles")) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(
                service, source, TAG, "connectAllEnabledProfiles")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        if (!Flags.gattConnSettings()) {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
            service.enforceCallingOrSelfPermission(MODIFY_PHONE_STATE, null);
        } else {
            Utils.enforceCdmAssociationIfNotBluetoothPrivileged(
                    service, service.getCompanionDeviceManager(), source, device);
        }

        Log.i(TAG, "connectAllEnabledProfiles: device=" + device + ", from " + getUidPidString());
        MetricsLogger.getInstance()
                .logBluetoothEvent(
                        device,
                        BluetoothStatsLog
                                .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__INITIATOR_CONNECTION,
                        BluetoothStatsLog.BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__START,
                        source.getUid());

        if (Flags.hapOnMainLooper()) {
            return service.syncPost(
                    () -> service.connectAllEnabledProfiles(device),
                    BluetoothStatusCodes.ERROR_TIMEOUT);
        }

        try {
            return service.connectAllEnabledProfiles(device);
        } catch (Exception e) {
            Log.v(TAG, "connectAllEnabledProfiles() failed", e);
            SneakyThrow.sneakyThrow(e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public int disconnectAllEnabledProfiles(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "disconnectAllEnabledProfiles")) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(
                service, source, TAG, "disconnectAllEnabledProfiles")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        if (!Flags.gattConnSettings()) {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } else {
            Utils.enforceCdmAssociationIfNotBluetoothPrivileged(
                    service, service.getCompanionDeviceManager(), source, device);
        }

        Log.i(
                TAG,
                "disconnectAllEnabledProfiles: device="
                        + device
                        + ", from "
                        + getUidPidString()
                        + " packageName:"
                        + source.getPackageName());

        if (Flags.hapOnMainLooper()) {
            return service.syncPost(
                    () ->
                            service.disconnectAllEnabledProfiles(
                                    device,
                                    BluetoothStatusCodes.ERROR_DISCONNECT_REASON_USER_REQUEST),
                    BluetoothStatusCodes.ERROR_TIMEOUT);
        }
        try {
            return service.disconnectAllEnabledProfiles(
                    device, BluetoothStatusCodes.ERROR_DISCONNECT_REASON_USER_REQUEST);
        } catch (Exception e) {
            Log.v(TAG, "disconnectAllEnabledProfiles() failed", e);
            SneakyThrow.sneakyThrow(e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public int disconnectAllAcl(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "disconnectAllAcl")) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, "disconnectAllAcl")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        if (!Flags.gattConnSettings()) {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } else {
            Utils.enforceCdmAssociationIfNotBluetoothPrivileged(
                    service, service.getCompanionDeviceManager(), source, device);
        }

        Log.i(
                TAG,
                "disconnectAllAcl: device="
                        + device
                        + ", from "
                        + getUidPidString()
                        + " packageName:"
                        + source.getPackageName());

        return service.disconnectAllAcl(
                device, BluetoothStatusCodes.ERROR_DISCONNECT_REASON_USER_REQUEST);
    }

    @Override
    public String getRemoteName(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getRemoteName");
        if (service == null) {
            return null;
        }

        return service.getRemoteName(device);
    }

    @Override
    public int getRemoteType(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getRemoteType");
        if (service == null) {
            return BluetoothDevice.DEVICE_TYPE_UNKNOWN;
        }

        return service.getRemoteType(device);
    }

    @Override
    public String getRemoteAlias(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getRemoteAlias");
        if (service == null) {
            return null;
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        return deviceProp != null ? deviceProp.getAlias() : null;
    }

    @Override
    public int setRemoteAlias(BluetoothDevice device, String name, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "setRemoteAlias")) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (name != null && name.isEmpty()) {
            throw new IllegalArgumentException("alias cannot be the empty string");
        }

        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, "setRemoteAlias")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        Utils.enforceCdmAssociationIfNotBluetoothPrivileged(
                service, service.getCompanionDeviceManager(), source, device);

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        deviceProp.setAlias(device, name);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int getRemoteClass(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getRemoteClass");
        if (service == null) {
            return 0;
        }

        return service.getRemoteClass(device);
    }

    // Nullable is needed because CTS enforce it
    @Override
    public @Nullable List<ParcelUuid> getRemoteUuids(
            BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getRemoteUuids");
        if (service == null) {
            return Collections.emptyList();
        }

        final ParcelUuid[] parcels = service.getRemoteUuids(device);
        if (parcels == null) {
            return null;
        }
        return Arrays.asList(parcels);
    }

    @Override
    public boolean fetchRemoteUuidsWithSdp(
            BluetoothDevice device, int transport, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "fetchRemoteUuidsWithSdp");
        if (service == null) {
            return false;
        }
        if (transport != TRANSPORT_AUTO) {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        }

        Log.i(
                TAG,
                "fetchRemoteUuidsWithSdp: device="
                        + device
                        + ", transport="
                        + transport
                        + ", from "
                        + getUidPidString());

        service.addAssociatedPackage(device, source.getPackageName());
        service.getRemoteDevices().fetchUuids(device, transport);
        MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_FETCH_UUID_REQUEST, 1);
        return true;
    }

    @Override
    public boolean fetchRemoteUuids(
            BluetoothDevice device, int transport, AttributionSource source) {
        if (transport != TRANSPORT_AUTO
                && transport != TRANSPORT_BREDR
                && transport != TRANSPORT_LE) {
            throw new IllegalArgumentException("invalid transport: " + transport);
        }
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "fetchRemoteUuids");
        if (service == null) {
            return false;
        }

        Log.i(
                TAG,
                "fetchRemoteUuids: device="
                        + device
                        + ", transport="
                        + transport
                        + ", from "
                        + getUidPidString());

        service.addAssociatedPackage(device, source.getPackageName());
        service.getRemoteDevices().fetchUuids(device, transport);
        MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_FETCH_UUID_REQUEST, 1);
        return true;
    }

    @Override
    public boolean setPin(
            BluetoothDevice device,
            boolean accept,
            int len,
            byte[] pinCode,
            AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setPin");
        if (service == null) {
            return false;
        }

        if (Utils.isBluetoothPairingHardeningSupported()) {
            boolean checkPrivileged = false;
            final int callingUid = Binder.getCallingUid();
            final long token = Binder.clearCallingIdentity();
            try {
                checkPrivileged =
                        CompatChanges.isChangeEnabled(
                                BONDING_APIS_REQUIRE_PRIVILEGED_PERMISSION, callingUid);
            } finally {
                Binder.restoreCallingIdentity(token);
            }

            if (checkPrivileged) {
                service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
            }
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        // Only allow setting a pin in bonding state, or bonded state in case of security
        // upgrade.
        if (deviceProp == null || !deviceProp.isBondingOrBonded()) {
            Log.e(TAG, "setPin: device=" + device + ", not bonding");
            return false;
        }
        if (pinCode.length != len) {
            android.util.EventLog.writeEvent(
                    0x534e4554, "139287605", -1, "PIN code length mismatch");
            return false;
        }
        service.logUserBondResponse(device, accept, source);
        Log.i(
                TAG,
                "setPin: device=" + device + ", accept=" + accept + ", from " + getUidPidString());
        return service.getNative()
                .pinReply(getBytesFromAddress(device.getAddress()), accept, len, pinCode);
    }

    @Override
    public boolean setPairingConfirmation(
            BluetoothDevice device, boolean accept, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setPairingConfirmation");
        if (service == null) {
            return false;
        }

        try {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } catch (SecurityException e) {
            /* see android.bluetooth.BluetoothDevice#setPairingConfirmation */
            Utils.enforceBluetoothPrivilegedAndroidAutoOrThrow(service, e);
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        if (deviceProp == null || !deviceProp.isBonding()) {
            Log.e(TAG, "setPairingConfirmation: device=" + device + ", not bonding");
            return false;
        }
        service.logUserBondResponse(device, accept, source);
        Log.i(
                TAG,
                "setPairingConfirmation: device="
                        + device
                        + ", accept="
                        + accept
                        + ", from "
                        + getUidPidString());

        return service.getNative()
                .sspReply(
                        getBytesFromAddress(device.getAddress()),
                        AbstractionLayer.BT_PAIRING_VARIANT_PASSKEY_CONFIRMATION,
                        accept,
                        0);
    }

    @Override
    public boolean getSilenceMode(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getSilenceMode");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getSilenceDeviceManager().getSilenceMode(device);
    }

    @Override
    public boolean setSilenceMode(
            BluetoothDevice device, boolean silence, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setSilenceMode");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getSilenceDeviceManager().setSilenceMode(device, silence);
        return true;
    }

    @Override
    public int getPhonebookAccessPermission(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var method = "getPhonebookAccessPermission";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return BluetoothDevice.ACCESS_UNKNOWN;
        }

        return service.getPhonebookAccessPermission(device);
    }

    @Override
    public boolean setPhonebookAccessPermission(
            BluetoothDevice device, int value, AttributionSource source) {
        requireNonNull(device);
        var method = "setPhonebookAccessPermission";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.setPhonebookAccessPermission(device, value);
        return true;
    }

    @Override
    public int getMessageAccessPermission(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var method = "getMessageAccessPermission";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return BluetoothDevice.ACCESS_UNKNOWN;
        }

        return service.getMessageAccessPermission(device);
    }

    @Override
    public boolean setMessageAccessPermission(
            BluetoothDevice device, int value, AttributionSource source) {
        requireNonNull(device);
        var method = "setMessageAccessPermission";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.setMessageAccessPermission(device, value);
        return true;
    }

    @Override
    public int getSimAccessPermission(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getSimAccessPermission");
        if (service == null) {
            return BluetoothDevice.ACCESS_UNKNOWN;
        }

        return service.getSimAccessPermission(device);
    }

    @Override
    public boolean setSimAccessPermission(
            BluetoothDevice device, int value, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setSimAccessPermission");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.setSimAccessPermission(device, value);
        return true;
    }

    @Override
    public void logL2capcocServerConnection(
            @Nullable BluetoothDevice device,
            int port,
            boolean isSecured,
            int result,
            long socketCreationTimeMillis,
            long socketCreationLatencyMillis,
            long socketConnectionTimeMillis,
            long timeoutMillis) {
        AdapterService service = getService();
        if (service == null) {
            return;
        }
        service.logL2capcocServerConnection(
                device,
                port,
                isSecured,
                result,
                socketCreationTimeMillis,
                socketCreationLatencyMillis,
                socketConnectionTimeMillis,
                timeoutMillis,
                Binder.getCallingUid());
    }

    @Override
    public IBluetoothSocketManager getSocketManager() {
        AdapterService service = getService();
        if (service == null) {
            return null;
        }

        return IBluetoothSocketManager.Stub.asInterface(service.getBluetoothSocketManagerBinder());
    }

    @Override
    public void logL2capcocClientConnection(
            BluetoothDevice device,
            int port,
            boolean isSecured,
            int result,
            long socketCreationTimeNanos,
            long socketCreationLatencyNanos,
            long socketConnectionTimeNanos) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return;
        }
        service.logL2capcocClientConnection(
                device,
                port,
                isSecured,
                result,
                socketCreationTimeNanos,
                socketCreationLatencyNanos,
                socketConnectionTimeNanos,
                Binder.getCallingUid());
    }

    @Override
    public boolean sdpSearch(BluetoothDevice device, ParcelUuid uuid, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "sdpSearch");
        if (service == null) {
            return false;
        }
        service.addAssociatedPackage(device, source.getPackageName());
        return service.sdpSearch(device, uuid);
    }

    @Override
    public int getBatteryLevel(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnectAllowPcc(source, "getBatteryLevel");
        if (service == null) {
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }

        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        return deviceProp.getBatteryLevel();
    }

    @Override
    public int getMaxConnectedAudioDevices(AttributionSource source) {
        // don't check caller, may be called from system UI
        var service = getServiceAndEnforceConnect(source, "getMaxConnectedAudioDevices");
        if (service == null) {
            return -1;
        }

        return service.getMaxConnectedAudioDevices();
    }

    @Override
    public void registerBluetoothConnectionCallback(
            IBluetoothConnectionCallback callback, AttributionSource source) {
        var method = "registerBluetoothConnectionCallback";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getBluetoothConnectionCallbacks().register(callback);
    }

    @Override
    public void unregisterBluetoothConnectionCallback(
            IBluetoothConnectionCallback callback, AttributionSource source) {
        var method = "unregisterBluetoothConnectionCallback";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getBluetoothConnectionCallbacks().unregister(callback);
    }

    @Override
    public boolean isMultiAdvertisementSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        int val = service.getAdapterProperties().getNumOfAdvertisementInstancesSupported();
        return val >= MIN_ADVT_INSTANCES_FOR_MA;
    }

    /**
     * This method has an associated binder cache. The invalidation methods must be changed if the
     * logic behind this method changes.
     */
    @Override
    public boolean isOffloadedFilteringSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }
        return ScanUtil.isOffloadedFilteringSupported(service);
    }

    @Override
    public boolean isOffloadedScanBatchingSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }
        return ScanUtil.isOffloadedScanBatchingSupported(service);
    }

    @Override
    public boolean isLe2MPhySupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.isLe2MPhySupported();
    }

    @Override
    public boolean isLeCodedPhySupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.isLeCodedPhySupported();
    }

    @Override
    public boolean isLeHighDataThroughputPhySupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.isLeHighDataThroughputPhySupported();
    }

    @Override
    public boolean isLeExtendedAdvertisingSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.isLeExtendedAdvertisingSupported();
    }

    @Override
    public boolean isLePeriodicAdvertisingSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.isLePeriodicAdvertisingSupported();
    }

    @Override
    public boolean isLeAudioSupported() {
        Set<Integer> supportedProfileServices =
                Arrays.stream(Config.getSupportedProfiles()).boxed().collect(Collectors.toSet());
        int[] leAudioUnicastProfiles = Config.getLeAudioUnicastProfiles();

        return Arrays.stream(leAudioUnicastProfiles).allMatch(supportedProfileServices::contains);
    }

    @Override
    public boolean isLeAudioBroadcastSourceSupported() {
        return Config.isProfileSupported(BluetoothProfile.LE_AUDIO_BROADCAST);
    }

    @Override
    public boolean isLeAudioBroadcastAssistantSupported() {
        return Config.isProfileSupported(BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT);
    }

    @Override
    public int isDistanceMeasurementSupported(AttributionSource source) {
        AdapterService service = getService();
        var method = "isDistanceMeasurementSupported";
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        } else if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        } else if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return BluetoothStatusCodes.FEATURE_SUPPORTED;
    }

    @Override
    public int getLeMaximumAdvertisingDataLength() {
        AdapterService service = getService();
        if (service == null) {
            return 0;
        }

        return service.getLeMaximumAdvertisingDataLength();
    }

    @Override
    public boolean isActivityAndEnergyReportingSupported() {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }

        return service.getAdapterProperties().isActivityAndEnergyReportingSupported();
    }

    @Override
    public boolean registerMetadataListener(
            IBluetoothMetadataListener listener, BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        requireNonNull(listener);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "registerMetadataListener");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getHandler()
                .post(
                        () ->
                                service.getMetadataListeners()
                                        .computeIfAbsent(device, k -> new RemoteCallbackList<>())
                                        .register(listener));
        return true;
    }

    @Override
    public boolean unregisterMetadataListener(
            IBluetoothMetadataListener listener, BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        requireNonNull(listener);
        var method = "unregisterMetadataListener";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getHandler()
                .post(
                        () ->
                                service.getMetadataListeners()
                                        .computeIfPresent(
                                                device,
                                                (k, v) -> {
                                                    v.unregister(listener);
                                                    if (v.getRegisteredCallbackCount() == 0) {
                                                        return null;
                                                    }
                                                    return v;
                                                }));
        return true;
    }

    @Override
    public boolean setMetadata(
            BluetoothDevice device, int key, byte[] value, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "setMetadata");
        if (service == null) {
            return false;
        }

        try {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } catch (SecurityException e) {
            /* see android.bluetooth.BluetoothDevice#setMetadata */
            Utils.enforceBluetoothPrivilegedAndroidAutoOrThrow(service, e);
        }

        return service.setMetadata(device, key, value);
    }

    @Override
    public byte[] getMetadata(BluetoothDevice device, int key, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getMetadata");
        if (service == null) {
            return null;
        }

        try {
            service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        } catch (SecurityException e) {
            /* see android.bluetooth.BluetoothDevice#getMetadata */
            Utils.enforceBluetoothPrivilegedAndroidAutoOrThrow(service, e);
        }

        return service.getMetadata(device, key);
    }

    @Override
    public int isRequestAudioPolicyAsSinkSupported(
            BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var method = "isRequestAudioPolicyAsSinkSupported";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return BluetoothStatusCodes.FEATURE_NOT_CONFIGURED;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.isRequestAudioPolicyAsSinkSupported(device);
    }

    @Override
    public int requestAudioPolicyAsSink(
            BluetoothDevice device, BluetoothSinkAudioPolicy policies, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        var method = "requestAudioPolicyAsSink";
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        } else if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        } else if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.requestAudioPolicyAsSink(device, policies);
    }

    @Override
    public BluetoothSinkAudioPolicy getRequestedAudioPolicyAsSink(
            BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var method = "getRequestedAudioPolicyAsSink";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return null;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getRequestedAudioPolicyAsSink(device);
    }

    @Override
    public void requestActivityInfo(
            IBluetoothActivityEnergyInfoListener listener, AttributionSource source) {
        var service = getServiceAndEnforceConnect(source, "requestActivityInfo");
        if (service == null) {
            return;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        try {
            listener.onBluetoothActivityEnergyInfoAvailable(service.requestActivityInfo());
        } catch (RemoteException e) {
            Log.e(TAG, "onBluetoothActivityEnergyInfo: RemoteException", e);
        }
    }

    @Override
    public void dump(FileDescriptor fd, String[] args) {
        PrintWriter writer = new PrintWriter(new FileOutputStream(fd));
        AdapterService service = getService();
        if (service == null) {
            return;
        }

        service.enforceCallingOrSelfPermission(DUMP, null);
        service.dump(fd, writer, args);
        writer.close();
    }

    @Override
    public boolean allowLowLatencyAudio(
            boolean allowed, BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "allowLowLatencyAudio");
        if (service == null) {
            return false;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.allowLowLatencyAudio(allowed, device);
    }

    @Override
    public int startRfcommListener(
            String name, ParcelUuid uuid, PendingIntent pendingIntent, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "startRfcommListener");
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }

        Util.enforceCallingUidIsNotPcc("AdapterServiceBinder.startRfcommListener");
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.startRfcommListener(name, uuid, pendingIntent, source);
    }

    @Override
    public int stopRfcommListener(ParcelUuid uuid, AttributionSource source) {
        var service = getServiceAndEnforceCallerUserAndConnect(source, "stopRfcommListener");
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.stopRfcommListener(uuid, source);
    }

    @Override
    public IncomingRfcommSocketInfo retrievePendingSocketForServiceRecord(
            ParcelUuid uuid, AttributionSource source) {
        var method = "retrievePendingSocketForServiceRecord";
        var service = getServiceAndEnforceCallerUserAndConnect(source, method);
        if (service == null) {
            return null;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.retrievePendingSocketForServiceRecord(uuid, source);
    }

    @Override
    public int setPreferredAudioProfiles(
            BluetoothDevice device, Bundle modeToProfileBundle, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "setPreferredAudioProfiles";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        requireNonNull(modeToProfileBundle);
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        if (service.getBondState(device) != BluetoothDevice.BOND_BONDED) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        return service.setPreferredAudioProfiles(device, modeToProfileBundle);
    }

    @Override
    public Bundle getPreferredAudioProfiles(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        var service = getServiceAndEnforceCallerUserAndConnect(source, "getPreferredAudioProfiles");
        if (service == null) {
            return Bundle.EMPTY;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        if (service.getBondState(device) != BluetoothDevice.BOND_BONDED) {
            return Bundle.EMPTY;
        }
        return service.getPreferredAudioProfiles(device);
    }

    @Override
    public int notifyActiveDeviceChangeApplied(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "notifyActiveDeviceChangeApplied";
        if (!callerIsSystem(TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        if (service.getBondState(device) != BluetoothDevice.BOND_BONDED) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        return service.notifyActiveDeviceChangeApplied(device);
    }

    @Override
    public int isDualModeAudioEnabled(AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        if (!enforceConnectPermissionForDataDelivery(
                service, source, TAG, "isDualModeAudioEnabled")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        if (!Utils.isDualModeAudioEnabled()) {
            return BluetoothStatusCodes.FEATURE_NOT_SUPPORTED;
        }

        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int registerPreferredAudioProfilesChangedCallback(
            IBluetoothPreferredAudioProfilesCallback callback, AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "registerPreferredAudioProfilesChangedCallback";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        requireNonNull(callback);
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        // If LE only mode is enabled, the dual mode audio feature is disabled
        if (!Utils.isDualModeAudioEnabled()) {
            return BluetoothStatusCodes.FEATURE_NOT_SUPPORTED;
        }

        service.getPreferredAudioProfilesCallbacks().register(callback);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int unregisterPreferredAudioProfilesChangedCallback(
            IBluetoothPreferredAudioProfilesCallback callback, AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "unregisterPreferredAudioProfilesChangedCallback";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        requireNonNull(callback);
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        if (!service.getPreferredAudioProfilesCallbacks().unregister(callback)) {
            Log.e(TAG, method + "(): callback was never " + "registered");
            return BluetoothStatusCodes.ERROR_CALLBACK_NOT_REGISTERED;
        }
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int registerBluetoothQualityReportReadyCallback(
            IBluetoothQualityReportReadyCallback callback, AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "registerBluetoothQualityReportReadyCallback";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        requireNonNull(callback);
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        service.getBluetoothQualityReportReadyCallbacks().register(callback);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int unregisterBluetoothQualityReportReadyCallback(
            IBluetoothQualityReportReadyCallback callback, AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "unregisterBluetoothQualityReportReadyCallback";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        requireNonNull(callback);
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        if (!service.getBluetoothQualityReportReadyCallbacks().unregister(callback)) {
            Log.e(TAG, method + "(): callback was never registered");
            return BluetoothStatusCodes.ERROR_CALLBACK_NOT_REGISTERED;
        }
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public void registerHciVendorSpecificCallback(
            IBluetoothHciVendorSpecificCallback callback, int[] eventCodes, int[] aclHandles) {
        AdapterService service = getService();
        if (service == null) {
            return;
        }
        if (!callerIsSystemOrActiveOrManagedUser(
                service, TAG, "registerHciVendorSpecificCallback")) {
            throw new SecurityException("not allowed");
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        requireNonNull(callback);
        requireNonNull(eventCodes);
        requireNonNull(aclHandles);

        Set<Integer> eventCodesSet = Arrays.stream(eventCodes).boxed().collect(Collectors.toSet());
        Set<Integer> aclHandlesSet = Arrays.stream(aclHandles).boxed().collect(Collectors.toSet());
        if (eventCodesSet.stream()
                .anyMatch((n) -> (n < 0) || (n >= 0x52 && n < 0x60) || (n > 0xff))) {
            throw new IllegalArgumentException("invalid vendor-specific event code");
        }

        if (aclHandlesSet.stream().anyMatch((n) -> (n <= 0) || (n > 0xfff))) {
            throw new IllegalArgumentException("invalid acl handle");
        }

        service.getBluetoothHciVendorSpecificDispatcher()
                .register(callback, eventCodesSet, aclHandlesSet);
    }

    @Override
    public void unregisterHciVendorSpecificCallback(IBluetoothHciVendorSpecificCallback callback) {
        AdapterService service = getService();
        if (service == null) {
            return;
        }
        if (!callerIsSystemOrActiveOrManagedUser(
                service, TAG, "unregisterHciVendorSpecificCallback")) {
            throw new SecurityException("not allowed");
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        requireNonNull(callback);
        service.getBluetoothHciVendorSpecificDispatcher().unregister(callback);
    }

    @Override
    public void sendHciVendorSpecificCommand(
            int ocf, byte[] parameters, IBluetoothHciVendorSpecificCallback callback) {
        AdapterService service = getService();
        if (service == null) {
            return;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "sendHciVendorSpecificCommand")) {
            throw new SecurityException("not allowed");
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        // Open this no-op android command for test purpose
        int getVendorCapabilitiesOcf = 0x153;
        if (ocf < 0
                || (ocf >= 0x150 && ocf < 0x160 && ocf != getVendorCapabilitiesOcf)
                || (ocf > 0x3ff)) {
            throw new IllegalArgumentException("invalid vendor-specific event code");
        }
        requireNonNull(parameters);
        if (parameters.length > 255) {
            throw new IllegalArgumentException("Parameters size is too big");
        }

        Optional<byte[]> cookie =
                service.getBluetoothHciVendorSpecificDispatcher().getRegisteredCookie(callback);
        if (cookie.isEmpty()) {
            Log.e(TAG, "send command without registered callback");
            throw new IllegalStateException("callback not registered");
        }

        service.getBluetoothHciVendorSpecificNativeInterface()
                .sendCommand(ocf, parameters, cookie.get());
    }

    @Override
    public int getOffloadedTransportDiscoveryDataScanSupported(AttributionSource source) {
        var method = "getOffloadedTransportDiscoveryDataScanSupported";
        var service = getServiceAndEnforceCallerUserAndScan(source, method);
        if (service == null) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_SCAN_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getOffloadedTransportDiscoveryDataScanSupported();
    }

    @Override
    public IBinder getBluetoothGatt() {
        AdapterService service = getService();
        return service == null ? null : service.getBluetoothGatt();
    }

    @Override
    public IBinder getBluetoothScan() {
        AdapterService service = getService();
        return service == null ? null : service.getBluetoothScan();
    }

    @Override
    public void getProfileOneway(int profileId, IBluetoothProfileCallback callback) {
        AdapterService service = getService();
        if (service == null) {
            return;
        }

        service.getProfile(profileId, callback);
    }

    @Override
    public int setActiveAudioDevicePolicy(
            BluetoothDevice device, int policy, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "setActiveAudioDevicePolicy";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        if (!service.getBondedDevices().contains(device)) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        service.setActiveAudioPolicy(device, policy);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int getActiveAudioDevicePolicy(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothDevice.ACTIVE_AUDIO_DEVICE_POLICY_DEFAULT;
        }
        var method = "getActiveAudioDevicePolicy";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            throw new IllegalStateException(
                    "Caller is not the system or part of the active/managed user");
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothDevice.ACTIVE_AUDIO_DEVICE_POLICY_DEFAULT;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getActiveAudioPolicy(device);
    }

    @Override
    public int setMicrophonePreferredForCalls(
            BluetoothDevice device, boolean enabled, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "setMicrophonePreferredForCalls";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);

        if (!service.getBondedDevices().contains(device)) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        service.setMicrophonePreferredForCalls(device, enabled);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public boolean isMicrophonePreferredForCalls(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return true;
        }
        var method = "isMicrophonePreferredForCalls";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            throw new IllegalStateException(
                    "Caller is not the system or part of the active/managed user");
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return true;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.isMicrophonePreferredForCalls(device);
    }

    @Override
    public int setOnHeadDetectionEnabled(
            BluetoothDevice device, int enabledState, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        var method = "setOnHeadDetectionEnabled";
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, method)) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, method)) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        deviceProp.setOnHeadDetectionEnabledState(enabledState);
        Log.d(
                TAG,
                "Successfully set on-head detection enabled state for device "
                        + device
                        + " with value: "
                        + enabledState);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public int setOnHead(BluetoothDevice device, int state, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ENABLED;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "setOnHead")) {
            return BluetoothStatusCodes.ERROR_BLUETOOTH_NOT_ALLOWED;
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, "setOnHead")) {
            return BluetoothStatusCodes.ERROR_MISSING_BLUETOOTH_CONNECT_PERMISSION;
        }

        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        DeviceProperties deviceProp = service.getRemoteDevices().getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothStatusCodes.ERROR_DEVICE_NOT_BONDED;
        }
        deviceProp.setOnHeadDetectionState(state);
        Log.d(
                TAG,
                "Successfully set on-head detection state for device "
                        + device
                        + " with value: "
                        + state);
        return BluetoothStatusCodes.SUCCESS;
    }

    @Override
    public boolean isLeCocSocketOffloadSupported(AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.isLeCocSocketOffloadSupported();
    }

    @Override
    public boolean isRfcommSocketOffloadSupported(AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return false;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.isRfcommSocketOffloadSupported();
    }

    @Override
    public IBinder getBluetoothAdvertise() {
        AdapterService service = getService();
        return service == null ? null : service.getBluetoothAdvertise();
    }

    @Override
    public IBinder getDistanceMeasurement() {
        AdapterService service = getService();
        return service == null ? null : service.getDistanceMeasurement();
    }

    @Override
    public int getKeyMissingCount(BluetoothDevice device, AttributionSource source) {
        requireNonNull(device);
        AdapterService service = getService();
        if (service == null) {
            return -1;
        }
        if (!callerIsSystemOrActiveOrManagedUser(service, TAG, "getKeyMissingCount")) {
            throw new IllegalStateException(
                    "Caller is not the system or part of the active/managed user");
        }
        if (!enforceConnectPermissionForDataDelivery(service, source, TAG, "getKeyMissingCount")) {
            return -1;
        }

        return service.getKeyMissingCount(device);
    }

    @Override
    public EncryptionStatus.InnerParcel getEncryptionStatus(
            BluetoothDevice device, AttributionSource source, int transport) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "getEncryptionStatus");
        if (service == null) {
            return null;
        }

        EncryptionStatus enc = service.getEncryptionStatus(device, transport);
        if (enc == null) {
            return null;
        }
        return enc.getParcel();
    }

    @Override
    public boolean isConnected(BluetoothDevice device, AttributionSource source, int transport) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "isConnected");
        if (service == null) {
            return false;
        }

        return service.isConnected(device, transport);
    }

    @Override
    public GattOffloadCapabilities.InnerParcel getSupportedGattOffloadCapabilities(
            AttributionSource source) {
        AdapterService service = getService();
        if (service == null) {
            return null;
        }
        service.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED, null);
        return service.getSupportedGattOffloadCapabilities();
    }

    @Override
    public BondStatus.InnerParcel getBondStatus(
            BluetoothDevice device, AttributionSource source, int transport) {
        requireNonNull(device);
        var service = getServiceAndEnforceConnect(source, "getBondStatus");
        if (service == null) {
            return null;
        }
        BondStatus bondStatus = service.getBondStatus(device, transport);
        return bondStatus != null ? bondStatus.getParcel() : null;
    }
}
