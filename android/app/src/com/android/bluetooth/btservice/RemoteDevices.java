/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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
import static android.bluetooth.BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
import static android.bluetooth.BluetoothDevice.TRANSPORT_AUTO;
import static android.bluetooth.BluetoothDevice.TRANSPORT_BREDR;
import static android.bluetooth.BluetoothDevice.TRANSPORT_LE;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTED;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTED;
import static android.bluetooth.BluetoothUtils.RemoteExceptionIgnoringConsumer;
import static android.bluetooth.BluetoothUtils.toAnonymizedAddress;

import static java.util.Objects.requireNonNullElseGet;

import android.annotation.NonNull;
import android.app.Activity;
import android.app.BroadcastOptions;
import android.app.admin.SecurityLog;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAssignedNumbers;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothDevice.AddressType;
import android.bluetooth.BluetoothDevice.BluetoothAddress;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothProtoEnums;
import android.bluetooth.BluetoothSinkAudioPolicy;
import android.bluetooth.BondStatus;
import android.bluetooth.EncryptionStatus;
import android.bluetooth.IBluetoothConnectionCallback;
import android.bluetooth.State;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemProperties;
import android.util.Log;

import com.android.bluetooth.BluetoothStatsLog;
import com.android.bluetooth.R;
import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.flags.Flags;
import com.android.bluetooth.hfp.HeadsetHalConstants;
import com.android.bluetooth.metrics.MetricsLogger;
import com.android.internal.annotations.VisibleForTesting;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** Remote device manager. This class is currently mostly used for HF and AG remote devices. */
public class RemoteDevices {
    private static final String TAG = Util.BT_PREFIX + RemoteDevices.class.getSimpleName();

    // Maximum number of device properties to remember
    @VisibleForTesting static final int MAX_DEVICE_QUEUE_SIZE = 200;

    private final AdapterService mAdapterService;
    private final BluetoothAdapter mAdapter;
    private final Object mObject = new Object();

    private static final int MESSAGE_NOTIFY_UUIDS = 1;
    private static final int MESSAGE_SERVICE_DISCOVERY_TIMEOUT = 2;

    @VisibleForTesting static final int SERVICE_DISCOVERY_TIMEOUT_MS = 6000; // 6 seconds

    private static final String LOG_SOURCE_DIS = "DIS";

    private final LinkedHashMap<String, DeviceProperties> mDevices =
            new LinkedHashMap<>(MAX_DEVICE_QUEUE_SIZE);
    private final HashMap<String, String> mAddressMap =
            new HashMap<>(); // Identity address to pseudo address map
    private final WatchConnectionStateListener mWatchConnectionStateListener;

    record AclLinkSpec(BluetoothDevice device, int transport) {}

    private final Set<AclLinkSpec> mConnectedDevices = new HashSet<AclLinkSpec>();

    /**
     * Bluetooth HFP v1.8 specifies the Battery Charge indicator of AG can take values from {@code
     * 0} to {@code 5}, but it does not specify how to map the values back to percentages. The
     * following mapping is used: - Level 0: 0% - Level 1: midpoint of 1-25% - Level 2: midpoint of
     * 26-50% - Level 3: midpoint of 51-75% - Level 4: midpoint of 76-99% - Level 5: 100%
     */
    private static final int HFP_BATTERY_CHARGE_INDICATOR_0 = 0;

    private static final int HFP_BATTERY_CHARGE_INDICATOR_1 = 13;
    private static final int HFP_BATTERY_CHARGE_INDICATOR_2 = 38;
    private static final int HFP_BATTERY_CHARGE_INDICATOR_3 = 63;
    private static final int HFP_BATTERY_CHARGE_INDICATOR_4 = 88;
    private static final int HFP_BATTERY_CHARGE_INDICATOR_5 = 100;

    @VisibleForTesting
    static final String ACL_CONNECTION_DELIVERY_GROUP_POLICY = "bluetooth.ACL_CONNECTION";

    private final Handler mHandler;

    private class RemoteDevicesHandler extends Handler {

        /**
         * Handler must be created from an explicit looper to avoid threading ambiguity
         *
         * @param looper The looper that this handler should be executed on
         */
        RemoteDevicesHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MESSAGE_NOTIFY_UUIDS -> {
                    BluetoothDevice device = (BluetoothDevice) msg.obj;
                    if (device == null) {
                        warnLog("MESSAGE_NOTIFY_UUIDS: device is null");
                        return;
                    }

                    debugLog("MESSAGE_NOTIFY_UUIDS: " + device);
                    if (Flags.broadcastUuidsFromMainLooper()) {
                        notifyUuids(getDeviceProperties(device), true);
                    } else {
                        DeviceProperties prop = getDeviceProperties(device);
                        sendUuidIntent(device, prop, true);
                    }
                }
                case MESSAGE_SERVICE_DISCOVERY_TIMEOUT -> {
                    BluetoothDevice device = (BluetoothDevice) msg.obj;
                    if (device == null) {
                        warnLog("MESSAGE_SERVICE_DISCOVERY_TIMEOUT: device is null");
                        MetricsLogger.getInstance()
                                .cacheCount(BluetoothProtoEnums.SDP_NOT_SENDING_DELAYED_UUID, 1);
                        return;
                    }

                    debugLog("MESSAGE_SERVICE_DISCOVERY_TIMEOUT: " + device);
                    if (Flags.broadcastUuidsFromMainLooper()) {
                        notifyUuids(getDeviceProperties(device), false);
                    } else {
                        DeviceProperties prop = getDeviceProperties(device);
                        sendUuidIntent(device, prop, false);
                    }
                }
                default -> {} // Nothing to do
            }
        }
    }

    RemoteDevices(AdapterService service, Looper looper) {
        mAdapterService = service;
        if (Flags.removeAdapterDependency()) {
            mAdapter = null;
        } else {
            mAdapter = mAdapterService.getSystemService(BluetoothManager.class).getAdapter();
        }
        mHandler = new RemoteDevicesHandler(looper);
        mWatchConnectionStateListener = new WatchConnectionStateListener(mAdapterService, looper);
    }

    /**
     * Reset should be called when the state of this object needs to be cleared RemoteDevices is
     * still usable after reset
     */
    void reset() {
        // Unregister Handler and stop all queued messages.
        mHandler.removeCallbacksAndMessages(null);

        synchronized (mDevices) {
            debugLog("reset(): Broadcasting ACL_DISCONNECTED");

            mDevices.forEach(
                    (address, deviceProperties) -> {
                        BluetoothDevice device = deviceProperties.getDevice();
                        var connected =
                                mAdapterService.getConnectionState(device)
                                        != BluetoothDevice.CONNECTION_STATE_DISCONNECTED;
                        debugLog(
                                ("reset(): address=" + toAnonymizedAddress(address))
                                        + (", connected=" + connected));
                        if (connected) {
                            Intent intent = new Intent(BluetoothDevice.ACTION_ACL_DISCONNECTED);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                            intent.addFlags(
                                    Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                                            | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);

                            if (deviceProperties.getConnectionHandle(TRANSPORT_BREDR)
                                    != BluetoothDevice.ERROR) {
                                deviceProperties.setDisconnected(TRANSPORT_BREDR);
                                mAdapterService.notifyAclDisconnected(device, TRANSPORT_BREDR);
                                intent.putExtra(BluetoothDevice.EXTRA_TRANSPORT, TRANSPORT_BREDR);
                                mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT);
                            }
                            if (deviceProperties.getConnectionHandle(TRANSPORT_LE)
                                    != BluetoothDevice.ERROR) {
                                deviceProperties.setDisconnected(TRANSPORT_LE);
                                mAdapterService.notifyAclDisconnected(device, TRANSPORT_LE);
                                intent.putExtra(BluetoothDevice.EXTRA_TRANSPORT, TRANSPORT_LE);
                                mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT);
                            }
                        }
                    });
            mDevices.clear();
        }

        mAddressMap.clear();
        mConnectedDevices.clear();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    DeviceProperties getDeviceProperties(BluetoothDevice device) {
        if (device == null) {
            return null;
        }

        synchronized (mDevices) {
            String address = mAddressMap.get(device.getAddress());
            // If the device is not in the dual map, use its original address
            if (address == null || mDevices.get(address) == null) {
                address = device.getAddress();
            }
            return mDevices.get(address);
        }
    }

    Set<AclLinkSpec> getConnectedDevices() {
        return Collections.unmodifiableSet(mConnectedDevices);
    }

    int getBondState(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.BOND_NONE;
        }
        return deviceProp.getBondState();
    }

    public String getName(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }
        return deviceProp.getName();
    }

    /**
     * Gets the alias of a remote device from the internal cache.
     *
     * @param device the remote {@link BluetoothDevice}
     * @return the alias of the device, or {@code null} if no alias is set or the device is not
     *     found
     */
    public String getAlias(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }
        return deviceProp.getAlias();
    }

    int getType(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return BluetoothDevice.DEVICE_TYPE_UNKNOWN;
        }
        return deviceProp.getDeviceType();
    }

    public ParcelUuid[] getUuids(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return null;
        }
        return deviceProp.getUuids();
    }

    public int getBluetoothClass(BluetoothDevice device) {
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            return 0;
        }
        return deviceProp.getBluetoothClass();
    }

    BluetoothDevice getDevice(String address) {
        if (address == null) {
            return null;
        }
        String deviceAddress = mAddressMap.get(address);
        // If the device is not in the dual map, use its original address
        if (deviceAddress == null || mDevices.get(deviceAddress) == null) {
            deviceAddress = address;
        }

        DeviceProperties prop = mDevices.get(deviceAddress);
        if (prop != null) {
            return prop.getDevice();
        }
        return null;
    }

    BluetoothDevice getDevice(byte[] address) {
        String addressString = Utils.getAddressStringFromByte(address);
        return getDevice(addressString);
    }

    DeviceProperties addDeviceProperties(byte[] address, int addressType) {
        synchronized (mDevices) {
            String key = Utils.getAddressStringFromByte(address);
            if (mDevices.containsKey(key)) {
                debugLog(
                        ("Properties for device=" + toAnonymizedAddress(key))
                                + ("["
                                        + Util.addressTypeToString(addressType)
                                        + "] are already added"));
                return mDevices.get(key);
            }

            DeviceProperties prop = new DeviceProperties();
            if (Flags.removeAdapterDependency()) {
                if (!Flags.retainAddressType()) {
                    addressType = BluetoothDevice.ADDRESS_TYPE_PUBLIC;
                }
                prop.setDevice(new BluetoothDevice(null, key, addressType));
            } else {
                BluetoothDevice device =
                        Flags.retainAddressType()
                                ? mAdapter.getRemoteLeDevice(key, addressType)
                                : mAdapter.getRemoteDevice(key);
                prop.setDevice(device);
            }

            // Make space for the new device if the cache is full
            if (mDevices.size() >= MAX_DEVICE_QUEUE_SIZE) {
                String lruAddress = findLruAddress();
                if (lruAddress != null) {
                    mDevices.remove(lruAddress);
                    debugLog("Ejected " + (toAnonymizedAddress(lruAddress) + " from property map"));
                } else {
                    errorLog("No non-bonded device to eject");
                }
            }

            mDevices.put(key, prop);
            return prop;
        }
    }

    private String findLruAddress() {
        String evictionCandidate = null;

        for (Map.Entry<String, DeviceProperties> entry : mDevices.entrySet()) {
            String address = entry.getKey();
            DeviceProperties prop = entry.getValue();

            // Ignore the bonded or bonding devices
            if (prop.getBondState() != BluetoothDevice.BOND_NONE) {
                continue;
            }

            // Ignore the connected devices
            if (prop.getConnectionHandle(TRANSPORT_BREDR) != BluetoothDevice.ERROR
                    || prop.getConnectionHandle(TRANSPORT_LE) != BluetoothDevice.ERROR) {
                continue;
            }

            if (prop.getPackages().length != 0) {
                // Some apps are interested, use it as the eviction candidate of last resort
                if (evictionCandidate == null) {
                    evictionCandidate = address;
                }
                continue;
            }

            // Not bonded, not connected, and not in use by any apps, so it's eligible for eviction
            return address;
        }

        return evictionCandidate;
    }

    DeviceProperties addDeviceProperties(byte[] address) {
        return addDeviceProperties(address, BluetoothDevice.ADDRESS_TYPE_PUBLIC);
    }

    class DeviceProperties {
        private static final int MAX_PACKAGE_NAMES = 4;
        private static final int BONDING_INITIATOR_NONE = 0;
        private static final int BONDING_INITIATOR_LOCAL = 1;
        private static final int BONDING_INITIATOR_REMOTE = 2;
        public static final BluetoothAddress UNKNOWN_ADDRESS =
                new BluetoothAddress(null, BluetoothDevice.ADDRESS_TYPE_UNKNOWN);
        private String mName;
        private BluetoothAddress mIdentityAddress = UNKNOWN_ADDRESS;
        private boolean mIsConsolidated = false;
        private int mBluetoothClass = BluetoothClass.Device.Major.UNCATEGORIZED;
        private short mRssi;
        private String mAlias;
        private BluetoothDevice mDevice;
        private int mBondingInitiator;
        private int mBatteryLevelFromHfp = BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        private int mBatteryLevelFromBatteryService = BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        // This is the cached battery level to handle temporary disconnection from BAS.
        private int mLastBatteryLevelFromBatteryService = BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        private boolean mIsCoordinatedSetMember;
        private int mAshaCapability;
        private int mAshaTruncatedHiSyncId;
        private String mModelName;
        private int mOnHeadDetectionEnabledState =
                BluetoothDevice.ON_HEAD_DETECTION_ENABLED_STATE_UNKNOWN;
        private int mOnHeadDetectionState = BluetoothDevice.ON_HEAD_DETECTION_STATE_UNKNOWN;
        @VisibleForTesting int mBondState;
        @VisibleForTesting int mDeviceType;
        @VisibleForTesting ParcelUuid[] mUuidsBrEdr;
        @VisibleForTesting ParcelUuid[] mUuidsLe;
        @VisibleForTesting ParcelUuid[] mUuidsFromExtendedInquiryResponse;
        @VisibleForTesting ParcelUuid[] mUuidsFromLeAdvertisingData;
        @VisibleForTesting int mDiscoveryResultType = BluetoothDevice.DEVICE_TYPE_UNKNOWN;
        @VisibleForTesting boolean mHfpBatteryIndicator = false;
        private BluetoothSinkAudioPolicy mAudioPolicy;
        private Optional<Integer> mLastBondLossReason = Optional.empty();

        // Stores the PairingInitiator (from AbstractionLayer) of the last BOND_BONDED state change.
        private Optional<Integer> mLastBondedInitiator = Optional.empty();

        private BondStatus mBredrBond;
        private BondStatus mLeBond;

        static class LinkState {
            private final int mConnectionHandle;
            private EncryptionStatus mEncryptionStatus;

            public LinkState(int handle) {
                mConnectionHandle = handle;
                mEncryptionStatus = null;
            }

            public int getConnectionHandle() {
                return mConnectionHandle;
            }

            public void setEncryptionStatus(EncryptionStatus encryptionStatus) {
                mEncryptionStatus = encryptionStatus;
            }

            public EncryptionStatus getEncryptionStatus() {
                return mEncryptionStatus;
            }
        }

        private LinkState mBredrLink;
        private LinkState mLeLink;

        // LRU cache of package names associated to this device
        private final Set<String> mPackages =
                Collections.newSetFromMap(
                        new LinkedHashMap<>() {
                            // This is called on every add. Returning true removes the eldest entry.
                            protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                                return size() >= MAX_PACKAGE_NAMES;
                            }
                        });

        DeviceProperties() {
            mBondState = BluetoothDevice.BOND_NONE;
        }

        /**
         * @return the mName
         */
        String getName() {
            synchronized (mObject) {
                return mName;
            }
        }

        /**
         * @param name the mName to set
         */
        void setName(String name) {
            synchronized (mObject) {
                this.mName = name;
            }
        }

        /**
         * @return the mIdentityAddress
         */
        @NonNull
        BluetoothAddress getIdentityAddress() {
            synchronized (mObject) {
                return mIdentityAddress;
            }
        }

        /**
         * @param identityAddress the mIdentityAddress to set
         */
        void setIdentityAddress(String identityAddress, @AddressType int identityAddressType) {
            synchronized (mObject) {
                this.mIdentityAddress = new BluetoothAddress(identityAddress, identityAddressType);
            }
        }

        /**
         * @return mIsConsolidated
         */
        boolean isConsolidated() {
            synchronized (mObject) {
                return mIsConsolidated;
            }
        }

        /**
         * @param isConsolidated the mIsConsolidated to set
         */
        void setIsConsolidated(boolean isConsolidated) {
            synchronized (mObject) {
                this.mIsConsolidated = isConsolidated;
            }
        }

        /**
         * @return the mClass
         */
        int getBluetoothClass() {
            synchronized (mObject) {
                return mBluetoothClass;
            }
        }

        /**
         * @param bluetoothClass the mBluetoothClass to set
         */
        void setBluetoothClass(int bluetoothClass) {
            synchronized (mObject) {
                this.mBluetoothClass = bluetoothClass;
            }
        }

        /**
         * @param transport the transport on which the connection exists
         * @return the mConnectionHandle
         */
        int getConnectionHandle(int transport) {
            synchronized (mObject) {
                if (transport == TRANSPORT_AUTO) {
                    return BluetoothDevice.ERROR;
                }
                LinkState linkState = (transport == TRANSPORT_BREDR) ? mBredrLink : mLeLink;
                if (linkState == null) {
                    return BluetoothDevice.ERROR;
                }
                return linkState.getConnectionHandle();
            }
        }

        /**
         * Initializes the LinkState object for the given transport with connectionHandle. The
         * non-null LinkState object for the given transport indicates that the device is now
         * connected.
         *
         * @param connectionHandle the connectionHandle to set
         * @param transport the transport on which to set the handle
         */
        void setConnected(int transport, int connectionHandle) {
            synchronized (mObject) {
                switch (transport) {
                    case TRANSPORT_BREDR -> mBredrLink = new LinkState(connectionHandle);
                    case TRANSPORT_LE -> mLeLink = new LinkState(connectionHandle);
                    default -> errorLog("setConnected(): unexpected transport value " + transport);
                }
            }
        }

        /**
         * Sets the link state to disconnected for the given transport. The respective transport
         * based LinkState object is set to null.
         *
         * @param transport the transport on which the connection exists
         */
        void setDisconnected(int transport) {
            synchronized (mObject) {
                switch (transport) {
                    case TRANSPORT_BREDR -> mBredrLink = null;
                    case TRANSPORT_LE -> mLeLink = null;
                    default ->
                            errorLog("setDisconnected(): unexpected transport value " + transport);
                }
            }
        }

        void setBondStatus(int transport, int pairingAlgorithm, int pairingVariant) {
            synchronized (mObject) {
                switch (transport) {
                    case TRANSPORT_BREDR ->
                            mBredrBond = new BondStatus(pairingAlgorithm, pairingVariant);
                    case TRANSPORT_LE -> mLeBond = new BondStatus(pairingAlgorithm, pairingVariant);
                    default -> errorLog("setBondStatus(): unexpected transport value " + transport);
                }
            }
        }

        BondStatus getBondStatus(int transport) {
            synchronized (mObject) {
                return switch (transport) {
                    case TRANSPORT_BREDR -> mBredrBond;
                    case TRANSPORT_LE -> mLeBond;
                    default -> {
                        errorLog("getBondStatus(): unexpected transport value " + transport);
                        yield null;
                    }
                };
            }
        }

        /**
         * @param transport the transport on which the connection exists
         * @param keySize the encryption key size
         * @param algorithm the encryption algorithm (E0/AES)
         */
        void setEncryptionStatus(int transport, int keySize, int algorithm) {
            synchronized (mObject) {
                if (transport == TRANSPORT_AUTO) {
                    errorLog("setEncryptionStatus(): unexpected transport value " + transport);
                    return;
                }
                LinkState linkState = getLinkState(transport);
                if (linkState == null) {
                    errorLog("setEncryptionStatus(): the device is not connected");
                    return;
                }
                if (keySize > 0 && algorithm > 0) {
                    linkState.setEncryptionStatus(new EncryptionStatus(keySize, algorithm));
                } else {
                    linkState.setEncryptionStatus(null);
                }
            }
        }

        /**
         * @param transport the transport on which the connection exists
         * @return the current {@link LinkState} object for the given transport, or null if the
         *     device is not connected.
         */
        LinkState getLinkState(int transport) {
            synchronized (mObject) {
                LinkState linkState = null;
                switch (transport) {
                    case TRANSPORT_BREDR -> linkState = mBredrLink;
                    case TRANSPORT_LE -> linkState = mLeLink;
                    default -> errorLog("getLinkState(): unexpected transport value " + transport);
                }
                return linkState;
            }
        }

        EncryptionStatus getEncryptionStatus(int transport) {
            synchronized (mObject) {
                LinkState linkState = getLinkState(transport);
                return (linkState == null) ? null : linkState.getEncryptionStatus();
            }
        }

        /**
         * @return the UUIDs on LE and Classic transport
         */
        ParcelUuid[] getUuids() {
            synchronized (mObject) {
                /* When we bond dual mode device, and discover LE and Classic services, stack would
                 * return LE and Classic UUIDs separately, but Java apps expect them merged.
                 */
                int combinedUuidsLength =
                        (mUuidsBrEdr != null ? mUuidsBrEdr.length : 0)
                                + (mUuidsLe != null ? mUuidsLe.length : 0);
                if (combinedUuidsLength == 0) {
                    return mUuidsBrEdr;
                }

                LinkedHashSet<ParcelUuid> result = new LinkedHashSet<>();
                if (mUuidsBrEdr != null) {
                    for (ParcelUuid uuid : mUuidsBrEdr) {
                        result.add(uuid);
                    }
                }

                if (mUuidsLe != null) {
                    for (ParcelUuid uuid : mUuidsLe) {
                        result.add(uuid);
                    }
                }

                return result.toArray(new ParcelUuid[result.size()]);
            }
        }

        /**
         * @return just classic transport UUIDS
         */
        ParcelUuid[] getUuidsBrEdr() {
            synchronized (mObject) {
                return mUuidsBrEdr;
            }
        }

        /**
         * @param uuids the mUuidsBrEdr to set
         */
        void setUuidsBrEdr(ParcelUuid[] uuids) {
            synchronized (mObject) {
                this.mUuidsBrEdr = uuids;
            }
        }

        /**
         * @return the mUuidsLe
         */
        ParcelUuid[] getUuidsLe() {
            synchronized (mObject) {
                return mUuidsLe;
            }
        }

        /**
         * @param uuids the mUuidsLe to set
         */
        void setUuidsLe(ParcelUuid[] uuids) {
            synchronized (mObject) {
                this.mUuidsLe = uuids;
            }
        }

        void setUuidsFromExtendedInquiryResponse(ParcelUuid[] uuids) {
            synchronized (mObject) {
                this.mUuidsFromExtendedInquiryResponse = uuids;
            }
        }

        ParcelUuid[] getUuidsFromExtendedInquiryResponse() {
            synchronized (mObject) {
                return mUuidsFromExtendedInquiryResponse;
            }
        }

        void setUuidsFromLeAdvertisingData(ParcelUuid[] uuids) {
            synchronized (mObject) {
                this.mUuidsFromLeAdvertisingData = uuids;
            }
        }

        ParcelUuid[] getUuidsFromLeAdvertisingData() {
            synchronized (mObject) {
                return mUuidsFromLeAdvertisingData;
            }
        }

        void setDiscoveryResultType(int discoveryResultType) {
            synchronized (mObject) {
                this.mDiscoveryResultType = discoveryResultType;
            }
        }

        int getDiscoveryResultType() {
            synchronized (mObject) {
                return mDiscoveryResultType;
            }
        }

        /**
         * @return the mDevice
         */
        BluetoothDevice getDevice() {
            synchronized (mObject) {
                return mDevice;
            }
        }

        /**
         * @param device the mDevice to set
         */
        void setDevice(BluetoothDevice device) {
            synchronized (mObject) {
                this.mDevice = device;
            }
        }

        /**
         * @return mRssi
         */
        short getRssi() {
            synchronized (mObject) {
                return mRssi;
            }
        }

        /**
         * @param rssi the mRssi to set
         */
        void setRssi(short rssi) {
            synchronized (mObject) {
                this.mRssi = rssi;
            }
        }

        /**
         * @return mDeviceType
         */
        int getDeviceType() {
            synchronized (mObject) {
                return mDeviceType;
            }
        }

        /**
         * @param deviceType the mDeviceType to set
         */
        @VisibleForTesting
        void setDeviceType(int deviceType) {
            synchronized (mObject) {
                this.mDeviceType = deviceType;
            }
        }

        /**
         * @return the mAlias
         */
        String getAlias() {
            synchronized (mObject) {
                return mAlias;
            }
        }

        /**
         * @param mAlias the mAlias to set
         */
        void setAlias(BluetoothDevice device, String mAlias) {
            synchronized (mObject) {
                this.mAlias = mAlias;
                mAdapterService
                        .getNative()
                        .setDeviceProperty(
                                Util.getByteAddress(device),
                                AbstractionLayer.BT_PROPERTY_REMOTE_FRIENDLY_NAME,
                                mAlias.getBytes());
                Intent intent = new Intent(BluetoothDevice.ACTION_ALIAS_CHANGED);
                intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
                intent.putExtra(BluetoothDevice.EXTRA_NAME, mAlias);
                mAdapterService.sendBroadcast(
                        intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
            }
        }

        /**
         * @param newBondState the mBondState to set
         */
        void setBondState(int newBondState) {
            synchronized (mObject) {
                this.mBondState = newBondState;
                if (newBondState == BluetoothDevice.BOND_NONE) {
                    /* Clearing the Uuids local copy when the device is unpaired. If not cleared,
                    cachedBluetoothDevice issued a connect using the local cached copy of uuids,
                    without waiting for the ACTION_UUID intent.
                    This was resulting in multiple calls to connect().*/
                    mUuidsBrEdr = null;
                    mUuidsLe = null;
                    mAlias = null;
                } else if (newBondState == BluetoothDevice.BOND_BONDED) {
                    if (getBondingInitiator() == BONDING_INITIATOR_NONE) {
                        // Device bonded but not initiated locally. This may happen if remote device
                        // initiated bonded or bonded device was loaded on BT restart.
                        setBondingInitiatedLocally(false);
                    }

                    // Identity address of the bonded device may not be provided by the native
                    // stack if it is same as the pseudo address.
                    if (mIdentityAddress == UNKNOWN_ADDRESS) {
                        mIdentityAddress =
                                new BluetoothAddress(
                                        mDevice.getAddress(), mDevice.getAddressType());
                    }
                }
            }
        }

        /**
         * @return the mBondState
         */
        int getBondState() {
            synchronized (mObject) {
                return mBondState;
            }
        }

        boolean isBonding() {
            return getBondState() == BluetoothDevice.BOND_BONDING;
        }

        boolean isBondingOrBonded() {
            return isBonding() || getBondState() == BluetoothDevice.BOND_BONDED;
        }

        /**
         * @param isBondingInitiatedLocally whether bonding is initiated locally
         */
        void setBondingInitiatedLocally(boolean isBondingInitiatedLocally) {
            synchronized (mObject) {
                if (isBondingInitiatedLocally) {
                    this.mBondingInitiator = BONDING_INITIATOR_LOCAL;
                } else {
                    this.mBondingInitiator = BONDING_INITIATOR_REMOTE;
                }
            }
        }

        /**
         * @return the mBondingInitiator
         */
        int getBondingInitiator() {
            synchronized (mObject) {
                return mBondingInitiator;
            }
        }

        /**
         * @return whether the current bonding attempt is initiated locally
         */
        boolean isBondingInitiatedLocally() {
            synchronized (mObject) {
                return mBondingInitiator == BONDING_INITIATOR_LOCAL;
            }
        }

        /**
         * @return mBatteryLevel
         */
        int getBatteryLevel() {
            synchronized (mObject) {
                if (mBatteryLevelFromBatteryService != BATTERY_LEVEL_UNKNOWN) {
                    return mBatteryLevelFromBatteryService;
                }
                // Returns one from BAS to prevent battery level fluctuation.
                if (mLastBatteryLevelFromBatteryService != BATTERY_LEVEL_UNKNOWN) {
                    return mLastBatteryLevelFromBatteryService;
                }

                return mBatteryLevelFromHfp;
            }
        }

        /**
         * @param hfpBatteryIndicator is set to true based on the HF battery indicator support
         *     received from AT+BIND command and set to false in disconnect path.
         */
        void setHfpBatteryIndicatorStatus(boolean hfpBatteryIndicator) {
            this.mHfpBatteryIndicator = hfpBatteryIndicator;
        }

        /**
         * @return mHfpBatteryIndicator
         */
        boolean isHfpBatteryIndicatorEnabled() {
            return mHfpBatteryIndicator;
        }

        void setBatteryLevelFromHfp(int batteryLevel) {
            synchronized (mObject) {
                if (mBatteryLevelFromHfp == batteryLevel) {
                    return;
                }
                mBatteryLevelFromHfp = batteryLevel;
                // The battery level from HFP is changed, now HFP value is reliable.
                if (mBatteryLevelFromBatteryService == BATTERY_LEVEL_UNKNOWN) {
                    mLastBatteryLevelFromBatteryService = BATTERY_LEVEL_UNKNOWN;
                }
            }
        }

        void setBatteryLevelFromBatteryService(int batteryLevel) {
            synchronized (mObject) {
                // Preserve the last battery level to prevent
                // battery level fluctuation between BAS and HFP.
                // We can safely reset it if there is no HFP.
                if (batteryLevel != BATTERY_LEVEL_UNKNOWN
                        || mBatteryLevelFromHfp == BATTERY_LEVEL_UNKNOWN) {
                    mLastBatteryLevelFromBatteryService = batteryLevel;
                }
                mBatteryLevelFromBatteryService = batteryLevel;
            }
        }

        /**
         * @return the mIsCoordinatedSetMember
         */
        boolean isCoordinatedSetMember() {
            synchronized (mObject) {
                return mIsCoordinatedSetMember;
            }
        }

        /**
         * @param isCoordinatedSetMember the mIsCoordinatedSetMember to set
         */
        void setIsCoordinatedSetMember(boolean isCoordinatedSetMember) {
            if (!Config.isProfileSupported(BluetoothProfile.CSIP_SET_COORDINATOR)) {
                debugLog("CSIP is not supported");
                return;
            }
            synchronized (mObject) {
                this.mIsCoordinatedSetMember = isCoordinatedSetMember;
            }
        }

        /**
         * @return the mAshaCapability
         */
        int getAshaCapability() {
            synchronized (mObject) {
                return mAshaCapability;
            }
        }

        void setAshaCapability(int ashaCapability) {
            synchronized (mObject) {
                this.mAshaCapability = ashaCapability;
            }
        }

        /**
         * @return the mAshaTruncatedHiSyncId
         */
        int getAshaTruncatedHiSyncId() {
            synchronized (mObject) {
                return mAshaTruncatedHiSyncId;
            }
        }

        void setAshaTruncatedHiSyncId(int ashaTruncatedHiSyncId) {
            synchronized (mObject) {
                this.mAshaTruncatedHiSyncId = ashaTruncatedHiSyncId;
            }
        }

        public void setHfAudioPolicyForRemoteAg(BluetoothSinkAudioPolicy policies) {
            mAudioPolicy = policies;
        }

        public BluetoothSinkAudioPolicy getHfAudioPolicyForRemoteAg() {
            return mAudioPolicy;
        }

        public void setModelName(String modelName) {
            mModelName = modelName;
            mAdapterService.setMetadata(
                    this.mDevice,
                    BluetoothDevice.METADATA_MODEL_NAME,
                    mModelName.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * @return the mModelName
         */
        String getModelName() {
            synchronized (mObject) {
                return mModelName;
            }
        }

        public void setOnHeadDetectionEnabledState(int enabledState) {
            synchronized (mObject) {
                this.mOnHeadDetectionEnabledState = enabledState;
            }
        }

        /**
         * @return the mOnHeadDetectionEnabledState
         */
        int getOnHeadDetectionEnabledState() {
            synchronized (mObject) {
                return mOnHeadDetectionEnabledState;
            }
        }

        public void setOnHeadDetectionState(int state) {
            synchronized (mObject) {
                this.mOnHeadDetectionState = state;
            }
        }

        /**
         * @return the mOnHeadDetectionState
         */
        int getOnHeadDetectionState() {
            synchronized (mObject) {
                return mOnHeadDetectionState;
            }
        }

        @NonNull
        public String[] getPackages() {
            synchronized (mObject) {
                return mPackages.toArray(new String[0]);
            }
        }

        public void addPackage(String packageName) {
            synchronized (mObject) {
                // Removing the package ensures that the LRU cache order is updated. Adding it back
                // will make it the newest.
                mPackages.remove(packageName);
                mPackages.add(packageName);
            }
        }

        public void setLastBondLossReason(Optional<Integer> bondLossReason) {
            synchronized (mObject) {
                this.mLastBondLossReason = bondLossReason;
            }
        }

        public Optional<Integer> getLastBondLossReason() {
            synchronized (mObject) {
                return mLastBondLossReason;
            }
        }

        public void setLastBondedInitiator(Optional<Integer> lastBondedInitiator) {
            synchronized (mObject) {
                this.mLastBondedInitiator = lastBondedInitiator;
            }
        }

        public Optional<Integer> getLastBondedInitiator() {
            synchronized (mObject) {
                return mLastBondedInitiator;
            }
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            synchronized (mObject) {
                String address = mDevice.getAddress();
                String identityAddress = mIdentityAddress.getAddress();
                String anonAddress = toAnonymizedAddress(address);
                String anonIdentityAddress =
                        identityAddress != null
                                ? toAnonymizedAddress(identityAddress)
                                : "XX:XX:XX:XX:XX:XX";
                int identityAddressType = mIdentityAddress.getAddressType();

                boolean connectedBrEdr = mBredrLink != null;
                boolean connectedLe = mLeLink != null;

                sb.append("    ")
                        .append(anonAddress)
                        .append("(")
                        .append(Util.addressTypeToString(mDevice.getAddressType()))
                        .append(")")
                        .append(" => ")
                        .append(anonIdentityAddress)
                        .append("(")
                        .append(Util.addressTypeToString(identityAddressType))
                        .append(")")
                        .append(" [")
                        .append(Util.deviceTypeToString(mDeviceType))
                        .append("] [0x")
                        .append(String.format("%06X", mBluetoothClass))
                        .append("] [Pairing Algorithm BR/EDR: ")
                        .append(mBredrBond != null ? mBredrBond.getPairingAlgorithm() : "N/A")
                        .append(" LE: ")
                        .append(mLeBond != null ? mLeBond.getPairingAlgorithm() : "N/A")
                        .append("] [ACL BR/EDR:")
                        .append(connectedBrEdr ? "Y" : "N")
                        .append(" LE:")
                        .append(connectedLe ? "Y" : "N")
                        .append("] [ Encryption status(BR/EDR): ")
                        .append(connectedBrEdr ? mBredrLink.getEncryptionStatus() : "N/A")
                        .append(" LE: ")
                        .append(connectedLe ? mLeLink.getEncryptionStatus() : "N/A")
                        .append("] ")
                        .append(mName);

                if (Utils.isAutonomousRepairingSupported() && mLastBondLossReason.isPresent()) {
                    sb.append("[Latest bond-loss reason: ")
                            .append(mLastBondLossReason.get())
                            .append("]");
                }
                sb.append("\n");

                if (mUuidsBrEdr != null) {
                    sb.append("        [BR/EDR UUIDs]: ")
                            .append(
                                    Arrays.stream(mUuidsBrEdr)
                                            .map(ParcelUuid::toString)
                                            .collect(Collectors.joining(" ")))
                            .append("\n");
                }

                if (mUuidsLe != null) {
                    sb.append("        [LE UUIDs    ]: ")
                            .append(
                                    Arrays.stream(mUuidsLe)
                                            .map(ParcelUuid::toString)
                                            .collect(Collectors.joining(" ")))
                            .append("\n");
                }

                if (!mPackages.isEmpty()) {
                    sb.append("        [Packages    ]: ")
                            .append(Arrays.toString(mPackages.toArray()))
                            .append("\n");
                }
            }
            return sb.toString();
        }
    }

    // TODO (b/462533972): Remove once the flag broadcast_uuids_from_main_looper is shipped.
    private void sendUuidIntent(BluetoothDevice device, DeviceProperties prop, boolean success) {
        // Send uuids within the stack before the broadcast is sent out
        ParcelUuid[] uuids = prop == null ? null : prop.getUuids();

        if (success) {
            mAdapterService.sendUuidsInternal(device, uuids);
        }

        Intent intent = new Intent(BluetoothDevice.ACTION_UUID);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothDevice.EXTRA_UUID, uuids);
        mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());

        // SDP Sent UUID Intent here
        MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_SENT_UUID, 1);

        // Remove the outstanding UUID request
        // Handler.removeMessages() compares the object pointer so we cannot use the device
        // directly. So we have to extract original BluetoothDevice object from DeviceProperties.
        mHandler.removeMessages(
                MESSAGE_SERVICE_DISCOVERY_TIMEOUT, prop == null ? device : prop.getDevice());
    }

    /**
     * When bonding is initiated to remote device that we have never seen, i.e Out Of Band pairing,
     * we must add device first before setting it's properties. This is a helper method for doing
     * that.
     */
    void setBondingInitiatedLocally(BluetoothDevice device) {
        DeviceProperties properties = getDeviceProperties(device);

        if (properties == null) {
            properties = addDeviceProperties(Util.getByteAddress(device), device.getAddressType());
        }

        properties.setBondingInitiatedLocally(true);
    }

    void updateBatteryLevel(BluetoothDevice device, int batteryLevel, boolean isBas) {
        if (device == null || batteryLevel < 0 || batteryLevel > 100) {
            warnLog(
                    "Invalid parameters device="
                            + String.valueOf(device == null)
                            + ", batteryLevel="
                            + String.valueOf(batteryLevel));
            return;
        }
        DeviceProperties deviceProperties = getDeviceProperties(device);
        if (deviceProperties == null) {
            deviceProperties =
                    addDeviceProperties(Util.getByteAddress(device), device.getAddressType());
        }
        int prevBatteryLevel = deviceProperties.getBatteryLevel();
        if (isBas) {
            deviceProperties.setBatteryLevelFromBatteryService(batteryLevel);
        } else {
            deviceProperties.setBatteryLevelFromHfp(batteryLevel);
        }
        int newBatteryLevel = deviceProperties.getBatteryLevel();
        if (prevBatteryLevel == newBatteryLevel) {
            debugLog(
                    "Same battery level for device "
                            + device
                            + " received "
                            + String.valueOf(batteryLevel)
                            + "%");
            return;
        }
        sendBatteryLevelChangedBroadcast(device, newBatteryLevel);
        Log.d(TAG, "Updated device " + device + " battery level to " + newBatteryLevel + "%");
    }

    void resetBatteryLevel(BluetoothDevice device, boolean isBas) {
        if (device == null) {
            warnLog("Device is null");
            return;
        }
        DeviceProperties deviceProperties = getDeviceProperties(device);
        if (deviceProperties == null) {
            return;
        }
        int prevBatteryLevel = deviceProperties.getBatteryLevel();
        if (isBas) {
            deviceProperties.setBatteryLevelFromBatteryService(
                    BluetoothDevice.BATTERY_LEVEL_UNKNOWN);
        } else {
            deviceProperties.setBatteryLevelFromHfp(BluetoothDevice.BATTERY_LEVEL_UNKNOWN);
        }

        if (Flags.enableBatteryLevelUpdateOnlyThroughHfIndicator()) {
            deviceProperties.setHfpBatteryIndicatorStatus(false);
        }
        int newBatteryLevel = deviceProperties.getBatteryLevel();
        if (prevBatteryLevel == newBatteryLevel) {
            debugLog("Battery level was not changed due to reset, device=" + device);
            return;
        }
        sendBatteryLevelChangedBroadcast(device, newBatteryLevel);
        Log.d(TAG, "Updated device " + device + " battery level to " + newBatteryLevel + "%");
    }

    private void sendBatteryLevelChangedBroadcast(BluetoothDevice device, int batteryLevel) {
        Intent intent = new Intent(BluetoothDevice.ACTION_BATTERY_LEVEL_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothDevice.EXTRA_BATTERY_LEVEL, batteryLevel);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
    }

    /**
     * Converts HFP's Battery Charge indicator values of {@code 0 -- 5} to an integer percentage.
     */
    @VisibleForTesting
    static int batteryChargeIndicatorToPercentage(int indicator) {
        int percent =
                switch (indicator) {
                    case 5 -> HFP_BATTERY_CHARGE_INDICATOR_5;
                    case 4 -> HFP_BATTERY_CHARGE_INDICATOR_4;
                    case 3 -> HFP_BATTERY_CHARGE_INDICATOR_3;
                    case 2 -> HFP_BATTERY_CHARGE_INDICATOR_2;
                    case 1 -> HFP_BATTERY_CHARGE_INDICATOR_1;
                    case 0 -> HFP_BATTERY_CHARGE_INDICATOR_0;
                    default -> BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
                };
        Log.d(TAG, "Battery charge indicator: " + indicator + "; converted to: " + percent + "%");
        return percent;
    }

    private static boolean areUuidsEqual(ParcelUuid[] uuids1, ParcelUuid[] uuids2) {
        final int length1 = uuids1 == null ? 0 : uuids1.length;
        final int length2 = uuids2 == null ? 0 : uuids2.length;
        if (length1 != length2) {
            return false;
        }
        Set<ParcelUuid> set = new HashSet<>();
        for (int i = 0; i < length1; ++i) {
            set.add(uuids1[i]);
        }
        for (int i = 0; i < length2; ++i) {
            set.remove(uuids2[i]);
        }
        return set.isEmpty();
    }

    void devicePropertyChangedCallback(
            byte[] address, int addressType, int[] types, byte[][] values) {
        Intent intent;
        byte[] val;
        int type;
        BluetoothDevice bdDevice = getDevice(address);
        DeviceProperties deviceProperties;
        if (bdDevice == null) {
            deviceProperties = addDeviceProperties(address, addressType);
            bdDevice = deviceProperties.getDevice();
            debugLog("Added new device property, device=" + bdDevice);
        } else {
            deviceProperties = getDeviceProperties(bdDevice);
            if (bdDevice.getAddressType() != addressType) {
                warnLog("Address type mismatch for " + bdDevice + ", new type: " + addressType);
            }
        }

        if (types.length <= 0) {
            errorLog("No properties to update");
            return;
        }

        boolean newUuidsFound = false;

        for (int j = 0; j < types.length; j++) {
            type = types[j];
            val = values[j];
            if (val.length == 0) {
                continue;
            }

            synchronized (mObject) {
                debugLog("Update property, device=" + bdDevice + ", type: " + type);
                switch (type) {
                    case AbstractionLayer.BT_PROPERTY_BDNAME -> {
                        final String newName = new String(val);
                        if (newName.equals(deviceProperties.getName())) {
                            debugLog("Skip name update for " + bdDevice);
                            break;
                        }
                        deviceProperties.setName(newName);
                        List<String> wordBreakdownList =
                                MetricsLogger.getInstance().getWordBreakdownList(newName);
                        MetricsLogger.getInstance()
                                .uploadRestrictedBluetoothDeviceName(wordBreakdownList);
                        intent = new Intent(BluetoothDevice.ACTION_NAME_CHANGED);
                        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, bdDevice);
                        intent.putExtra(BluetoothDevice.EXTRA_NAME, deviceProperties.getName());
                        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
                        mAdapterService.sendBroadcast(
                                intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
                        debugLog("Remote device name is: " + deviceProperties.getName());
                    }
                    case AbstractionLayer.BT_PROPERTY_REMOTE_FRIENDLY_NAME -> {
                        deviceProperties.setAlias(bdDevice, new String(val));
                        debugLog("Remote device alias is: " + deviceProperties.getAlias());
                    }
                    case AbstractionLayer.BT_PROPERTY_BDADDR ->
                            debugLog(
                                    "Remote Address is:"
                                            + Util.getRedactedAddressStringFromByte(val));
                    case AbstractionLayer.BT_PROPERTY_CLASS_OF_DEVICE -> {
                        final int newBluetoothClass = Utils.byteArrayToInt(val);
                        if (newBluetoothClass == deviceProperties.getBluetoothClass()) {
                            debugLog(
                                    "Skip class update, device="
                                            + bdDevice
                                            + ", cod=0x"
                                            + Integer.toHexString(newBluetoothClass));
                            break;
                        }
                        deviceProperties.setBluetoothClass(newBluetoothClass);
                        if (Flags.sendClassChangeIntentForBondedDevicesOnly()
                                && deviceProperties.getBondState() != BluetoothDevice.BOND_BONDED) {
                            break;
                        }
                        intent = new Intent(BluetoothDevice.ACTION_CLASS_CHANGED);
                        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, bdDevice);
                        intent.putExtra(
                                BluetoothDevice.EXTRA_CLASS,
                                new BluetoothClass(deviceProperties.getBluetoothClass()));
                        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
                        mAdapterService.sendBroadcast(
                                intent, BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
                        debugLog(
                                "Remote class update, device="
                                        + bdDevice
                                        + ", cod=0x"
                                        + Integer.toHexString(newBluetoothClass));
                    }
                    case AbstractionLayer.BT_PROPERTY_UUIDS,
                            AbstractionLayer.BT_PROPERTY_UUIDS_LE -> {
                        if (type == AbstractionLayer.BT_PROPERTY_UUIDS) {
                            final ParcelUuid[] newUuids = Utils.byteArrayToUuid(val);
                            if (areUuidsEqual(newUuids, deviceProperties.getUuidsBrEdr())) {
                                // SDP Skip adding UUIDs to property cache if equal
                                debugLog("Skip uuids update for " + bdDevice.getAddress());
                                MetricsLogger.getInstance()
                                        .cacheCount(BluetoothProtoEnums.SDP_UUIDS_EQUAL_SKIP, 1);
                                break;
                            }
                            deviceProperties.setUuidsBrEdr(newUuids);
                        } else if (type == AbstractionLayer.BT_PROPERTY_UUIDS_LE) {
                            final ParcelUuid[] newUuidsLe = Utils.byteArrayToUuid(val);
                            if (areUuidsEqual(newUuidsLe, deviceProperties.getUuidsLe())) {
                                // SDP Skip adding UUIDs to property cache if equal
                                debugLog("Skip LE uuids update for " + bdDevice.getAddress());
                                MetricsLogger.getInstance()
                                        .cacheCount(BluetoothProtoEnums.SDP_UUIDS_EQUAL_SKIP, 1);
                                break;
                            }
                            deviceProperties.setUuidsLe(newUuidsLe);
                        }
                        newUuidsFound = true;
                    }
                    case AbstractionLayer.BT_PROPERTY_TYPE_OF_DEVICE -> {
                        if (deviceProperties.isConsolidated()) {
                            break;
                        }
                        // The device type from hal layer, defined in bluetooth.h,
                        // matches the type defined in BluetoothDevice.java
                        deviceProperties.setDeviceType(Utils.byteArrayToInt(val));
                    }
                    case AbstractionLayer.BT_PROPERTY_DISCOVERY_RESULT_TYPE ->
                            deviceProperties.setDiscoveryResultType(val[0]);
                    case AbstractionLayer.BT_PROPERTY_UUIDS_FROM_EXTENDED_INQUIRY_RESPONSE,
                            AbstractionLayer.BT_PROPERTY_UUIDS_FROM_LE_ADVERTISING_DATA -> {
                        final ParcelUuid[] newUuids;
                        if (val.length != 1) {
                            newUuids = Utils.byteArrayToUuid(val);
                        } else if (val[0]
                                == AbstractionLayer.BT_REASON_FOR_NO_UUIDS_EMPTY_UUID_LIST) {
                            newUuids = new ParcelUuid[0];
                        } else {
                            // val[0] ==
                            // AbstractionLayer.BT_REASON_FOR_NO_UUIDS_NO_UUID_TYPES_EXIST
                            newUuids = null;
                        }

                        Log.d(
                                TAG,
                                "UUID from EIR/AD. type="
                                        + type
                                        + ", newUuids="
                                        + Arrays.toString(newUuids));

                        if (type
                                == AbstractionLayer
                                        .BT_PROPERTY_UUIDS_FROM_EXTENDED_INQUIRY_RESPONSE) {
                            deviceProperties.setUuidsFromExtendedInquiryResponse(newUuids);
                        } else {
                            // type ==
                            // AbstractionLayer.BT_PROPERTY_UUIDS_FROM_LE_ADVERTISING_DATA
                            deviceProperties.setUuidsFromLeAdvertisingData(newUuids);
                        }
                    }
                    // RSSI from hal is in one byte
                    case AbstractionLayer.BT_PROPERTY_REMOTE_RSSI ->
                            deviceProperties.setRssi(val[0]);
                    case AbstractionLayer.BT_PROPERTY_REMOTE_IS_COORDINATED_SET_MEMBER ->
                            deviceProperties.setIsCoordinatedSetMember(val[0] != 0);
                    case AbstractionLayer.BT_PROPERTY_REMOTE_ASHA_CAPABILITY ->
                            deviceProperties.setAshaCapability(val[0]);
                    case AbstractionLayer.BT_PROPERTY_REMOTE_ASHA_TRUNCATED_HISYNCID ->
                            deviceProperties.setAshaTruncatedHiSyncId(val[0]);
                    case AbstractionLayer.BT_PROPERTY_REMOTE_MODEL_NUM -> {
                        final String modelName = new String(val);
                        debugLog("Remote device model name: " + modelName);
                        deviceProperties.setModelName(modelName);
                        BluetoothStatsLog.write(
                                BluetoothStatsLog.BLUETOOTH_DEVICE_INFO_REPORTED,
                                mAdapterService.obfuscateAddress(bdDevice),
                                BluetoothProtoEnums.DEVICE_INFO_INTERNAL,
                                LOG_SOURCE_DIS,
                                null,
                                modelName,
                                null,
                                null,
                                mAdapterService.getMetricId(bdDevice),
                                bdDevice.getAddressType(),
                                0,
                                0,
                                0);
                    }

                    case AbstractionLayer.BT_PROPERTY_BREDR_PAIRING_TYPE ->
                            updateBondStatus(
                                    deviceProperties, BluetoothDevice.TRANSPORT_BREDR, val);

                    case AbstractionLayer.BT_PROPERTY_LE_PAIRING_TYPE ->
                            updateBondStatus(deviceProperties, BluetoothDevice.TRANSPORT_LE, val);

                    default -> {} // Nothing to do
                }
            }
        }

        if (newUuidsFound) {
            if (Flags.broadcastUuidsFromMainLooper()) {
                // Ensure that UUID update is propagated in main looper
                triggerUuidNotification(bdDevice);
            } else {
                notifyUuids(deviceProperties, true);
            }
        }
    }

    private static void updateBondStatus(
            DeviceProperties deviceProperties, int transport, byte[] pairingType) {
        final int nativePairingAlgorithm = pairingType[0];
        final int nativePairingVariant = pairingType[1];
        final int pairingAlgorithm =
                BondStateMachine.getPairingAlgorithm(transport, nativePairingAlgorithm);
        final int pairingVariant =
                BondStateMachine.getPairingVariant(
                        transport, pairingAlgorithm, nativePairingVariant);
        debugLog(
                "updateBondStatus: "
                        + deviceProperties.getDevice()
                        + " transport: "
                        + (transport == BluetoothDevice.TRANSPORT_BREDR ? "BR/EDR" : "LE")
                        + ", algorithm:"
                        + pairingAlgorithm
                        + ", variant:"
                        + pairingVariant);
        deviceProperties.setBondStatus(transport, pairingAlgorithm, pairingVariant);
    }

    // TODO (b/462533972): Remove once the flag broadcast_uuids_from_main_looper is shipped.
    private void notifyUuids_(DeviceProperties deviceProperties, boolean success) {
        if (deviceProperties == null) {
            errorLog("notifyUuids_: Device Properties is null");
            return;
        }

        BluetoothDevice device = deviceProperties.getDevice();
        switch (mAdapterService.getState()) {
            case State.ON -> {
                if (success) {
                    MetricsLogger.getInstance()
                            .cacheCount(BluetoothProtoEnums.SDP_ADD_UUID_WITH_INTENT, 1);
                    // Adding UUIDs to property cache and sending intent
                    mAdapterService.serviceDiscoveryNotificationToBondStateMachine(device);
                } else {
                    MetricsLogger.getInstance()
                            .cacheCount(BluetoothProtoEnums.SDP_SENDING_DELAYED_UUID, 1);
                }
                sendUuidIntent(device, deviceProperties, success);
            }
            case State.BLE_ON -> {
                if (success) {
                    MetricsLogger.getInstance()
                            .cacheCount(BluetoothProtoEnums.SDP_ADD_UUID_WITH_NO_INTENT, 1);
                    // Adding UUIDs to property cache but with no intent
                    mAdapterService.serviceDiscoveryNotificationToBondStateMachine(device);
                }
            }
            default -> MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_DROP_UUID, 1);
        }
    }

    private void notifyUuids(DeviceProperties deviceProperties, boolean success) {
        if (!Flags.broadcastUuidsFromMainLooper()) {
            notifyUuids_(deviceProperties, success);
            return;
        }

        if (deviceProperties == null) {
            errorLog("uuidsUpdated: Device Properties is null");
            return;
        }

        BluetoothDevice device = deviceProperties.getDevice();
        ParcelUuid[] uuids = deviceProperties.getUuids();

        mAdapterService.deviceUuidsUpdated(device, uuids, success);
    }

    void deviceFoundCallback(byte[] address) {
        // The device properties are already registered - we can send the intent
        // now
        BluetoothDevice device = getDevice(address);
        DeviceProperties deviceProp = getDeviceProperties(device);
        if (deviceProp == null) {
            errorLog("deviceFoundCallback: Device Properties is null for Device:" + device);
            return;
        }
        boolean restrict_device_found =
                SystemProperties.getBoolean("bluetooth.restrict_discovered_device.enabled", false);
        if (restrict_device_found && (deviceProp.mName == null || deviceProp.mName.isEmpty())) {
            warnLog("deviceFoundCallback: Device name is null or empty: " + device);
            return;
        }

        infoLog("deviceFoundCallback: Remote Address is:" + device);
        mAdapterService.discoveryResultHandler(deviceProp);
    }

    void addressConsolidateCallback(byte[] mainAddress, byte[] secondaryAddress) {
        DeviceProperties deviceProperties;
        BluetoothDevice device = getDevice(mainAddress);
        if (device == null) {
            // Address consolidation happens only for the random device addresses
            deviceProperties =
                    addDeviceProperties(mainAddress, BluetoothDevice.ADDRESS_TYPE_RANDOM);
            device = deviceProperties.getDevice();
        } else {
            deviceProperties = getDeviceProperties(device);
        }
        Log.d(
                TAG,
                "addressConsolidateCallback device: "
                        + device
                        + ", secondaryAddress:"
                        + Util.getRedactedAddressStringFromByte(secondaryAddress));

        deviceProperties.setIsConsolidated(true);
        deviceProperties.setDeviceType(BluetoothDevice.DEVICE_TYPE_DUAL);
        // Dual mode devices have public identity address type
        deviceProperties.setIdentityAddress(
                Utils.getAddressStringFromByte(secondaryAddress),
                BluetoothDevice.ADDRESS_TYPE_PUBLIC);
        mAddressMap.put(
                deviceProperties.getIdentityAddress().getAddress(),
                Utils.getAddressStringFromByte(mainAddress));
    }

    /**
     * Callback to associate an LE-only device's RPA with its identity address and identity address
     * type
     *
     * @param pseudoAddress the device's RPA
     * @param identityAddress the device's identity address
     * @param identityAddressType the device's identity address type from native
     */
    void leAddressAssociateCallback(
            byte[] pseudoAddress, byte[] identityAddress, int identityAddressType) {
        DeviceProperties deviceProperties;
        BluetoothDevice device = getDevice(pseudoAddress);
        if (device == null) {
            // Address association happens only for the random device addresses
            deviceProperties =
                    addDeviceProperties(pseudoAddress, BluetoothDevice.ADDRESS_TYPE_RANDOM);
            device = deviceProperties.getDevice();
        } else {
            deviceProperties = getDeviceProperties(device);
        }
        Log.d(
                TAG,
                "leAddressAssociateCallback device: "
                        + device
                        + ", identityAddress:"
                        + Util.getRedactedAddressStringFromByte(identityAddress)
                        + ", identityAddressType="
                        + identityAddressType);

        final int addressType =
                switch (identityAddressType) {
                    case 0x00 -> BluetoothDevice.ADDRESS_TYPE_PUBLIC;
                    case 0x01 -> BluetoothDevice.ADDRESS_TYPE_RANDOM;
                    default -> {
                        errorLog(
                                "Unexpected identity address type received from native: "
                                        + identityAddressType);
                        yield BluetoothDevice.ADDRESS_TYPE_UNKNOWN;
                    }
                };

        String identityAddressString = Utils.getAddressStringFromByte(identityAddress);
        deviceProperties.setIdentityAddress(identityAddressString, addressType);
        mAddressMap.put(identityAddressString, Utils.getAddressStringFromByte(pseudoAddress));
    }

    void aclStateChangeCallback(
            int status,
            byte[] address,
            int addressType,
            int transport,
            int newState,
            int hciReason,
            int handle) {
        if (status != AbstractionLayer.BT_STATUS_SUCCESS) {
            debugLog("aclStateChangeCallback status is " + status + ", skipping");
            return;
        }

        final BluetoothDevice device =
                requireNonNullElseGet(
                        getDevice(address),
                        () -> {
                            Log.w(
                                    TAG,
                                    "aclStateChangeCallback: Adding cache for unknown device "
                                            + Util.getRedactedAddressStringFromByte(address)
                                            + " ("
                                            + Util.addressTypeToString(addressType));
                            return addDeviceProperties(address, addressType).getDevice();
                        });

        DeviceProperties deviceProperties = getDeviceProperties(device);

        int state = mAdapterService.getState();

        infoLog(
                "aclStateChangeCallback: "
                        + Util.transportToString(transport)
                        + (newState == AbstractionLayer.BT_ACL_STATE_CONNECTED
                                ? " Connected "
                                : " Disconnected ")
                        + device
                        + "("
                        + Util.addressTypeToString(addressType)
                        + ") reason: "
                        + hciReason
                        + (" adapter state: " + State.$.toString(state)));

        Intent intent = null;
        if (newState == AbstractionLayer.BT_ACL_STATE_CONNECTED) {
            deviceProperties.setConnected(transport, handle);
            if (Flags.leHidConnectionPolicySuspend()) {
                mConnectedDevices.add(new AclLinkSpec(device, transport));
            }

            if (Flags.fixIntentSelectionForAcl()
                    || state == State.ON
                    || state == State.TURNING_ON) {
                intent = new Intent(BluetoothDevice.ACTION_ACL_CONNECTED);
                intent.putExtra(BluetoothDevice.EXTRA_TRANSPORT, transport);
            } else if (state == State.BLE_ON || state == State.BLE_TURNING_ON) {
                intent = new Intent(BluetoothAdapter.ACTION_BLE_ACL_CONNECTED);
            }
            mAdapterService
                    .getBatteryService()
                    .filter(battery -> transport == TRANSPORT_LE)
                    .ifPresent(battery -> battery.connectIfPossible(device));
            SecurityLog.writeEvent(
                    SecurityLog.TAG_BLUETOOTH_CONNECTION,
                    device.toString(), /* success */
                    1, /* reason */
                    "");
        } else {
            deviceProperties.setDisconnected(transport);
            if (Flags.leHidConnectionPolicySuspend()) {
                mConnectedDevices.remove(new AclLinkSpec(device, transport));
            }
            if (getBondState(device) == BluetoothDevice.BOND_BONDING) {
                // Send PAIRING_CANCEL intent to dismiss any dialog requesting bonding.
                sendPairingCancelIntent(device);
            } else if (getBondState(device) == BluetoothDevice.BOND_NONE
                    && deviceProperties.getBondingInitiator()
                            != DeviceProperties.BONDING_INITIATOR_NONE) {
                // Don't remove device properties if bonding never attempted
                removeDeviceProperties(Utils.getAddressStringFromByte(address));
            }
            if (Flags.fixIntentSelectionForAcl()
                    || state == State.ON
                    || state == State.TURNING_OFF) {
                mAdapterService.notifyAclDisconnected(device, transport);
                intent = new Intent(BluetoothDevice.ACTION_ACL_DISCONNECTED);
                intent.putExtra(BluetoothDevice.EXTRA_TRANSPORT, transport);
            } else if (state == State.BLE_ON || state == State.BLE_TURNING_OFF) {
                intent = new Intent(BluetoothAdapter.ACTION_BLE_ACL_DISCONNECTED);
            }
            // Reset battery level on complete disconnection
            if (mAdapterService.getConnectionState(device) == 0) {
                mAdapterService
                        .getBatteryService()
                        .filter(battery -> transport == TRANSPORT_LE)
                        .filter(battery -> battery.getConnectionState(device) != STATE_DISCONNECTED)
                        .ifPresent(battery -> battery.disconnect(device));
                resetBatteryLevel(device, /* isBas= */ true);
            }

            if (mAdapterService.isAllProfilesUnknown(device)) {
                DeviceProperties deviceProp = getDeviceProperties(device);
                if (deviceProp != null && deviceProp.isBondingInitiatedLocally()) {
                    // Reset bonding initiator state if both transports are disconnected
                    if (deviceProp.getConnectionHandle(TRANSPORT_LE) == BluetoothDevice.ERROR
                            && deviceProp.getConnectionHandle(TRANSPORT_BREDR)
                                    == BluetoothDevice.ERROR) {
                        deviceProp.setBondingInitiatedLocally(false);
                    }
                }
            }
            SecurityLog.writeEvent(
                    SecurityLog.TAG_BLUETOOTH_DISCONNECTION,
                    device.toString(),
                    BluetoothAdapter.BluetoothConnectionCallback.disconnectReasonToString(
                            Util.hciToAndroidDisconnectReason(hciReason)));
        }

        int connectionState =
                newState == AbstractionLayer.BT_ACL_STATE_CONNECTED
                        ? BluetoothAdapter.STATE_CONNECTED
                        : BluetoothAdapter.STATE_DISCONNECTED;
        int metricId = mAdapterService.getMetricId(device);
        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_ACL_CONNECTION_STATE_CHANGED,
                mAdapterService.obfuscateAddress(device),
                connectionState,
                metricId,
                transport);

        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_CLASS_OF_DEVICE_REPORTED,
                mAdapterService.obfuscateAddress(device),
                getBluetoothClass(device),
                metricId);

        byte[] remoteDeviceInfoBytes = MetricsLogger.getInstance().getRemoteDeviceInfoProto(device);

        BluetoothStatsLog.write(
                BluetoothStatsLog.REMOTE_DEVICE_INFORMATION_WITH_METRIC_ID,
                metricId,
                remoteDeviceInfoBytes);

        if (intent == null) {
            Log.e(TAG, "aclStateChangeCallback intent is null. BondState: " + getBondState(device));
            return;
        }

        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device)
                .addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT)
                .addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        final BroadcastOptions options = Util.getTempBroadcastOptions();
        if (BluetoothDevice.ACTION_ACL_CONNECTED.equals(intent.getAction())
                || BluetoothDevice.ACTION_ACL_DISCONNECTED.equals(intent.getAction())) {
            // This allows the broadcasting system to discard any older broadcasts
            // waiting to be delivered to a process.
            options.setDeliveryGroupPolicy(BroadcastOptions.DELIVERY_GROUP_POLICY_MOST_RECENT);
            // Set namespace and key to identify which older broadcasts can be discarded.
            // We use transport and device address as the key so that only older broadcasts
            // for the same device and transport are discarded.
            options.setDeliveryGroupMatchingKey(
                    ACL_CONNECTION_DELIVERY_GROUP_POLICY, transport + "/" + device.getAddress());
        }

        // Send the ACTION_KEY_MISSING Intent here if the link is disconnected in a bond-loss
        // scenario, and none of the transports are connected indicating that we are done.
        // Note: Broadcast the ACTION_KEY_MISSING before the ACTION_ACL_DISCONNECTED.
        if (Utils.isAutonomousRepairingSupported()
                && mAdapterService.isBondLost(device)
                && newState == AbstractionLayer.BT_ACL_STATE_DISCONNECTED
                && deviceProperties.getLastBondLossReason().isPresent()
                && deviceProperties.getConnectionHandle(TRANSPORT_LE) == BluetoothDevice.ERROR
                && deviceProperties.getConnectionHandle(TRANSPORT_BREDR) == BluetoothDevice.ERROR) {
            sendKeyMissingIntent(device, deviceProperties.getLastBondLossReason().get());
            deviceProperties.setLastBondLossReason(Optional.empty()); // Reset once sent.
        }

        mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT, options.toBundle());

        RemoteExceptionIgnoringConsumer<IBluetoothConnectionCallback> connectionChangeConsumer;
        if (connectionState == BluetoothAdapter.STATE_CONNECTED) {
            connectionChangeConsumer = cb -> cb.onDeviceConnected(device);
            // TODO the whole method should run on the looper
            mHandler.post(() -> mWatchConnectionStateListener.onDeviceConnected(device, transport));
        } else {
            final int disconnectReasonFromHci;
            if (hciReason == 0x16 /* HCI_ERR_CONN_CAUSE_LOCAL_HOST */
                    && mAdapterService.getKeyMissingCount(device) > 0) {
                // Native stack disconnects the link on detecting the bond loss. Native GATT would
                // return HCI_ERR_CONN_CAUSE_LOCAL_HOST in such case, but the apps should see
                // HCI_ERR_AUTH_FAILURE.
                Log.d(
                        TAG,
                        "aclStateChangeCallback() - disconnected due to bond loss for device="
                                + device);
                disconnectReasonFromHci = 0x05; /* HCI_ERR_AUTH_FAILURE */
            } else {
                disconnectReasonFromHci = hciReason;
            }

            if (Flags.addNewLocalDisconnectReason()
                    && hciReason == 0x16 /* HCI_ERR_CONN_CAUSE_LOCAL_HOST */) {
                // When disconnectAllEnabledProfiles() or disconnectAllAcl() is user-triggered,
                // the disconnect reason changes from HCI_ERR_CONN_CAUSE_LOCAL_HOST to
                // ERROR_DISCONNECT_REASON_USER_REQUEST or ERROR_DISCONNECT_REASON_ADAPTER_SUSPEND.
                final int disconnectReason = mAdapterService.popDeviceDisconnectReason(device);
                Log.d(TAG, "ACTION_ACL_DISCONNECTED: reason=" + disconnectReason);
                connectionChangeConsumer = cb -> cb.onDeviceDisconnected(device, disconnectReason);
            } else {
                connectionChangeConsumer =
                        cb ->
                                cb.onDeviceDisconnected(
                                        device,
                                        Util.hciToAndroidDisconnectReason(disconnectReasonFromHci));
            }
            mHandler.post(
                    () -> mWatchConnectionStateListener.onDeviceDisconnected(device, transport));
        }

        mAdapterService.aclStateChangeBroadcastCallback(connectionChangeConsumer);
    }

    private void sendPairingCancelIntent(BluetoothDevice device) {
        Intent intent = new Intent(BluetoothDevice.ACTION_PAIRING_CANCEL);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.setPackage(
                SystemProperties.get(
                        Utils.PAIRING_UI_PROPERTY,
                        mAdapterService.getString(R.string.pairing_ui_package)));

        Log.i(TAG, "sendPairingCancelIntent: device=" + device);
        mAdapterService.sendBroadcastAsUser(intent, mAdapterService.getUser(), BLUETOOTH_CONNECT, Util.getTempBroadcastBundle());
    }

    private void removeDeviceProperties(String address) {
        DeviceProperties deviceProperties = mDevices.get(address);
        if (deviceProperties != null) {
            String pseudoAddress = mAddressMap.get(address);
            if (pseudoAddress != null) {
                deviceProperties = mDevices.get(pseudoAddress);
            }
        }

        if (deviceProperties != null) {
            int leConnectionHandle = deviceProperties.getConnectionHandle(TRANSPORT_LE);
            int bredrConnectionHandle = deviceProperties.getConnectionHandle(TRANSPORT_BREDR);
            if (leConnectionHandle != BluetoothDevice.ERROR
                    || bredrConnectionHandle != BluetoothDevice.ERROR) {
                // Device still connected, wait for disconnection to remove the properties
                return;
            }
        }

        Log.i(
                TAG,
                "removeDeviceProperties: "
                        + (deviceProperties != null
                                ? deviceProperties
                                : toAnonymizedAddress(address)));

        synchronized (mDevices) {
            mDevices.remove(address);

            // Remove from dual mode device mappings
            mAddressMap.values().remove(address);
            mAddressMap.remove(address);
        }
    }

    void onBondStateChange(
            BluetoothDevice device,
            int transport,
            int newState,
            Integer pairingAlgorithm,
            Integer pairingVariant) {
        String address = device.getAddress();

        if (newState == BluetoothDevice.BOND_NONE) {
            removeDeviceProperties(address);
        } else if (newState == BluetoothDevice.BOND_BONDED) {
            if (pairingAlgorithm == null || pairingVariant == null) {
                Log.e(
                        TAG,
                        "onBondStateChange: pairingAlgorithm or pairingVariant is null, device="
                                + device);
                return;
            }

            Log.i(
                    TAG,
                    "onBondStateChange: device="
                            + device
                            + " newState="
                            + newState
                            + " transport="
                            + transport
                            + " pairingAlgorithm="
                            + pairingAlgorithm
                            + " pairingVariant="
                            + pairingVariant);
            DeviceProperties deviceProperties = getDeviceProperties(device);
            if (deviceProperties != null) {
                deviceProperties.setBondStatus(transport, pairingAlgorithm, pairingVariant);
            }
        }
    }

    void keyMissingCallback(byte[] address, int reason) {
        BluetoothDevice device = getDevice(address);
        if (device == null) {
            errorLog(
                    "keyMissingCallback: device is NULL, address="
                            + Util.getRedactedAddressStringFromByte(address));
            return;
        }

        if (getBondState(device) != BluetoothDevice.BOND_BONDED) {
            errorLog("keyMissingCallback: device is not bonded, address=" + device);
            return;
        }

        Log.i(TAG, "keyMissingCallback device: " + device + ", reason: " + reason);

        // Log transition to key missing state, if the key missing count is 0 which indicates
        // that the device is bonded until now.
        if (mAdapterService.getKeyMissingCount(device) == 0) {
            MetricsLogger.getInstance()
                    .logBluetoothEvent(
                            device,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__TRANSITION,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__BOND_BONDED_TO_ACTION_KEY_MISSING,
                            0);
        }

        // Bond loss detected, add to the count.
        mAdapterService.updateKeyMissingCount(device, true);

        if (Utils.isAutonomousRepairingSupported()) {
            MetricsLogger.getInstance().count(BluetoothProtoEnums.BOND_LOSS_DETECTED_REPAIRING, 1);
            MetricsLogger.getInstance()
                    .logBluetoothEvent(
                            device,
                            BluetoothStatsLog
                                    .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__BOND_REPAIR,
                            BluetoothStatsLog.BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__START,
                            0);
        } else {
            MetricsLogger.getInstance().count(BluetoothProtoEnums.BOND_LOSS_DETECTED, 1);
        }

        // Some apps are not able to handle the key missing broadcast, so we need to remove
        // the bond to prevent them from misbehaving.
        // TODO (b/402854328): Remove when the misbehaving apps are updated
        DeviceProperties deviceProperties = getDeviceProperties(device);
        if (bondLossIopFixNeeded(device)) {
            if (deviceProperties == null) {
                return;
            }
            String[] packages = deviceProperties.getPackages();
            if (packages.length == 0) {
                return;
            }

            Log.w(TAG, "Removing " + device + " on behalf of: " + Arrays.toString(packages));
            mAdapterService.syncPost(() -> mAdapterService.removeBond(device), false);
            return;
        }

        if (!Utils.isAutonomousRepairingSupported()) {
            sendKeyMissingIntent(device, reason);
            return;
        }

        deviceProperties.setLastBondLossReason(Optional.of(reason));
        if (reason == BluetoothDevice.BOND_LOSS_REASON_BREDR_AUTH_FAILURE
                || reason == BluetoothDevice.BOND_LOSS_REASON_LE_ENCRYPT_FAILURE) {
            Log.i(
                    TAG,
                    "Bond loss is detected, initiating autonomous repairing for device: " + device);

            // If the create bond procedure fails, that will be detected in
            // BondStateMachine.createBond(). ACL disconnect will be initiated from that place
            // instead.
            if (reason == BluetoothDevice.BOND_LOSS_REASON_BREDR_AUTH_FAILURE) {
                mAdapterService.sendCreateBondMessage(device, TRANSPORT_BREDR, null, null);
            } else {
                mAdapterService.sendCreateBondMessage(device, TRANSPORT_LE, null, null);
            }
        }
    }

    void encryptionChangeCallback(
            byte[] address,
            int status,
            boolean encryptionEnable,
            int transport,
            int encryptionAlgo,
            int keySize) {
        BluetoothDevice bluetoothDevice = getDevice(address);
        if (bluetoothDevice == null) {
            errorLog(
                    "encryptionChangeCallback: device is NULL, address="
                            + Util.getRedactedAddressStringFromByte(address));
            return;
        }
        Log.d(
                TAG,
                "encryptionChangeCallback device: "
                        + bluetoothDevice
                        + ", status: "
                        + status
                        + ", enabled: "
                        + encryptionEnable
                        + ", transport: "
                        + transport
                        + ", encryptionAlgo: "
                        + encryptionAlgo
                        + ", keySize: "
                        + keySize);

        logEncryptionEvent(bluetoothDevice, transport, encryptionEnable);

        if (encryptionEnable) {
            // Log transition to encryption change state (bonded), if the key missing count is > 0
            //  which indicates that the device is in key missing state.
            if (mAdapterService.getKeyMissingCount(bluetoothDevice) > 0) {
                MetricsLogger.getInstance()
                        .logBluetoothEvent(
                                bluetoothDevice,
                                BluetoothStatsLog
                                        .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__TRANSITION,
                                BluetoothStatsLog
                                        .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__ACTION_KEY_MISSING_TO_ENCRYPTION_CHANGE,
                                0);

                // Successful bond detected, reset the count.
                mAdapterService.updateKeyMissingCount(bluetoothDevice, false);
            }
        }

        getDeviceProperties(bluetoothDevice)
                .setEncryptionStatus(transport, keySize, encryptionAlgo);

        Intent intent =
                new Intent(BluetoothDevice.ACTION_ENCRYPTION_CHANGE)
                        .putExtra(BluetoothDevice.EXTRA_DEVICE, bluetoothDevice)
                        .putExtra(BluetoothDevice.EXTRA_TRANSPORT, transport)
                        .putExtra(BluetoothDevice.EXTRA_ENCRYPTION_STATUS, status)
                        .putExtra(BluetoothDevice.EXTRA_ENCRYPTION_ENABLED, encryptionEnable)
                        .putExtra(BluetoothDevice.EXTRA_KEY_SIZE, keySize)
                        .putExtra(BluetoothDevice.EXTRA_ENCRYPTION_ALGORITHM, encryptionAlgo);

        mAdapterService.sendBroadcast(intent, BLUETOOTH_CONNECT);
    }

    void fetchUuids(BluetoothDevice device, int transport) {
        DeviceProperties deviceProperties = getDeviceProperties(device);

        // If there are no cached UUIDs and the device is bonding, wait for service discovery
        // results from the bonding process.
        if (deviceProperties != null && deviceProperties.isBonding()) {
            debugLog("Skip fetch UUIDs due to bonding peer:" + device + " transport:" + transport);
            MetricsLogger.getInstance()
                    .cacheCount(BluetoothProtoEnums.SDP_FETCH_UUID_SKIP_ALREADY_BONDED, 1);
            return;
        }

        if (deviceProperties == null) {
            deviceProperties =
                    addDeviceProperties(Util.getByteAddress(device), device.getAddressType());
        }

        // mHandler.hasMessages() and mHandler.removeMessages() uses reference equality to compare
        // the device object. So the BluetoothDevice object from deviceProperties must be used.
        device = deviceProperties.getDevice();
        if (mHandler.hasMessages(MESSAGE_SERVICE_DISCOVERY_TIMEOUT, device)) {
            debugLog(
                    "Skip fetch UUIDs are they are already cached peer:"
                            + device
                            + " transport:"
                            + transport);
            MetricsLogger.getInstance()
                    .cacheCount(BluetoothProtoEnums.SDP_FETCH_UUID_SKIP_ALREADY_CACHED, 1);
            return;
        }

        // Start a timer to conclude service discovery if it takes too long.
        Message message = mHandler.obtainMessage(MESSAGE_SERVICE_DISCOVERY_TIMEOUT, device);
        mHandler.sendMessageDelayed(message, SERVICE_DISCOVERY_TIMEOUT_MS);

        MetricsLogger.getInstance().cacheCount(BluetoothProtoEnums.SDP_INVOKE_SDP_CYCLE, 1);

        // Some apps expect service discovery to be performed on all connected transports.
        if (transport == TRANSPORT_AUTO) {
            boolean startedLeServiceDiscovery = false;
            boolean startedBredrServiceDiscovery = false;
            if (deviceProperties.getConnectionHandle(TRANSPORT_LE) != BluetoothDevice.ERROR) {
                mAdapterService
                        .getNative()
                        .getRemoteServices(
                                Util.getBytesFromAddress(device.getAddress()), TRANSPORT_LE);
                startedLeServiceDiscovery = true;
            }

            if (deviceProperties.getConnectionHandle(TRANSPORT_BREDR) != BluetoothDevice.ERROR) {
                mAdapterService
                        .getNative()
                        .getRemoteServices(
                                Util.getBytesFromAddress(device.getAddress()), TRANSPORT_BREDR);
                startedBredrServiceDiscovery = true;
            }

            if (startedLeServiceDiscovery || startedBredrServiceDiscovery) {
                infoLog(
                        "fetchUuids(): Invoking service discovery over connected transports:"
                                + device
                                + " LE:"
                                + startedLeServiceDiscovery
                                + " BREDR:"
                                + startedBredrServiceDiscovery);
                return;
            }
        }

        debugLog(
                "fetchUuids: Start service discovery for device:"
                        + device
                        + " transport:"
                        + transport);
        mAdapterService
                .getNative()
                .getRemoteServices(Util.getBytesFromAddress(device.getAddress()), transport);
    }

    void triggerUuidNotification(BluetoothDevice device) {
        Message message = mHandler.obtainMessage(MESSAGE_NOTIFY_UUIDS, device);
        mHandler.sendMessage(message);
    }

    /** Handles headset connection state change event */
    public void handleHeadsetConnectionStateChanged(
            BluetoothDevice device, int fromState, int toState) {
        mHandler.post(() -> onHeadsetConnectionStateChanged(device, fromState, toState));
    }

    @VisibleForTesting
    void onHeadsetConnectionStateChanged(BluetoothDevice device, int fromState, int toState) {
        if (device == null) {
            Log.e(TAG, "onHeadsetConnectionStateChanged() remote device is null");
            return;
        }
        if (toState == STATE_DISCONNECTED && !hasBatteryService(device)) {
            resetBatteryLevel(device, /* isBas= */ false);
        }
    }

    /** Handle Indicator status events from Hands-free. */
    public void handleHfIndicatorStatus(
            BluetoothDevice device, int indicatorId, boolean indicatorStatus) {
        mHandler.post(() -> onHfIndicatorStatus(device, indicatorId, indicatorStatus));
    }

    @VisibleForTesting
    void onHfIndicatorStatus(BluetoothDevice device, int indicatorId, boolean indicatorStatus) {
        if (device == null) {
            Log.e(TAG, "onHfIndicatorStatus() remote device is null");
            return;
        }
        if (indicatorId == HeadsetHalConstants.HF_INDICATOR_BATTERY_LEVEL_STATUS) {
            getDeviceProperties(device).setHfpBatteryIndicatorStatus(indicatorStatus);
        }
    }

    /** Handle indication events from Hands-free. */
    public void handleHfIndicatorValueChanged(
            BluetoothDevice device, int indicatorId, int indicatorValue) {
        mHandler.post(() -> onHfIndicatorValueChanged(device, indicatorId, indicatorValue));
    }

    @VisibleForTesting
    void onHfIndicatorValueChanged(BluetoothDevice device, int indicatorId, int indicatorValue) {
        if (device == null) {
            Log.e(TAG, "onHfIndicatorValueChanged() remote device is null");
            return;
        }
        if (indicatorId == HeadsetHalConstants.HF_INDICATOR_BATTERY_LEVEL_STATUS) {
            updateBatteryLevel(device, indicatorValue, /* isBas= */ false);
        }
    }

    /** Handles Headset specific Bluetooth events */
    public void handleVendorSpecificHeadsetEvent(
            BluetoothDevice device, String cmd, int companyId, int cmdType, Object[] args) {
        mHandler.post(() -> onVendorSpecificHeadsetEvent(device, cmd, companyId, cmdType, args));
    }

    @VisibleForTesting
    void onVendorSpecificHeadsetEvent(
            BluetoothDevice device, String cmd, int companyId, int cmdType, Object[] args) {
        if (device == null) {
            Log.e(TAG, "onVendorSpecificHeadsetEvent() remote device is null");
            return;
        }
        if (companyId != BluetoothAssignedNumbers.PLANTRONICS
                && companyId != BluetoothAssignedNumbers.APPLE) {
            Log.i(
                    TAG,
                    "onVendorSpecificHeadsetEvent() filtered out non-PLANTRONICS and non-APPLE "
                            + "vendor commands");
            return;
        }
        if (cmd == null) {
            Log.e(TAG, "onVendorSpecificHeadsetEvent() command is null");
            return;
        }
        // Only process set command
        if (cmdType != BluetoothHeadset.AT_CMD_TYPE_SET) {
            debugLog("onVendorSpecificHeadsetEvent() only SET command is processed");
            return;
        }
        if (args == null) {
            Log.e(TAG, "onVendorSpecificHeadsetEvent() arguments are null");
            return;
        }

        if (Flags.enableBatteryLevelUpdateOnlyThroughHfIndicator()) {
            DeviceProperties deviceProperties = getDeviceProperties(device);
            if ((deviceProperties.isHfpBatteryIndicatorEnabled())
                    && ((BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XEVENT.equals(cmd))
                            || (BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_IPHONEACCEV.equals(
                                    cmd)))) {
                infoLog(
                        "Ignoring Battery Level update through vendor specific command as"
                                + "HfpBatteryIndicator support is enabled.");
                return;
            }
        }

        final int batteryPercent =
                switch (cmd) {
                    case BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XEVENT ->
                            getBatteryLevelFromXEventVsc(args);
                    case BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_IPHONEACCEV ->
                            getBatteryLevelFromAppleBatteryVsc(args);
                    default -> BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
                };
        if (batteryPercent != BluetoothDevice.BATTERY_LEVEL_UNKNOWN) {
            updateBatteryLevel(device, batteryPercent, /* isBas= */ false);
            infoLog(
                    "Updated device "
                            + device
                            + " battery level to "
                            + String.valueOf(batteryPercent)
                            + "%");
        }
    }

    /**
     * Parse AT+IPHONEACCEV=[NumberOfIndicators],[IndicatorType],[IndicatorValue] vendor specific
     * event
     *
     * @param args Array of arguments on the right side of assignment
     * @return Battery level in percents, [0-100], {@link BluetoothDevice#BATTERY_LEVEL_UNKNOWN}
     *     when there is an error parsing the arguments
     */
    @VisibleForTesting
    static int getBatteryLevelFromAppleBatteryVsc(Object[] args) {
        if (args.length == 0) {
            Log.w(TAG, "getBatteryLevelFromAppleBatteryVsc() empty arguments");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        int numKvPair;
        if (args[0] instanceof Integer) {
            numKvPair = (Integer) args[0];
        } else {
            Log.w(TAG, "getBatteryLevelFromAppleBatteryVsc() error parsing number of arguments");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        if (args.length != (numKvPair * 2 + 1)) {
            Log.w(TAG, "getBatteryLevelFromAppleBatteryVsc() number of arguments does not match");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        int indicatorType;
        int indicatorValue = -1;
        for (int i = 0; i < numKvPair; ++i) {
            Object indicatorTypeObj = args[2 * i + 1];
            if (indicatorTypeObj instanceof Integer) {
                indicatorType = (Integer) indicatorTypeObj;
            } else {
                Log.w(TAG, "getBatteryLevelFromAppleBatteryVsc() error parsing indicator type");
                return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
            }
            if (indicatorType
                    != BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_IPHONEACCEV_BATTERY_LEVEL) {
                continue;
            }
            Object indicatorValueObj = args[2 * i + 2];
            if (indicatorValueObj instanceof Integer) {
                indicatorValue = (Integer) indicatorValueObj;
            } else {
                Log.w(TAG, "getBatteryLevelFromAppleBatteryVsc() error parsing indicator value");
                return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
            }
            break;
        }
        return (indicatorValue < 0 || indicatorValue > 9)
                ? BluetoothDevice.BATTERY_LEVEL_UNKNOWN
                : (indicatorValue + 1) * 10;
    }

    /**
     * Parse AT+XEVENT=BATTERY,[Level],[NumberOfLevel],[MinutesOfTalk],[IsCharging] vendor specific
     * event
     *
     * @param args Array of arguments on the right side of SET command
     * @return Battery level in percents, [0-100], {@link BluetoothDevice#BATTERY_LEVEL_UNKNOWN}
     *     when there is an error parsing the arguments
     */
    @VisibleForTesting
    static int getBatteryLevelFromXEventVsc(Object[] args) {
        if (args.length == 0) {
            Log.w(TAG, "getBatteryLevelFromXEventVsc() empty arguments");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        Object eventNameObj = args[0];
        if (!(eventNameObj instanceof String)) {
            Log.w(TAG, "getBatteryLevelFromXEventVsc() error parsing event name");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        String eventName = (String) eventNameObj;
        if (!eventName.equals(
                BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XEVENT_BATTERY_LEVEL)) {
            infoLog("getBatteryLevelFromXEventVsc() skip none BATTERY event: " + eventName);
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        if (args.length != 5) {
            Log.w(
                    TAG,
                    "getBatteryLevelFromXEventVsc() wrong battery level event length: "
                            + String.valueOf(args.length));
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        if (!(args[1] instanceof Integer) || !(args[2] instanceof Integer)) {
            Log.w(TAG, "getBatteryLevelFromXEventVsc() error parsing event values");
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        int batteryLevel = (Integer) args[1];
        int numberOfLevels = (Integer) args[2];
        if (batteryLevel < 0 || numberOfLevels <= 1 || batteryLevel > numberOfLevels) {
            Log.w(
                    TAG,
                    "getBatteryLevelFromXEventVsc() wrong event value, batteryLevel="
                            + String.valueOf(batteryLevel)
                            + ", numberOfLevels="
                            + String.valueOf(numberOfLevels));
            return BluetoothDevice.BATTERY_LEVEL_UNKNOWN;
        }
        return batteryLevel * 100 / (numberOfLevels - 1);
    }

    @VisibleForTesting
    boolean hasBatteryService(BluetoothDevice device) {
        return mAdapterService
                .getBatteryService()
                .map(battery -> battery.getConnectionState(device) == STATE_CONNECTED)
                .orElse(false);
    }

    /** Handles headset client connection state change event. */
    public void handleHeadsetClientConnectionStateChanged(
            BluetoothDevice device, int fromState, int toState) {
        mHandler.post(() -> onHeadsetClientConnectionStateChanged(device, fromState, toState));
    }

    @VisibleForTesting
    void onHeadsetClientConnectionStateChanged(BluetoothDevice device, int fromState, int toState) {
        if (device == null) {
            Log.e(TAG, "onHeadsetClientConnectionStateChanged() remote device is null");
            return;
        }
        if (toState == STATE_DISCONNECTED && !hasBatteryService(device)) {
            resetBatteryLevel(device, /* isBas= */ false);
        }
    }

    /** Handle battery level changes indication events from Audio Gateway. */
    public void handleAgBatteryLevelChanged(BluetoothDevice device, int batteryLevel) {
        mHandler.post(() -> onAgBatteryLevelChanged(device, batteryLevel));
    }

    @VisibleForTesting
    void onAgBatteryLevelChanged(BluetoothDevice device, int batteryLevel) {
        if (device == null) {
            Log.e(TAG, "onAgBatteryLevelChanged() remote device is null");
            return;
        }
        updateBatteryLevel(
                device, batteryChargeIndicatorToPercentage(batteryLevel), /* isBas= */ false);
    }

    public boolean packageAssociated(BluetoothDevice device, String[] packages) {
        DeviceProperties deviceProperties = getDeviceProperties(device);
        if (deviceProperties == null) {
            return false;
        }

        String[] associatedPackages = deviceProperties.getPackages();
        if (associatedPackages.length == 0) {
            return false;
        }

        for (String appName : packages) {
            for (String associatedPackage : associatedPackages) {
                if (associatedPackage.contains(appName)) {
                    Log.w(
                            TAG,
                            "packageAssociated(): "
                                    + " package "
                                    + associatedPackage
                                    + "associated with "
                                    + device);
                    return true;
                }
            }
        }

        return false;
    }

    private static final String[] BOND_LOSS_IOP_PACKAGES = {
        "com.sjm.crmd.patientApp_Android", "com.abbott.crm.ngq.patient",
    };

    private static final Set<String> BOND_LOSS_IOP_DEVICE_NAMES = Set.of("CM", "DM");

    // TODO (b/402854328): Remove when the misbehaving apps are updated
    public boolean bondLossIopFixNeeded(BluetoothDevice device) {
        DeviceProperties deviceProperties = getDeviceProperties(device);
        if (deviceProperties == null) {
            return false;
        }

        String deviceName = deviceProperties.getName();
        if (deviceName == null) {
            return false;
        }

        if (!BOND_LOSS_IOP_DEVICE_NAMES.contains(deviceName)) {
            return false;
        }

        return packageAssociated(device, BOND_LOSS_IOP_PACKAGES);
    }

    private static void errorLog(String msg) {
        Log.e(TAG, msg);
    }

    private static void debugLog(String msg) {
        Log.d(TAG, msg);
    }

    private static void infoLog(String msg) {
        Log.i(TAG, msg);
    }

    private static void warnLog(String msg) {
        Log.w(TAG, msg);
    }

    protected void dump(PrintWriter writer) {
        int bondedCount = 0;
        int knownCount = 0;
        StringBuilder sbBonded = new StringBuilder();
        StringBuilder sbKnown = new StringBuilder();
        for (Map.Entry<String, DeviceProperties> entry : mDevices.entrySet()) {
            String address = entry.getKey();
            DeviceProperties deviceProperties = entry.getValue();
            if (address == null || deviceProperties == null) {
                continue;
            }

            boolean bonded = deviceProperties.getBondState() == BluetoothDevice.BOND_BONDED;
            StringBuilder sb = bonded ? sbBonded : sbKnown;
            sb.append(deviceProperties);

            if (bonded) {
                bondedCount++;
            } else {
                knownCount++;
            }
        }

        writer.println(TAG);
        writer.println("  Bonded devices: " + bondedCount);
        writer.println(sbBonded);
        writer.println("  Other devices: " + knownCount);
        writer.println(sbKnown);
    }

    // TODO: Remove this when use_autonomous_repairing flag is removed.
    private void sendKeyMissingIntent(BluetoothDevice device, int reason) {
        Intent keyMissingIntent =
                new Intent(BluetoothDevice.ACTION_KEY_MISSING)
                        .putExtra(BluetoothDevice.EXTRA_DEVICE, device)
                        .addFlags(
                                Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);

        keyMissingIntent.putExtra(BluetoothDevice.EXTRA_BOND_LOSS_REASON, reason);

        Log.d(TAG, "sendKeyMissingIntent: device=" + device + " reason=" + reason);

        mAdapterService.sendOrderedBroadcast(
                keyMissingIntent,
                BLUETOOTH_CONNECT,
                Util.getTempBroadcastBundle(),
                null /* resultReceiver */,
                null /* scheduler */,
                Activity.RESULT_OK /* initialCode */,
                null /* initialData */,
                null /* initialExtras */);
    }

    private static void logEncryptionEvent(
            BluetoothDevice device, int transport, boolean encryptionEnable) {
        int eventType;
        if (transport == TRANSPORT_BREDR) {
            eventType =
                    BluetoothStatsLog
                            .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__BREDR_ENCRYPTION;
        } else if (transport == TRANSPORT_LE) {
            eventType =
                    BluetoothStatsLog
                            .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__EVENT_TYPE__LE_ENCRYPTION;
        } else {
            Log.e(TAG, "logEncryptionEvent() unexpected transport: " + transport);
            return;
        }
        MetricsLogger.getInstance()
                .logBluetoothEvent(
                        device,
                        eventType,
                        encryptionEnable
                                ? BluetoothStatsLog
                                        .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__ENABLED
                                : BluetoothStatsLog
                                        .BLUETOOTH_CROSS_LAYER_EVENT_REPORTED__STATE__DISABLED,
                        0);
    }
}
