/*
 * Copyright (C) 2014 The Android Open Source Project
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

package com.android.bluetooth.gatt;

import android.bluetooth.BluetoothUuid;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.RemoteException;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Manages Bluetooth LE advertising operations and interacts with bluedroid stack. TODO: add tests.
 *
 * @hide
 */
class AdvertiseManager {
    private static final boolean DBG = GattServiceConfig.DBG;
    private static final String TAG = GattServiceConfig.TAG_PREFIX + "AdvertiseManager";

    // Timeout for each controller operation.
    private static final int OPERATION_TIME_OUT_MILLIS = 500;

    // Message for advertising operations.
    private static final int MSG_START_ADVERTISING = 0;
    private static final int MSG_STOP_ADVERTISING = 1;

    private final GattService mService;
    private final AdapterService mAdapterService;
    private final Set<AdvertiseClient> mAdvertiseClients;
    private final AdvertiseNative mAdvertiseNative;

    // Handles advertise operations.
    private ClientHandler mHandler;

    // CountDownLatch for blocking advertise operations.
    private CountDownLatch mLatch;

    /**
     * Constructor of {@link AdvertiseManager}.
     */
    AdvertiseManager(GattService service, AdapterService adapterService) {
        logd("advertise manager created");
        mService = service;
        mAdapterService = adapterService;
        mAdvertiseClients = new HashSet<AdvertiseClient>();
        mAdvertiseNative = new AdvertiseNative();
    }

    /**
     * Start a {@link HandlerThread} that handles advertising operations.
     */
    void start() {
        HandlerThread thread = new HandlerThread("BluetoothAdvertiseManager");
        thread.start();
        mHandler = new ClientHandler(thread.getLooper());
    }

    void cleanup() {
        logd("advertise clients cleared");
        mAdvertiseClients.clear();

        if (mHandler != null) {
            // Shut down the thread
            mHandler.removeCallbacksAndMessages(null);
            Looper looper = mHandler.getLooper();
            if (looper != null) {
                looper.quit();
            }
            mHandler = null;
        }
    }

    void registerAdvertiser(UUID uuid) {
        mAdvertiseNative.registerAdvertiserNative(
            uuid.getLeastSignificantBits(), uuid.getMostSignificantBits());
    }

    void unregisterAdvertiser(int advertiserId) {
        mAdvertiseNative.unregisterAdvertiserNative(advertiserId);
    }

    /**
     * Start BLE advertising.
     *
     * @param client Advertise client.
     */
    void startAdvertising(AdvertiseClient client) {
        if (client == null) {
            return;
        }
        Message message = new Message();
        message.what = MSG_START_ADVERTISING;
        message.obj = client;
        mHandler.sendMessage(message);
    }

    /**
     * Stop BLE advertising.
     */
    void stopAdvertising(AdvertiseClient client) {
        if (client == null) {
            return;
        }
        Message message = new Message();
        message.what = MSG_STOP_ADVERTISING;
        message.obj = client;
        mHandler.sendMessage(message);
    }

    /**
     * Signals the callback is received.
     *
     * @param advertiserId Identifier for the client.
     * @param status Status of the callback.
     */
    void callbackDone(int advertiserId, int status) {
        if (status == AdvertiseCallback.ADVERTISE_SUCCESS) {
            mLatch.countDown();
        } else {
            // Note in failure case we'll wait for the latch to timeout(which takes 100ms) and
            // the mClientHandler thread will be blocked till timeout.
            postCallback(advertiserId, AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR);
        }
    }

    // Post callback status to app process.
    private void postCallback(int advertiserId, int status) {
        try {
            AdvertiseClient client = getAdvertiseClient(advertiserId);
            AdvertiseSettings settings = (client == null) ? null : client.settings;
            boolean isStart = true;
            mService.onMultipleAdvertiseCallback(advertiserId, status, isStart, settings);
        } catch (RemoteException e) {
            loge("failed onMultipleAdvertiseCallback", e);
        }
    }

    private AdvertiseClient getAdvertiseClient(int advertiserId) {
        for (AdvertiseClient client : mAdvertiseClients) {
            if (client.advertiserId == advertiserId) {
                return client;
            }
        }
        return null;
    }

    // Handler class that handles BLE advertising operations.
    private class ClientHandler extends Handler {

        ClientHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            logd("message : " + msg.what);
            AdvertiseClient client = (AdvertiseClient) msg.obj;
            switch (msg.what) {
                case MSG_START_ADVERTISING:
                    handleStartAdvertising(client);
                    break;
                case MSG_STOP_ADVERTISING:
                    handleStopAdvertising(client);
                    break;
                default:
                    // Shouldn't happen.
                    Log.e(TAG, "recieve an unknown message : " + msg.what);
                    break;
            }
        }

        private void handleStartAdvertising(AdvertiseClient client) {
            Utils.enforceAdminPermission(mService);
            int advertiserId = client.advertiserId;
            if (mAdvertiseClients.contains(client)) {
                postCallback(advertiserId, AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED);
                return;
            }

            if (mAdvertiseClients.size() >= maxAdvertiseInstances()) {
                postCallback(advertiserId,
                        AdvertiseCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS);
                return;
            }
            if (!mAdvertiseNative.startAdverising(client)) {
                postCallback(advertiserId, AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR);
                return;
            }

            mAdvertiseClients.add(client);
        }

        // Handles stop advertising.
        private void handleStopAdvertising(AdvertiseClient client) {
            Utils.enforceAdminPermission(mService);
            if (client == null) {
                return;
            }
            logd("stop advertise for client " + client.advertiserId);
            mAdvertiseNative.stopAdvertising(client);
            if (client.appDied) {
                logd("app died - unregistering client : " + client.advertiserId);
                mAdvertiseNative.unregisterAdvertiserNative(client.advertiserId);
            }
            if (mAdvertiseClients.contains(client)) {
                mAdvertiseClients.remove(client);
            }
        }

        // Returns maximum advertise instances supported by controller.
        int maxAdvertiseInstances() {
            return mAdapterService.getNumOfAdvertisementInstancesSupported();
        }
    }

    // Class that wraps advertise native related constants, methods etc.
    private class AdvertiseNative {
        // Advertise interval for different modes.
        private static final int ADVERTISING_INTERVAL_HIGH_MILLS = 1000;
        private static final int ADVERTISING_INTERVAL_MEDIUM_MILLS = 250;
        private static final int ADVERTISING_INTERVAL_LOW_MILLS = 100;

        // Add some randomness to the advertising min/max interval so the controller can do some
        // optimization.
        private static final int ADVERTISING_INTERVAL_DELTA_UNIT = 10;

        // The following constants should be kept the same as those defined in bt stack.
        private static final int ADVERTISING_CHANNEL_37 = 1 << 0;
        private static final int ADVERTISING_CHANNEL_38 = 1 << 1;
        private static final int ADVERTISING_CHANNEL_39 = 1 << 2;
        private static final int ADVERTISING_CHANNEL_ALL =
                ADVERTISING_CHANNEL_37 | ADVERTISING_CHANNEL_38 | ADVERTISING_CHANNEL_39;

        private static final int ADVERTISING_TX_POWER_MIN = 0;
        private static final int ADVERTISING_TX_POWER_LOW = 1;
        private static final int ADVERTISING_TX_POWER_MID = 2;
        private static final int ADVERTISING_TX_POWER_UPPER = 3;
        // Note this is not exposed to the Java API.
        private static final int ADVERTISING_TX_POWER_MAX = 4;

        // Note we don't expose connectable directed advertising to API.
        private static final int ADVERTISING_EVENT_TYPE_CONNECTABLE = 0;
        private static final int ADVERTISING_EVENT_TYPE_SCANNABLE = 2;
        private static final int ADVERTISING_EVENT_TYPE_NON_CONNECTABLE = 3;

        boolean startAdverising(AdvertiseClient client) {
            logd("starting advertising");
            resetCountDownLatch();
            setAdvertisingParameters(client);
            if (!waitForCallback()) {
                return false;
            }
            resetCountDownLatch();
            setAdvertisingData(client, client.advertiseData, false);
            if (!waitForCallback()) {
                return false;
            }
            if (client.scanResponse != null) {
                resetCountDownLatch();
                setAdvertisingData(client, client.scanResponse, true);
                if (!waitForCallback()) {
                    return false;
                }
            }
            resetCountDownLatch();
            enableAdvertising(client, true);
            if (!waitForCallback()) {
                return false;
            }

            return true;
        }

        void stopAdvertising(AdvertiseClient client) {
            gattClientEnableAdvNative(client.advertiserId, false, 0);
        }

        private void resetCountDownLatch() {
            mLatch = new CountDownLatch(1);
        }

        // Returns true if mLatch reaches 0, false if timeout or interrupted.
        private boolean waitForCallback() {
            try {
                return mLatch.await(OPERATION_TIME_OUT_MILLIS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                return false;
            }
        }

        private void setAdvertisingParameters(AdvertiseClient client) {
            int advertiserId = client.advertiserId;
            int minAdvertiseUnit = (int) getAdvertisingIntervalUnit(client.settings);
            int maxAdvertiseUnit = minAdvertiseUnit + ADVERTISING_INTERVAL_DELTA_UNIT;
            int advertiseEventType = getAdvertisingEventType(client);
            int txPowerLevel = getTxPowerLevel(client.settings);

            // if only legacy advertising is supported, the TX power settings wont take effect
            gattClientSetParamsNative(
                        advertiserId,
                        minAdvertiseUnit, maxAdvertiseUnit,
                        advertiseEventType,
                        ADVERTISING_CHANNEL_ALL,
                        txPowerLevel);
        }

        private void enableAdvertising(AdvertiseClient client, boolean enable) {
            int advertiserId = client.advertiserId;
            int advertiseTimeoutSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(
                    client.settings.getTimeout());
            gattClientEnableAdvNative(advertiserId, enable, advertiseTimeoutSeconds);
        }

        private static final int DEVICE_NAME_MAX = 18;

        private static final int COMPLETE_LIST_16_BIT_SERVICE_UUIDS = 0X03;
        private static final int COMPLETE_LIST_32_BIT_SERVICE_UUIDS = 0X05;
        private static final int COMPLETE_LIST_128_BIT_SERVICE_UUIDS = 0X07;
        private static final int SHORTENED_LOCAL_NAME = 0X08;
        private static final int COMPLETE_LOCAL_NAME = 0X09;
        private static final int TX_POWER_LEVEL = 0x0A;
        private static final int SERVICE_DATA_16_BIT_UUID = 0X16;
        private static final int SERVICE_DATA_32_BIT_UUID = 0X20;
        private static final int SERVICE_DATA_128_BIT_UUID = 0X21;
        private static final int MANUFACTURER_SPECIFIC_DATA = 0XFF;

        private byte[] advertiseDataToBytes(AdvertiseData data) {
            // Flags are added by lower layers of the stack, only if needed;
            // no need to add them here.

            ByteArrayOutputStream ret = new ByteArrayOutputStream();

            if (data.getIncludeDeviceName()) {
                String name = mAdapterService.getName();
                try {
                    byte[] nameBytes = name.getBytes("UTF-8");

                    int nameLength = nameBytes.length;
                    byte type;

                    // TODO(jpawlowski) put a better limit on device name!
                    if (nameLength > DEVICE_NAME_MAX) {
                      nameLength = DEVICE_NAME_MAX;
                      type = SHORTENED_LOCAL_NAME;
                    } else {
                      type = COMPLETE_LOCAL_NAME;
                    }

                    ret.write(nameLength + 1);
                    ret.write(type);
                    ret.write(nameBytes, 0, nameLength);
                } catch (java.io.UnsupportedEncodingException e) {
                    loge("Can't include name - encoding error!", e);
                }
            }

            for (int i = 0; i< data.getManufacturerSpecificData().size(); i++) {
                int manufacturerId = data.getManufacturerSpecificData().keyAt(i);

                byte[] manufacturerData = data.getManufacturerSpecificData().get(
                        manufacturerId);
                int dataLen = 2 + (manufacturerData == null ? 0 : manufacturerData.length);
                byte[] concated = new byte[dataLen];
                // First two bytes are manufacturer id in little-endian.
                concated[0] = (byte) (manufacturerId & 0xFF);
                concated[1] = (byte) ((manufacturerId >> 8) & 0xFF);
                if (manufacturerData != null) {
                    System.arraycopy(manufacturerData, 0, concated, 2, manufacturerData.length);
                }

                ret.write(concated.length + 1);
                ret.write(MANUFACTURER_SPECIFIC_DATA);
                ret.write(concated, 0, concated.length);
            }

            if (data.getIncludeTxPowerLevel()) {
                ret.write(2 /* Length */);
                ret.write(TX_POWER_LEVEL);
                ret.write(0);  // lower layers will fill this value.
            }

            if (data.getServiceUuids() != null) {
                ByteArrayOutputStream serviceUuids16 = new ByteArrayOutputStream();
                ByteArrayOutputStream serviceUuids32 = new ByteArrayOutputStream();
                ByteArrayOutputStream serviceUuids128 = new ByteArrayOutputStream();

                for (ParcelUuid parcelUuid : data.getServiceUuids()) {
                    byte[] uuid = BluetoothUuid.uuidToBytes(parcelUuid);

                    if (uuid.length == BluetoothUuid.UUID_BYTES_16_BIT) {
                        serviceUuids16.write(uuid, 0, uuid.length);
                    } else if (uuid.length == BluetoothUuid.UUID_BYTES_32_BIT) {
                        serviceUuids32.write(uuid, 0, uuid.length);
                    } else /*if (uuid.length == BluetoothUuid.UUID_BYTES_128_BIT)*/ {
                        serviceUuids128.write(uuid, 0, uuid.length);
                    }
                }

                if (serviceUuids16.size() != 0) {
                    ret.write(serviceUuids16.size() + 1);
                    ret.write(COMPLETE_LIST_16_BIT_SERVICE_UUIDS);
                    ret.write(serviceUuids16.toByteArray(), 0, serviceUuids16.size());
                }

                if (serviceUuids32.size() != 0) {
                    ret.write(serviceUuids32.size() + 1);
                    ret.write(COMPLETE_LIST_32_BIT_SERVICE_UUIDS);
                    ret.write(serviceUuids32.toByteArray(), 0, serviceUuids32.size());
                }

                if (serviceUuids128.size() != 0) {
                    ret.write(serviceUuids128.size() + 1);
                    ret.write(COMPLETE_LIST_128_BIT_SERVICE_UUIDS);
                    ret.write(serviceUuids128.toByteArray(), 0, serviceUuids128.size());
                }
            }

            if (!data.getServiceData().isEmpty()) {
                for (ParcelUuid parcelUuid: data.getServiceData().keySet()) {
                    byte[] serviceData = data.getServiceData().get(parcelUuid);

                    byte[] uuid = BluetoothUuid.uuidToBytes(parcelUuid);
                    int uuidLen = uuid.length;

                    int dataLen = uuidLen + (serviceData == null ? 0 : serviceData.length);
                    byte[] concated = new byte[dataLen];

                    System.arraycopy(uuid, 0, concated, 0, uuidLen);

                    if (serviceData != null) {
                        System.arraycopy(serviceData, 0, concated, uuidLen, serviceData.length);
                    }

                    if (uuid.length == BluetoothUuid.UUID_BYTES_16_BIT) {
                        ret.write(concated.length + 1);
                        ret.write(SERVICE_DATA_16_BIT_UUID);
                        ret.write(concated, 0, concated.length);
                    } else if (uuid.length == BluetoothUuid.UUID_BYTES_32_BIT) {
                        ret.write(concated.length + 1);
                        ret.write(SERVICE_DATA_32_BIT_UUID);
                        ret.write(concated, 0, concated.length);
                    } else /*if (uuid.length == BluetoothUuid.UUID_BYTES_128_BIT)*/ {
                        ret.write(concated.length + 1);
                        ret.write(SERVICE_DATA_128_BIT_UUID);
                        ret.write(concated, 0, concated.length);
                    }
                }
            }

            return ret.toByteArray();
        }

        private void setAdvertisingData(AdvertiseClient client, AdvertiseData data,
                boolean isScanResponse) {
            if (data == null) {
                return;
            }

            byte [] data_out = advertiseDataToBytes(data);
            gattClientSetAdvDataNative(client.advertiserId, isScanResponse, data_out);
        }

        // Convert settings tx power level to stack tx power level.
        private int getTxPowerLevel(AdvertiseSettings settings) {
            switch (settings.getTxPowerLevel()) {
                case AdvertiseSettings.ADVERTISE_TX_POWER_ULTRA_LOW:
                    return ADVERTISING_TX_POWER_MIN;
                case AdvertiseSettings.ADVERTISE_TX_POWER_LOW:
                    return ADVERTISING_TX_POWER_LOW;
                case AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM:
                    return ADVERTISING_TX_POWER_MID;
                case AdvertiseSettings.ADVERTISE_TX_POWER_HIGH:
                    return ADVERTISING_TX_POWER_UPPER;
                default:
                    // Shouldn't happen, just in case.
                    return ADVERTISING_TX_POWER_MID;
            }
        }

        // Convert advertising event type to stack values.
        private int getAdvertisingEventType(AdvertiseClient client) {
            AdvertiseSettings settings = client.settings;
            if (settings.isConnectable()) {
                return ADVERTISING_EVENT_TYPE_CONNECTABLE;
            }
            return client.scanResponse == null ? ADVERTISING_EVENT_TYPE_NON_CONNECTABLE
                    : ADVERTISING_EVENT_TYPE_SCANNABLE;
        }

        // Convert advertising milliseconds to advertising units(one unit is 0.625 millisecond).
        private long getAdvertisingIntervalUnit(AdvertiseSettings settings) {
            switch (settings.getMode()) {
                case AdvertiseSettings.ADVERTISE_MODE_LOW_POWER:
                    return Utils.millsToUnit(ADVERTISING_INTERVAL_HIGH_MILLS);
                case AdvertiseSettings.ADVERTISE_MODE_BALANCED:
                    return Utils.millsToUnit(ADVERTISING_INTERVAL_MEDIUM_MILLS);
                case AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY:
                    return Utils.millsToUnit(ADVERTISING_INTERVAL_LOW_MILLS);
                default:
                    // Shouldn't happen, just in case.
                    return Utils.millsToUnit(ADVERTISING_INTERVAL_HIGH_MILLS);
            }
        }

        // Native functions

        private native void registerAdvertiserNative(long app_uuid_lsb,
                                                     long app_uuid_msb);

        private native void unregisterAdvertiserNative(int advertiserId);

        private native void gattClientSetParamsNative(int advertiserId,
                int min_interval, int max_interval, int adv_type, int chnl_map, int tx_power);

        private native void gattClientSetAdvDataNative(int advertiserId,
                boolean set_scan_rsp, byte[] data);

        private native void gattClientEnableAdvNative(int advertiserId,
                boolean enable, int timeout_s);
    }

    private void logd(String s) {
        if (DBG) {
            Log.d(TAG, s);
        }
    }

    private void loge(String s, Exception e) {
        Log.e(TAG, s, e);
    }

}
