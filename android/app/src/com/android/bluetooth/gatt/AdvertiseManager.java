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

import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseSettings;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
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
    }

    // Class that wraps advertise native related constants, methods etc.
    private class AdvertiseNative {

        // Add some randomness to the advertising min/max interval so the controller can do some
        // optimization.
        private static final int ADVERTISING_INTERVAL_DELTA_UNIT = 10;

        // The following constants should be kept the same as those defined in bt stack.
        private static final int ADVERTISING_CHANNEL_37 = 1 << 0;
        private static final int ADVERTISING_CHANNEL_38 = 1 << 1;
        private static final int ADVERTISING_CHANNEL_39 = 1 << 2;
        private static final int ADVERTISING_CHANNEL_ALL =
            ADVERTISING_CHANNEL_37 | ADVERTISING_CHANNEL_38 | ADVERTISING_CHANNEL_39;

        boolean startAdverising(AdvertiseClient client) {
            logd("starting advertising");

            int advertiserId = client.advertiserId;
            int minAdvertiseUnit = (int) AdvertiseHelper.getAdvertisingIntervalUnit(client.settings);
            int maxAdvertiseUnit = minAdvertiseUnit + ADVERTISING_INTERVAL_DELTA_UNIT;
            int advertiseEventType = AdvertiseHelper.getAdvertisingEventType(client);
            int txPowerLevel = AdvertiseHelper.getTxPowerLevel(client.settings);

            byte [] adv_data = AdvertiseHelper.advertiseDataToBytes(client.advertiseData,
                                                                    mAdapterService.getName());
            byte [] scan_resp_data = AdvertiseHelper.advertiseDataToBytes(client.scanResponse,
                                                                          mAdapterService.getName());

            int advertiseTimeoutSeconds = (int) TimeUnit.MILLISECONDS.toSeconds(
                    client.settings.getTimeout());

            resetCountDownLatch();

            startAdvertiserNative(advertiserId, minAdvertiseUnit, maxAdvertiseUnit,
                    advertiseEventType, ADVERTISING_CHANNEL_ALL, txPowerLevel, adv_data,
                    scan_resp_data, advertiseTimeoutSeconds);
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

        // Native functions

        private native void registerAdvertiserNative(long app_uuid_lsb,
                                                     long app_uuid_msb);

        private native void unregisterAdvertiserNative(int advertiserId);

        private native void gattClientEnableAdvNative(int advertiserId,
                boolean enable, int timeout_s);

        private native void startAdvertiserNative(int advertiserId,
                int min_interval, int max_interval, int adv_type, int chnl_map, int tx_power,
                byte[] adv_data, byte[] scan_resp_data, int timeout_s);

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
