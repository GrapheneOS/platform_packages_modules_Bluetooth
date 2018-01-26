/*
 * Copyright (C) 2018 The Android Open Source Project
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

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.hfp.HeadsetService;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * The active device manager is responsible for keeping track of the
 * connected A2DP/HFP/AVRCP devices and select which device is
 * active (for each profile).
 *
 * Current policy (subject to change):
 * 1) If the maximum number of connected devices is one, the manager doesn't
 *    do anything. Each profile is responsible for automatically selecting
 *    the connected device as active. Only if the maximum number of connected
 *    devices is more than one, the rules below will apply.
 * 2) The selected A2DP active device is the one used for AVRCP as well.
 * 3) The HFP active device might be different from the A2DP active device.
 * 4) The Active Device Manager always listens for
 *    ACTION_ACTIVE_DEVICE_CHANGED broadcasts for each profile:
 *    - BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED for A2DP
 *    - BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED for HFP
 *    If such broadcast is received (e.g., triggered indirectly by user
 *    action on the UI), the device in the received broacast is marked
 *    as the current active device for that profile.
 * 5) If there are no connected devices (e.g., during startup, or after all
 *    devices have been disconnected, the active device per profile
 *    (either A2DP or HFP) is selected as follows:
 * 5.1) The first connected device (for either A2DP or HFP) is immediately
 *      selected as active for that profile. Assume the first connected device
 *      is for A2DP.
 * 5.2) A timer is started: if the same device is connected for the other
 *      profile as well (HFP in this example) while the timer is running,
 *      and there is no active HFP device yet, that device is selected as
 *      active for HFP as well. The purpose is to select by default the same
 *      device as active for both profiles.
 * 5.3) While the timer is running, all other HFP connected devices are
 *      listed locally, but none of those devices is selected as active.
 * 5.4) While the timer is running, if ACTION_ACTIVE_DEVICE_CHANGED broadcast
 *      is received for HFP, the device contained in the broadcast is
 *      marked as active.
 * 5.5) If the timer expires and no HFP device has been selected as active,
 *      the first HFP connected device is selected as active.
 * 6) If the currently active device (per profile) is disconnected, the
 *    Active Device Manager just marks that the profile has no active device,
 *    but does not attempt to select a new one. Currently, the expectation is
 *    that the user will explicitly select the new active device.
 * 7) If there is already an active device, and the corresponding
 *    ACTION_ACTIVE_DEVICE_CHANGED broadcast is received, the device
 *    contained in the broadcast is marked as active. However, if
 *    the contained device is null, the corresponding profile is marked
 *    as having no active device.
 */
class ActiveDeviceManager {
    private static final boolean DBG = true;
    private static final String TAG = "BluetoothActiveDeviceManager";

    // Message types for the handler
    private static final int MESSAGE_ADAPTER_ACTION_STATE_CHANGED = 1;
    private static final int MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT = 2;
    private static final int MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED = 3;
    private static final int MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED = 4;
    private static final int MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED = 5;
    private static final int MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED = 6;

    // Timeouts
    private static final int SELECT_ACTIVE_DEVICE_TIMEOUT_MS = 6000; // 6s

    private final AdapterService mAdapterService;
    private final ServiceFactory mFactory;
    private HandlerThread mHandlerThread = null;
    private Handler mHandler = null;

    private final List<BluetoothDevice> mA2dpConnectedDevices = new LinkedList<>();
    private final List<BluetoothDevice> mHfpConnectedDevices = new LinkedList<>();
    private BluetoothDevice mA2dpActiveDevice = null;
    private BluetoothDevice mHfpActiveDevice = null;

    // Broadcast receiver for all changes
    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) {
                Log.e(TAG, "Received intent with null action");
                return;
            }
            switch (action) {
                case BluetoothAdapter.ACTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_ADAPTER_ACTION_STATE_CHANGED,
                                           intent).sendToTarget();
                    break;
                case BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED,
                                           intent).sendToTarget();
                    break;
                case BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED,
                                           intent).sendToTarget();
                    break;
                case BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED,
                                           intent).sendToTarget();
                    break;
                default:
                    Log.e(TAG, "Received unexpected intent, action=" + action);
                    break;
            }
        }
    };

    class ActivePoliceManagerHandler extends Handler {
        ActivePoliceManagerHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MESSAGE_ADAPTER_ACTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    int newState = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_ADAPTER_ACTION_STATE_CHANGED): newState="
                                + newState);
                    }
                    if (newState == BluetoothAdapter.STATE_ON) {
                        resetState();
                    }
                }
                break;

                case MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT: {
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT)");
                    }
                    // Set the first connected device as active
                    if ((mA2dpActiveDevice == null) && !mA2dpConnectedDevices.isEmpty()) {
                        setA2dpActiveDevice(mA2dpConnectedDevices.get(0));
                    }
                    if ((mHfpActiveDevice == null) && !mHfpConnectedDevices.isEmpty()) {
                        setHfpActiveDevice(mHfpConnectedDevices.get(0));
                    }
                }
                break;

                case MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " connected");
                        }
                        if (mA2dpConnectedDevices.contains(device)) {
                            break;
                        }
                        if (!hasConnectedDevices()) {
                            // First connected device: select it as active and start the timer
                            mA2dpConnectedDevices.add(device);
                            Message m = obtainMessage(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT);
                            sendMessageDelayed(m, SELECT_ACTIVE_DEVICE_TIMEOUT_MS);
                            setA2dpActiveDevice(device);
                            break;
                        }
                        mA2dpConnectedDevices.add(device);
                        // Check whether the active device for the other profile is same
                        if ((mA2dpActiveDevice == null) && matchesActiveDevice(device)) {
                            setA2dpActiveDevice(device);
                            break;
                        }
                        // Check whether the active device selection timer is not running
                        if ((mA2dpActiveDevice == null)
                                && !hasMessages(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT)) {
                            setA2dpActiveDevice(mA2dpConnectedDevices.get(0));
                            break;
                        }
                        break;
                    }
                    if ((prevState == BluetoothProfile.STATE_CONNECTED)
                            && (nextState != prevState)) {
                        // Device disconnected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " disconnected");
                        }
                        mA2dpConnectedDevices.remove(device);
                        if (Objects.equals(mA2dpActiveDevice, device)) {
                            setA2dpActiveDevice(null);
                        }
                    }
                }
                break;

                case MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    removeMessages(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT);
                    // Just assign locally the new value
                    mA2dpActiveDevice = device;
                }
                break;

                case MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    // TODO: Copy the corresponding logic from the processing of
                    // message MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED
                }
                break;

                case MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    removeMessages(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT);
                    // Just assign locally the new value
                    mHfpActiveDevice = device;
                }
                break;
            }
        }
    }

    ActiveDeviceManager(AdapterService service, ServiceFactory factory) {
        mAdapterService = service;
        mFactory = factory;
    }

    void start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }

        mHandlerThread = new HandlerThread("BluetoothActiveDeviceManager");
        mHandlerThread.start();
        mHandler = new ActivePoliceManagerHandler(mHandlerThread.getLooper());

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED);
        mAdapterService.registerReceiver(mReceiver, filter);
    }

    void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }

        mAdapterService.unregisterReceiver(mReceiver);
        if (mHandlerThread != null) {
            mHandlerThread.quit();
            mHandlerThread = null;
        }
        resetState();
    }

    private void setA2dpActiveDevice(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "setA2dpActiveDevice(" + device + ")");
        }
        final A2dpService a2dpService = mFactory.getA2dpService();
        if (a2dpService == null) {
            return;
        }
        if (!a2dpService.setActiveDevice(device)) {
            return;
        }
        mA2dpActiveDevice = device;
    }

    private void setHfpActiveDevice(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "setHfpActiveDevice(" + device + ")");
        }
        final HeadsetService headsetService = mFactory.getHeadsetService();
        if (headsetService == null) {
            return;
        }
        if (!headsetService.setActiveDevice(device)) {
            return;
        }
        mHfpActiveDevice = device;
    }

    private boolean hasConnectedDevices() {
        return (!mA2dpConnectedDevices.isEmpty() || !mHfpConnectedDevices.isEmpty());
    }

    private boolean matchesActiveDevice(BluetoothDevice device) {
        return (Objects.equals(mA2dpActiveDevice, device)
                || Objects.equals(mHfpActiveDevice, device));
    }

    private void resetState() {
        if (mHandler != null) {
            mHandler.removeMessages(MESSAGE_SELECT_ACTICE_DEVICE_TIMEOUT);
        }
        mA2dpConnectedDevices.clear();
        mA2dpActiveDevice = null;

        mHfpConnectedDevices.clear();
        mHfpActiveDevice = null;
    }
}
