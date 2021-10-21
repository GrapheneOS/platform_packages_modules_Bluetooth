/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
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

/**
 * Bluetooth VCP StateMachine. There is one instance per remote device.
 *  - "Disconnected" and "Connected" are steady states.
 *  - "Connecting" and "Disconnecting" are transient states until the
 *     connection / disconnection is completed.
 *
 *
 *                        (Disconnected)
 *                           |       ^
 *                   CONNECT |       | DISCONNECTED
 *                           V       |
 *                 (Connecting)<--->(Disconnecting)
 *                           |       ^
 *                 CONNECTED |       | DISCONNECT
 *                           V       |
 *                          (Connected)
 * NOTES:
 *  - If state machine is in "Connecting" state and the remote device sends
 *    DISCONNECT request, the state machine transitions to "Disconnecting" state.
 *  - Similarly, if the state machine is in "Disconnecting" state and the remote device
 *    sends CONNECT request, the state machine transitions to "Connecting" state.
 *
 *                    DISCONNECT
 *    (Connecting) ---------------> (Disconnecting)
 *                 <---------------
 *                      CONNECT
 *
 */

package com.android.bluetooth.vcp;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import com.android.bluetooth.Utils;
import android.bluetooth.BluetoothVcp;
import android.content.Context;
import android.content.Intent;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;

final class VcpControllerStateMachine extends StateMachine {
    private static final boolean DBG = true;
    private static final String TAG = "VcpControllerStateMachine";

    static final int CONNECT = 1;
    static final int DISCONNECT = 2;
    static final int SET_VOLUME = 3;
    static final int MUTE = 4;
    static final int UNMUTE = 5;

    @VisibleForTesting
    static final int STACK_EVENT = 101;
    private static final int CONNECT_TIMEOUT = 201;
    private static final int SET_ABS_VOL_TIMEOUT = 202;
    private static final int CHANGE_MUTE_TIMEOUT = 203;

    private static final int UNMUTE_STATE = 0;
    private static final int MUTE_STATE = 1;
    private static final int VOLUME_SETTING_NOT_PERSISTED = 0x00;
    private static final int VOLUME_SETTING_PERSISTED = 0x01;

    private static final int MAX_ERROR_RETRY_TIMES = 3;
    private static final int VCP_MAX_VOL = 255;
    // The default VCP volume 0x77 (119)
    private static final int VCP_DEFAULT_VOL = 119;
    private static final int CMD_TIMEOUT_DELAY = 2000;


    // NOTE: the value is not "final" - it is modified in the unit tests
    @VisibleForTesting
    static int sConnectTimeoutMs = 30000;        // 30s

    private Disconnected mDisconnected;
    private Connecting mConnecting;
    private Disconnecting mDisconnecting;
    private Connected mConnected;
    private int mLastConnectionState = -1;

    private VcpController mVcpController;
    private VcpControllerNativeInterface mNativeInterface;
    private Context mContext;

    /* Current remote volume */
    private int mRemoteVolume;
    /* Requested volume in progress of Native Layer setAbsVolume */
    private int mRequestedVolume;
    /* Cached new volume if has a requested volume in progress */
    private int mCachedVolume;
    private int mAbsVolRetryTimes;
    private boolean mAbsVolSetInProgress;

    /* Current remote mute state */
    private int mMuteState;
    /* Requested mute state in progress of Native Layer mute/unMute */
    private int mRequestedMuteState;
    /* Cached new mute state if has a requested mute state in progress */
    private int mCachedMuteState;
    private int mChangeMuteRetryTimes;
    private boolean mMuteChangeInProgress;

    private int mVolumeFlags;
    private final BluetoothDevice mDevice;
    private int mVolumeControlAudioType;
    private int mCachedVolumeControlAudioType;

    VcpControllerStateMachine(BluetoothDevice device, VcpController svc, Context context,
            VcpControllerNativeInterface nativeInterface, Looper looper) {
        super(TAG, looper);
        mDevice = device;
        mVcpController = svc;
        mContext = context;
        mNativeInterface = nativeInterface;

        mDisconnected = new Disconnected();
        mConnecting = new Connecting();
        mDisconnecting = new Disconnecting();
        mConnected = new Connected();

        addState(mDisconnected);
        addState(mConnecting);
        addState(mDisconnecting);
        addState(mConnected);

        setInitialState(mDisconnected);
    }

    static VcpControllerStateMachine make(BluetoothDevice device, VcpController svc,
            Context context, VcpControllerNativeInterface nativeInterface, Looper looper) {
        Log.i(TAG, "make for device " + device);
        VcpControllerStateMachine VcpControllerSm =
                new VcpControllerStateMachine(device, svc, context, nativeInterface, looper);
        VcpControllerSm.start();
        return VcpControllerSm;
    }

    public void doQuit() {
        log("doQuit for device " + mDevice);
        quitNow();
    }

    public void cleanup() {
        log("cleanup for device " + mDevice);
    }

    @VisibleForTesting
    class Disconnected extends State {
        @Override
        public void enter() {
            Log.i(TAG, "Enter Disconnected(" + mDevice + "): " + messageWhatToString(
                    getCurrentMessage().what));

            removeDeferredMessages(DISCONNECT);
            if (mLastConnectionState != -1) {
                // Don't broadcast during startup
                broadcastConnectionState(BluetoothProfile.STATE_DISCONNECTED,
                        mLastConnectionState);
            }

            cleanupDevice();
        }

        @Override
        public void exit() {
            log("Exit Disconnected(" + mDevice + "): " + messageWhatToString(
                    getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Disconnected process message(" + mDevice + "): " + messageWhatToString(
                    message.what));

            switch (message.what) {
                case CONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    log("Connecting to " + device);

                    if (!mDevice.equals(device)) {
                        Log.e(TAG, "CONNECT failed, device=" + device + ", currentDev=" + mDevice);
                        break;
                    }

                    if (!mNativeInterface.connectVcp(mDevice, true)) {
                        Log.e(TAG, "Disconnected: error connecting to " + mDevice);
                        break;
                    }

                    transitionTo(mConnecting);
                    break;
                case DISCONNECT:
                    Log.w(TAG, "Disconnected: DISCONNECT ignored: " + mDevice);
                    break;
                case STACK_EVENT:
                    VcpStackEvent event = (VcpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Disconnected: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                        break;
                    }
                    switch (event.type) {
                        case VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        default:
                            Log.e(TAG, "Disconnected: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    Log.e(TAG, "Unexpected msg " + messageWhatToString(message.what)
                            + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnected state
        private void processConnectionEvent(int state) {
            switch (state) {
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Ignore VCP DISCONNECTED event: " + mDevice);
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTING:
                    Log.i(TAG, "Incoming VCP Connecting request accepted: " + mDevice);
                    if (mVcpController.okToConnect(mDevice)) {
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming VCP Connecting request rejected: " + mDevice);
                        mNativeInterface.disconnectVcp(mDevice);
                    }
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTED:
                    Log.w(TAG, "VCP Connected from Disconnected state: " + mDevice);
                    if (mVcpController.okToConnect(mDevice)) {
                        Log.i(TAG, "Incoming VCP Connected request accepted: " + mDevice);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming VCP Connected request rejected: " + mDevice);
                        mNativeInterface.disconnectVcp(mDevice);
                    }
                    break;
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.w(TAG, "Ignore VCP DISCONNECTING event: " + mDevice);
                    break;
                default:
                    Log.e(TAG, "Incorrect state: " + state + " device: " + mDevice);
                    break;
            }
        }
    }

    @VisibleForTesting
    class Connecting extends State {
        @Override
        public void enter() {
            Log.i(TAG, "Enter Connecting(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            sendMessageDelayed(CONNECT_TIMEOUT, mDevice, sConnectTimeoutMs);
            broadcastConnectionState(BluetoothProfile.STATE_CONNECTING, mLastConnectionState);
        }

        @Override
        public void exit() {
            log("Exit Connecting(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_CONNECTING;
            removeMessages(CONNECT_TIMEOUT);
        }

        @Override
        public boolean processMessage(Message message) {
            log("Connecting process message(" + mDevice + "): "
                    + messageWhatToString(message.what));

            switch (message.what) {
                case CONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT:
                    Log.w(TAG, "Connecting connection timeout: " + mDevice);
                    mNativeInterface.disconnectVcp(mDevice);
                    // We timed out trying to connect, transition to Disconnected state
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.e(TAG, "Unknown device timeout " + device);
                        break;
                    }
                    Log.w(TAG, "CONNECT_TIMEOUT");
                    transitionTo(mDisconnected);
                    break;
                case DISCONNECT:
                    log("Connecting: connection canceled to " + mDevice);
                    mNativeInterface.disconnectVcp(mDevice);
                    transitionTo(mDisconnected);
                    break;
                case SET_VOLUME:
                case MUTE:
                case UNMUTE:
                case SET_ABS_VOL_TIMEOUT:
                case CHANGE_MUTE_TIMEOUT:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    VcpStackEvent event = (VcpStackEvent) message.obj;
                    log("Connecting: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        default:
                            Log.e(TAG, "Connecting: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Connecting state
        private void processConnectionEvent(int state) {
            switch (state) {
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Connecting device disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTED:
                    transitionTo(mConnected);
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTING:
                    break;
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.w(TAG, "Connecting interrupted: device is disconnecting: " + mDevice);
                    transitionTo(mDisconnecting);
                    break;
                default:
                    Log.e(TAG, "Incorrect state: " + state);
                    break;
            }
        }
    }

    @VisibleForTesting
    class Disconnecting extends State {
        @Override
        public void enter() {
            Log.i(TAG, "Enter Disconnecting(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            sendMessageDelayed(CONNECT_TIMEOUT, mDevice, sConnectTimeoutMs);
            broadcastConnectionState(BluetoothProfile.STATE_DISCONNECTING, mLastConnectionState);
        }

        @Override
        public void exit() {
            log("Exit Disconnecting(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTING;
            removeMessages(CONNECT_TIMEOUT);
        }

        @Override
        public boolean processMessage(Message message) {
            log("Disconnecting process message(" + mDevice + "): "
                    + messageWhatToString(message.what));

            switch (message.what) {
                case CONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    Log.w(TAG, "Disconnecting connection timeout: " + mDevice);
                    mNativeInterface.disconnectVcp(mDevice);
                    // We timed out trying to connect, transition to Disconnected state
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.e(TAG, "Unknown device timeout " + device);
                        break;
                    }
                    transitionTo(mDisconnected);
                    Log.w(TAG, "CONNECT_TIMEOUT");
                    break;
                }
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case SET_VOLUME:
                case MUTE:
                case UNMUTE:
                case SET_ABS_VOL_TIMEOUT:
                case CHANGE_MUTE_TIMEOUT:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    VcpStackEvent event = (VcpStackEvent) message.obj;
                    log("Disconnecting: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        default:
                            Log.e(TAG, "Disconnecting: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnecting state
        private void processConnectionEvent(int state) {
            switch (state) {
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTED:
                    if (mVcpController.okToConnect(mDevice)) {
                        Log.w(TAG, "Disconnecting interrupted: device is connected: " + mDevice);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming VCP Connected request rejected: " + mDevice);
                        mNativeInterface.disconnectVcp(mDevice);
                    }
                    break;
                case VcpStackEvent.CONNECTION_STATE_CONNECTING:
                    if (mVcpController.okToConnect(mDevice)) {
                        Log.i(TAG, "Disconnecting interrupted: try to reconnect: " + mDevice);
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming VCP Connecting request rejected: " + mDevice);
                        mNativeInterface.disconnectVcp(mDevice);
                    }
                    break;
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    break;
                default:
                    Log.e(TAG, "Incorrect state: " + state);
                    break;
            }
        }
    }

    @VisibleForTesting
    class Connected extends State {
        @Override
        public void enter() {
            Log.i(TAG, "Enter Connected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            removeDeferredMessages(CONNECT);
            broadcastConnectionState(BluetoothProfile.STATE_CONNECTED, mLastConnectionState);
        }

        @Override
        public void exit() {
            log("Exit Connected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_CONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Connected process message(" + mDevice + "): "
                    + messageWhatToString(message.what));

            switch (message.what) {
                case CONNECT: {
                    Log.w(TAG, "Connected: CONNECT ignored: " + mDevice);
                    break;
                }
                case DISCONNECT: {
                    log("Disconnecting from " + mDevice);
                    if (!mNativeInterface.disconnectVcp(mDevice)) {
                        // If error in the native stack, transition directly to Disconnected state.
                        Log.e(TAG, "Connected: error disconnecting from " + mDevice);
                        transitionTo(mDisconnected);
                        break;
                    }
                    transitionTo(mDisconnecting);
                    break;
                }
                case SET_VOLUME: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.w(TAG, "SET_VOLUME failed " + device
                                + " is not currentDevice");
                        break;
                    }
                    log("Set volume for " + device);

                    processSetAbsVolume(message.arg1, message.arg2);
                    break;
                }
                case MUTE: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.w(TAG, "Mute failed " + device
                                + " is not currentDevice");
                        break;
                    }
                    log("Mute for " + device);

                    processSetMute();
                    break;
                }
                case UNMUTE: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.w(TAG, "Unmute failed " + device
                                + " is not currentDevice");
                        break;
                    }
                    log("Unmute for " + device);

                    processSetUnmute();
                    break;
                }
                case SET_ABS_VOL_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.w(TAG, "Set abs vol timeout failed " + device
                                + " is not currentDevice");
                        break;
                    }

                    mAbsVolSetInProgress = false;
                    if (mAbsVolRetryTimes >= MAX_ERROR_RETRY_TIMES) {
                        Log.w(TAG, "Set abs vol retry exceed max times");
                        mRequestedVolume = -1;
                        mAbsVolRetryTimes = 0;
                        break;
                    } else {
                        mAbsVolRetryTimes += 1;
                        if (mNativeInterface.setAbsVolume(mRequestedVolume, mDevice)) {
                            sendMessageDelayed(SET_ABS_VOL_TIMEOUT, mDevice,
                                                            CMD_TIMEOUT_DELAY);
                            mAbsVolSetInProgress = true;
                        } else {
                            mRequestedVolume = -1;
                            mAbsVolRetryTimes = 0;
                            Log.e(TAG, "Set absolute volume failed for device: " + mDevice);
                        }
                    }
                    break;
                }
                case CHANGE_MUTE_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                        Log.w(TAG, "Mute timeout failed " + device
                                + " is not currentDevice");
                        break;
                    }

                    mMuteChangeInProgress = false;
                    if (mChangeMuteRetryTimes >= MAX_ERROR_RETRY_TIMES) {
                        Log.w(TAG, "Mute retry exceed max times");
                        mChangeMuteRetryTimes = 0;
                        mRequestedMuteState = -1;
                        break;
                    } else {
                        mChangeMuteRetryTimes += 1;
                        boolean ret;
                        if (mRequestedMuteState == MUTE_STATE) {
                            ret = mNativeInterface.mute(mDevice);
                        } else {
                            ret = mNativeInterface.unmute(mDevice);
                        }

                        if (ret) {
                            sendMessageDelayed(CHANGE_MUTE_TIMEOUT, mDevice,
                                                            CMD_TIMEOUT_DELAY);
                            mMuteChangeInProgress = true;
                        } else {
                            mChangeMuteRetryTimes = 0;
                            mRequestedMuteState = -1;
                           Log.e(TAG, "Change Mute failed for device: " + mDevice);
                        }
                    }
                    break;
                }
                case STACK_EVENT:
                    VcpStackEvent event = (VcpStackEvent) message.obj;
                    log("Connected: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        case VcpStackEvent.EVENT_TYPE_VOLUME_STATE_CHANGED:
                                processVolumeStateEvent(event.valueInt1, event.valueInt2);
                            break;
                        case VcpStackEvent.EVENT_TYPE_VOLUME_FLAGS_CHANGED:
                            processVolumeFlagsChanged(event.valueInt1);
                            break;
                        default:
                            Log.e(TAG, "Connected: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Connected state
        private void processConnectionEvent(int state) {
            switch (state) {
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected from " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case VcpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.i(TAG, "Disconnecting from " + mDevice);
                    transitionTo(mDisconnecting);
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + mDevice + " bad state: " + state);
                    break;
            }
        }
    }

    private void processSetAbsVolume(int volume, int audioType) {
        log("process set absolute volume");

        if (mAbsVolSetInProgress) {
            mCachedVolume = volume;
            mCachedVolumeControlAudioType = audioType;
            Log.w(TAG, "There is already a volume command in progress, cache volume:  " +
                    mCachedVolume + " cached audio type: " + audioType);
            return;
        }

        if (mRemoteVolume == -1) {
            Log.w(TAG, "remote not tell initial volume");
            return;
        }

        if (mRemoteVolume == volume) {
            Log.w(TAG, "Ignore set abs volume as current volume equals to requested volume");
            return;
        }

        Log.d(TAG, "set abs volume for audio type: " + audioType);
        if (mNativeInterface.setAbsVolume(volume, mDevice)) {
            sendMessageDelayed(SET_ABS_VOL_TIMEOUT, mDevice,
                                                CMD_TIMEOUT_DELAY);
            mAbsVolSetInProgress = true;
            mRequestedVolume = volume;
            mVolumeControlAudioType = audioType;
            mCachedVolume = -1;
        } else {
            Log.e(TAG, "Set absolute volume failed for device: " + mDevice);
        }
    }

    private void processSetMute() {
        log("process mute");

        if (mMuteChangeInProgress) {
            mCachedMuteState = MUTE_STATE;
            Log.w(TAG, "There is already a mute change in progress, cache mute");
            return;
        }

        if (mRemoteVolume == -1) {
            Log.w(TAG, "remote not tell initial volume");
            return;
        }

        if (mMuteState == MUTE_STATE) {
            Log.w(TAG, "Ignore mute request as current state is mute");
            return;
        }

        if (mNativeInterface.mute(mDevice)) {
            sendMessageDelayed(CHANGE_MUTE_TIMEOUT, mDevice,
                                                CMD_TIMEOUT_DELAY);
            mMuteChangeInProgress = true;
            mRequestedMuteState = MUTE_STATE;
            mCachedMuteState = -1;
        } else {
            Log.e(TAG, "Mute failed for device: " + mDevice);
        }
    }

    private void processSetUnmute() {
        log("process unmute");

        if (mMuteChangeInProgress) {
            mCachedMuteState = UNMUTE_STATE;
            Log.w(TAG, "There is already a mute change in progress, cache unmute");
            return;
        }

        if (mRemoteVolume == -1) {
            Log.w(TAG, "remote not tell initial volume");
            return;
        }

        if (mMuteState == UNMUTE_STATE) {
            Log.w(TAG, "Ignore unmute request as current state is unmute");
            return;
        }

        if (mNativeInterface.unmute(mDevice)) {
            sendMessageDelayed(CHANGE_MUTE_TIMEOUT, mDevice,
                                                CMD_TIMEOUT_DELAY);
            mMuteChangeInProgress = true;
            mRequestedMuteState = UNMUTE_STATE;
            mCachedMuteState = -1;
        } else {
            Log.e(TAG, "Unmute failed for device: " + mDevice);
        }
    }

    private void processVolumeStateEvent(int vcpVol, int mute) {
        log("process volume state event");

        if (mRemoteVolume == -1 || mMuteState != mute ||
                mMuteChangeInProgress == true) {
            processMuteChanged(mute);
        }

        if (mRemoteVolume == -1 || mRemoteVolume != vcpVol ||
                mAbsVolSetInProgress == true) {
            processVolumeChanged(vcpVol);
        }
    }

    private void processVolumeChanged(int vcpVol) {
        log("process volume setting changed");

        if (mAbsVolSetInProgress == true) {
            mAbsVolSetInProgress = false;
            removeMessages(SET_ABS_VOL_TIMEOUT);
            if (mRequestedVolume == vcpVol) {
                mRequestedVolume = -1;
                mAbsVolRetryTimes = 0;

                if ((mCachedVolume != -1) && (mCachedVolume != vcpVol)) {
                    mVcpController.notifyVolumeChanged(mDevice, vcpVol, mVolumeControlAudioType);
                    mVolumeControlAudioType = -1;
                    Log.w(TAG, "Set cached volume to remote");
                    if (mNativeInterface.setAbsVolume(mCachedVolume, mDevice)) {
                        sendMessageDelayed(SET_ABS_VOL_TIMEOUT, mDevice,
                                CMD_TIMEOUT_DELAY);
                        mAbsVolSetInProgress = true;
                        mRequestedVolume = mCachedVolume;
                        mVolumeControlAudioType = mCachedVolumeControlAudioType;
                        mCachedVolumeControlAudioType = -1;
                        mCachedVolume = -1;
                        return;
                    } else {
                        Log.e(TAG, "Set cached volume failed for device: " + mDevice);
                        mCachedVolume = -1;
                    }
                }
            } else {
                Log.w(TAG, "Remote changed volume not equal to requested volume");
                if (mAbsVolRetryTimes >= MAX_ERROR_RETRY_TIMES) {
                    Log.w(TAG, "Set abs vol retry exceed max times");
                    mRequestedVolume = -1;
                    mAbsVolRetryTimes = 0;
                } else {
                    mAbsVolRetryTimes += 1;
                    if (mNativeInterface.setAbsVolume(mRequestedVolume, mDevice)) {
                        sendMessageDelayed(SET_ABS_VOL_TIMEOUT, mDevice,
                                CMD_TIMEOUT_DELAY);
                        mAbsVolSetInProgress = true;
                        return;
                    } else {
                        Log.e(TAG, "Set absolute volume failed for device: " + mDevice);
                        mRequestedVolume = -1;
                        mAbsVolRetryTimes = 0;
                    }
                }
            }
        }

        if (mRemoteVolume == -1) {
            // Set initial volume if volume flags is not persisted
            if ((mVolumeFlags == VOLUME_SETTING_NOT_PERSISTED)) {
                int initialVolume = VCP_DEFAULT_VOL;
                if (vcpVol != initialVolume) {
                    mRemoteVolume = vcpVol;
                    Log.w(TAG, "Set initial volume to remote if volume persisted flag is false");
                    if (mNativeInterface.setAbsVolume(initialVolume, mDevice)) {
                        sendMessageDelayed(SET_ABS_VOL_TIMEOUT, mDevice,
                                                            CMD_TIMEOUT_DELAY);
                        mAbsVolSetInProgress = true;
                        mRequestedVolume = initialVolume;
                        mVcpController.setAbsVolumeSupport(mDevice, true, initialVolume);
                        mVcpController.updateConnState(mDevice, BluetoothProfile.STATE_CONNECTED);
                        return;
                    } else {
                        Log.e(TAG, "Set absolute volume failed for device: " + mDevice);
                    }
                }
            }
            Log.w(TAG, "Set abs volume support and update initial volume to ACM");
            mRemoteVolume = vcpVol;
            mVcpController.setAbsVolumeSupport(mDevice, true, vcpVol);
            mVcpController.updateConnState(mDevice, BluetoothProfile.STATE_CONNECTED);
            return;
        }

        if (mRemoteVolume != vcpVol) {
            mRemoteVolume = vcpVol;
            mVcpController.notifyVolumeChanged(mDevice, vcpVol, mVolumeControlAudioType);
            mVolumeControlAudioType = -1;
            long pecentVolChanged = ((long)vcpVol * 100) / 0xff;
            Log.w(TAG, "percent volume changed: " + pecentVolChanged + "%");
        }
    }

    private void processMuteChanged(int mute) {
        log("process mute changed");

        if (mMuteChangeInProgress == true) {
            mMuteChangeInProgress = false;
            mChangeMuteRetryTimes = 0;
            removeMessages(CHANGE_MUTE_TIMEOUT);

            if ((mCachedMuteState != -1) && (mCachedMuteState != mute)) {
                Log.w(TAG, "Set cached mute state to remote");
                boolean ret;
                if (mCachedMuteState == MUTE_STATE) {
                    ret = mNativeInterface.mute(mDevice);
                } else {
                    ret = mNativeInterface.unmute(mDevice);
                }

                if (ret) {
                    sendMessageDelayed(CHANGE_MUTE_TIMEOUT, mDevice,
                            CMD_TIMEOUT_DELAY);
                    mMuteChangeInProgress = true;
                    mRequestedMuteState = mCachedMuteState;
                    mCachedMuteState = -1;
                    return;
                }
                mCachedMuteState = -1;
            }
        }

        if (mMuteState != mute) {
            mMuteState = mute;
            boolean  isMute = (mMuteState == MUTE_STATE) ? true : false;
            mVcpController.notifyMuteChanged(mDevice, isMute);
            Log.w(TAG, "Mute state changed to " + mMuteState);
        }
    }

    private void processVolumeFlagsChanged(int flags) {
        log("process volume flags changed");
        mVolumeFlags = flags;
    }

    int getConnectionState() {
        String currentState = getCurrentState().getName();
        switch (currentState) {
            case "Disconnected":
                return BluetoothProfile.STATE_DISCONNECTED;
            case "Connecting":
                return BluetoothProfile.STATE_CONNECTING;
            case "Connected":
                return BluetoothProfile.STATE_CONNECTED;
            case "Disconnecting":
                return BluetoothProfile.STATE_DISCONNECTING;
            default:
                Log.e(TAG, "Bad currentState: " + currentState);
                return BluetoothProfile.STATE_DISCONNECTED;
        }
    }

    int getVolume() {
        return mRemoteVolume;
    }

    boolean isMute() {
        if (mMuteState == MUTE_STATE)
            return true;
        else
            return false;
    }

    BluetoothDevice getDevice() {
        return mDevice;
    }

    synchronized boolean isConnected() {
        return getCurrentState() == mConnected;
    }

    // This method does not check for error condition (newState == prevState)
    private void broadcastConnectionState(int newState, int prevState) {
        log("Connection state " + mDevice + ": " + profileStateToString(prevState)
                    + "->" + profileStateToString(newState));
        mVcpController.onConnectionStateChangedFromStateMachine(mDevice,
                newState, prevState);

        Intent intent = new Intent(BluetoothVcp.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mContext.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
    }

    private void cleanupDevice() {
        log("cleanup device " + mDevice);
        mRemoteVolume = -1;
        mRequestedVolume = -1;
        mCachedVolume = -1;
        mAbsVolRetryTimes = 0;
        mAbsVolSetInProgress = false;
        mMuteState = -1;
        mRequestedMuteState = -1;
        mCachedMuteState = -1;
        mChangeMuteRetryTimes = 0;
        mMuteChangeInProgress = false;
        mVolumeFlags = -1;
        mVolumeControlAudioType = -1;
        mCachedVolumeControlAudioType = -1;
    }

    private static String messageWhatToString(int what) {
        switch (what) {
            case CONNECT:
                return "CONNECT";
            case DISCONNECT:
                return "DISCONNECT";
            case STACK_EVENT:
                return "STACK_EVENT";
            case CONNECT_TIMEOUT:
                return "CONNECT_TIMEOUT";
            case SET_VOLUME:
                return "SET_VOLUME";
            case MUTE:
                return "MUTE";
            case UNMUTE:
                return "UNMUTE";
            case SET_ABS_VOL_TIMEOUT:
                return "SET_ABS_VOL_TIMEOUT";
            case CHANGE_MUTE_TIMEOUT:
                return "CHANGE_MUTE_TIMEOUT";
            default:
                return "UNKNOWN(" + what + ")";
        }
    }

    private static String profileStateToString(int state) {
        switch (state) {
            case BluetoothProfile.STATE_DISCONNECTED:
                return "DISCONNECTED";
            case BluetoothProfile.STATE_CONNECTING:
                return "CONNECTING";
            case BluetoothProfile.STATE_CONNECTED:
                return "CONNECTED";
            case BluetoothProfile.STATE_DISCONNECTING:
                return "DISCONNECTING";
            default:
                break;
        }
        return Integer.toString(state);
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mDevice: " + mDevice);
        ProfileService.println(sb, "  StateMachine: " + this);
        // Dump the state machine logs
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        super.dump(new FileDescriptor(), printWriter, new String[]{});
        printWriter.flush();
        stringWriter.flush();
        ProfileService.println(sb, "  StateMachineLog:");
        Scanner scanner = new Scanner(stringWriter.toString());
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            ProfileService.println(sb, "    " + line);
        }
        scanner.close();
    }

    @Override
    protected void log(String msg) {
        if (DBG) {
            super.log(msg);
        }
    }
}

