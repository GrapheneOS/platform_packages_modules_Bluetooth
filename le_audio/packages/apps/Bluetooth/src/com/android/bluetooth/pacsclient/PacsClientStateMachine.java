/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
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
 * Bluetooth PacsClient StateMachine. There is one instance per remote device.
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

package com.android.bluetooth.pc;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import com.android.bluetooth.Utils;
import android.bluetooth.BluetoothCodecConfig;
import android.content.Intent;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import android.content.Context;

import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;

final class PacsClientStateMachine extends StateMachine {
    private static final boolean DBG = false;
    private static final String TAG = "PacsClientStateMachine";

    static final int CONNECT = 1;
    static final int DISCONNECT = 2;
    static final int START_DISCOVERY = 3;
    static final int GET_AVAILABLE_CONTEXTS = 4;
    @VisibleForTesting
    static final int STACK_EVENT = 101;
    private static final int CONNECT_TIMEOUT = 201;

    // NOTE: the value is not "final" - it is modified in the unit tests
    @VisibleForTesting
    static int sConnectTimeoutMs = 30000;        // 30s

    private Disconnected mDisconnected;
    private Connecting mConnecting;
    private Disconnecting mDisconnecting;
    private Connected mConnected;
    private int mLastConnectionState = -1;

    private PCService mService;
    private PacsClientNativeInterface mNativeInterface;
    private BluetoothCodecConfig[] mSinkPacsConfig;
    private BluetoothCodecConfig[] mSrcPacsConfig;
    private int mSinkLocations;
    private int mSrcLocations;
    private int mAvailableContexts;
    private int mSupportedContexts;
    private Context mContext;

    private final BluetoothDevice mDevice;

    PacsClientStateMachine(BluetoothDevice device, PCService svc,
            PacsClientNativeInterface nativeInterface, Looper looper) {
        super(TAG, looper);
        mDevice = device;
        mService = svc;
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

    static PacsClientStateMachine make(BluetoothDevice device, PCService svc,
            PacsClientNativeInterface nativeInterface, Looper looper) {
        Log.i(TAG, "make for device " + device);
        PacsClientStateMachine PacsClientSm = new PacsClientStateMachine(device, svc,
                nativeInterface, looper);
        PacsClientSm.start();
        return PacsClientSm;
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
            Log.i(TAG, "Exit Disconnected(" + mDevice + "): " + messageWhatToString(
                    getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Disconnected process message(" + mDevice + "): " + messageWhatToString(
                    message.what));

            switch (message.what) {
                case CONNECT:
                    log("Connecting to " + mDevice);
                    if (!mNativeInterface.connectPacsClient(mDevice)) {
                        Log.e(TAG, "Disconnected: error connecting to " + mDevice);
                        break;
                    }
                    if (mService.okToConnect(mDevice)) {
                        transitionTo(mConnecting);
                    } else {
                        // Reject the request and stay in Disconnected state
                        Log.w(TAG, "Outgoing PacsClient Connecting request rejected: " + mDevice);
                    }
                    break;
                case DISCONNECT:
                    Log.w(TAG, "Disconnected: DISCONNECT ignored: " + mDevice);
                    break;
                case STACK_EVENT:
                    PacsClientStackEvent event = (PacsClientStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Disconnected: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtf(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case PacsClientStackEvent.EVENT_TYPE_INITIALIZED:
                            if(event.valueInt1 != 0) {
                                Log.e(TAG, "Disconnected: error initializing PACS");
                                return NOT_HANDLED;
                            }
                            Log.d(TAG, "PACS Initialized succesfully (DISCONNECTED)");
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        default:
                            Log.e(TAG, "Disconnected: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnected state
        private void processConnectionEvent(int state) {
            switch (state) {
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Ignore PacsClient DISCONNECTED event: " + mDevice);
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTING:
                    if (mService.okToConnect(mDevice)) {
                        Log.i(TAG, "Incoming PacsClient Connecting request accepted: " + mDevice
                            + "state: " + state);
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming PacsClient Connecting request rejected: " + mDevice
                            + "state: " + state);
                        mNativeInterface.disconnectPacsClient(mDevice);
                    }
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTED:
                    Log.w(TAG, "PacsClient Connected from Disconnected state: " + mDevice
                            + "state: " + state);
                    if (mService.okToConnect(mDevice)) {
                        Log.i(TAG, "Incoming PacsClient Connected request accepted: " + mDevice
                            + "state: " + state);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming PacsClient Connected request rejected: " + mDevice
                            + "state: " + state);
                        mNativeInterface.disconnectPacsClient(mDevice);
                    }
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.w(TAG, "Ignore PacsClient DISCONNECTING event: " + mDevice
                        + "state: " + state);
                    break;
                default:
                    Log.e(TAG, "Incorrect state: " + state + " device: " + mDevice
                        + "state: " + state);
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
            sendMessageDelayed(CONNECT_TIMEOUT, sConnectTimeoutMs);
            broadcastConnectionState(BluetoothProfile.STATE_CONNECTING, mLastConnectionState);
        }

        @Override
        public void exit() {
            Log.i(TAG, "Exit Connecting(" + mDevice + "): "
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
                    mNativeInterface.disconnectPacsClient(mDevice);
                    PacsClientStackEvent disconnectEvent =
                            new PacsClientStackEvent(
                                    PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
                    disconnectEvent.device = mDevice;
                    disconnectEvent.valueInt1 = PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED;
                    sendMessage(STACK_EVENT, disconnectEvent);
                    break;
                case DISCONNECT:
                    log("Connecting: connection canceled to " + mDevice);
                    mNativeInterface.disconnectPacsClient(mDevice);
                    transitionTo(mDisconnected);
                    break;
                case START_DISCOVERY:
                case GET_AVAILABLE_CONTEXTS:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    PacsClientStackEvent event = (PacsClientStackEvent) message.obj;
                    log("Connecting: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtf(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case PacsClientStackEvent.EVENT_TYPE_INITIALIZED:
                            if(event.valueInt1 != 0) {
                                Log.e(TAG, "Disconnected: error initializing PACS");
                                return NOT_HANDLED;
                            }
                            Log.d(TAG, "PACS Initialized succesfully (CONNECTING)");
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_SERVICE_DISCOVERY:
                        case PacsClientStackEvent.EVENT_TYPE_AUDIO_CONTEXT_AVAIL:
                            deferMessage(message);
                            break;
                        default:
                            Log.e(TAG, "Disconnected: ignoring stack event: " + event);
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
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Connecting device disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTED:
                    transitionTo(mConnected);
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTING:
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTING:
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
            sendMessageDelayed(CONNECT_TIMEOUT, sConnectTimeoutMs);
            broadcastConnectionState(BluetoothProfile.STATE_DISCONNECTING, mLastConnectionState);
        }

        @Override
        public void exit() {
            Log.i(TAG, "Exit Disconnecting(" + mDevice + "): "
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
                    mNativeInterface.disconnectPacsClient(mDevice);
                    PacsClientStackEvent disconnectEvent =
                            new PacsClientStackEvent(
                                    PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
                    disconnectEvent.device = mDevice;
                    disconnectEvent.valueInt1 = PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED;
                    sendMessage(STACK_EVENT, disconnectEvent);
                    break;
                }
                case START_DISCOVERY:
                case GET_AVAILABLE_CONTEXTS:
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    PacsClientStackEvent event = (PacsClientStackEvent) message.obj;
                    log("Disconnecting: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtf(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_SERVICE_DISCOVERY:
                        case PacsClientStackEvent.EVENT_TYPE_AUDIO_CONTEXT_AVAIL:
                            deferMessage(message);
                            break;
                        default:
                            Log.e(TAG, "Disconnected: ignoring stack event: " + event);
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
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTED:
                    if (mService.okToConnect(mDevice)) {
                        Log.w(TAG, "Disconnecting interrupted: device is connected: " + mDevice);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming PacsClient Connected request rejected: " + mDevice);
                        mNativeInterface.disconnectPacsClient(mDevice);
                    }
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_CONNECTING:
                    if (mService.okToConnect(mDevice)) {
                        Log.i(TAG, "Disconnecting interrupted: try to reconnect: " + mDevice);
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming PacsClient Connecting request rejected: " + mDevice);
                        mNativeInterface.disconnectPacsClient(mDevice);
                    }
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTING:
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
            mNativeInterface.startDiscoveryNative(mDevice);
            broadcastConnectionState(BluetoothProfile.STATE_CONNECTED, mLastConnectionState);
        }

        @Override
        public void exit() {
            Log.i(TAG, "Exit Connected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_CONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Connected process message(" + mDevice + "): "
                    + messageWhatToString(message.what));

            switch (message.what) {
                case CONNECT:
                    Log.w(TAG, "Connected: CONNECT ignored: " + mDevice);
                    break;
                case DISCONNECT:
                    log("Disconnecting from " + mDevice);
                    if (!mNativeInterface.disconnectPacsClient(mDevice)) {
                        // If error in the native stack, transition directly to Disconnected state.
                        Log.e(TAG, "Connected: error disconnecting from " + mDevice);
                        transitionTo(mDisconnected);
                        break;
                    }
                    transitionTo(mDisconnecting);
                    break;
                case START_DISCOVERY:
                    log("sending start discovery to " + mDevice);
                    if (!mNativeInterface.startDiscoveryNative(mDevice)) {
                        Log.e(TAG, "connected: error sending startdiscovery to " + mDevice);
                    }
                    break;
                case GET_AVAILABLE_CONTEXTS:
                    log("get available audio conxtes from " + mDevice);
                    mNativeInterface.GetAvailableAudioContexts(mDevice);
                    break;
                case STACK_EVENT:
                    PacsClientStackEvent event = (PacsClientStackEvent) message.obj;
                    log("Connected: stack event: " + event);
                    if (!mDevice.equals(event.device)) {
                        Log.wtf(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case PacsClientStackEvent.EVENT_TYPE_INITIALIZED:
                            deferMessage(message);
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt1);
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_SERVICE_DISCOVERY:
                            processPacsRecordEvent(event.sinkCodecConfig, event.srcCodecConfig,
                                                   event.valueInt1, event.valueInt2,
                                                   event.valueInt3, event.valueInt4);
                            break;
                        case PacsClientStackEvent.EVENT_TYPE_AUDIO_CONTEXT_AVAIL:
                            mAvailableContexts = event.valueInt1;
                            break;
                        default:
                            Log.e(TAG, "Disconnected: ignoring stack event: " + event);
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
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected from " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case PacsClientStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.i(TAG, "Disconnecting from " + mDevice);
                    transitionTo(mDisconnecting);
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + mDevice + " bad state: " + state);
                    break;
            }
        }

        private void processPacsRecordEvent(BluetoothCodecConfig[] sinkCodecConfig,
                                            BluetoothCodecConfig[] srcCodecConfig,
                                            int sink_locations, int src_locations,
                                            int available_contexts, int supported_contexts) {
             mSinkPacsConfig = sinkCodecConfig;
             mSrcPacsConfig = srcCodecConfig;
             mSinkLocations = sink_locations;
             mSrcLocations =  src_locations;
             mAvailableContexts = available_contexts;
             mSupportedContexts = supported_contexts;
        }
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

    BluetoothDevice getDevice() {
        return mDevice;
    }

    synchronized boolean isConnected() {
        return getCurrentState() == mConnected;
    }


    private void cleanupDevice() {
        log("cleanup device " + mDevice);
        mSinkLocations = -1;
        mSrcLocations = -1;
        mAvailableContexts = -1;
        mSupportedContexts = -1;
    }

    BluetoothCodecConfig[] getSinkPacs() {
        synchronized (this) {
            return mSinkPacsConfig;
        }
    }

    BluetoothCodecConfig[] getSrcPacs() {
        synchronized (this) {
            return mSrcPacsConfig;
        }
    }

    int getSinklocations() {
        synchronized (this) {
            return mSinkLocations;
        }
    }

    int getSrclocations() {
        synchronized (this) {
            return mSrcLocations;
        }
    }

    int getAvailableContexts() {
        synchronized (this) {
            return mAvailableContexts;
        }
    }

    int getSupportedContexts() {
        synchronized (this) {
            return mSupportedContexts;
        }
    }

    // This method does not check for error condition (newState == prevState)
    private void broadcastConnectionState(int newState, int prevState) {
        log("Connection state " + mDevice + ": " + profileStateToString(prevState)
                    + "->" + profileStateToString(newState));
        mService.onConnectionStateChangedFromStateMachine(mDevice, newState, prevState);
        Intent intent = new Intent(PCService.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mService.sendBroadcast(intent, BLUETOOTH_CONNECT, Utils.getTempAllowlistBroadcastOptions());
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
            default:
                break;
        }
        return Integer.toString(what);
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

    @Override
    protected void log(String msg) {
        if (DBG) {
            super.log(msg);
        }
    }
}
