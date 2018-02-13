/*
 * Copyright (C) 2012 The Android Open Source Project
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
 * Bluetooth A2DP StateMachine. There is one instance per remote device.
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

package com.android.bluetooth.a2dp;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.Intent;
import android.os.Looper;
import android.os.Message;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;

final class A2dpStateMachine extends StateMachine {
    private static final boolean DBG = true;
    private static final String TAG = "A2dpStateMachine";

    static final int CONNECT = 1;
    static final int DISCONNECT = 2;
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
    private int mConnectionState = BluetoothProfile.STATE_DISCONNECTED;
    private int mLastConnectionState = -1;

    private A2dpService mA2dpService;
    private A2dpNativeInterface mA2dpNativeInterface;

    private final BluetoothDevice mDevice;
    private boolean mIsPlaying = false;
    private BluetoothCodecStatus mCodecStatus;

    A2dpStateMachine(BluetoothDevice device, A2dpService a2dpService,
                     A2dpNativeInterface a2dpNativeInterface, Looper looper) {
        super(TAG, looper);
        mDevice = device;
        mA2dpService = a2dpService;
        mA2dpNativeInterface = a2dpNativeInterface;

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

    static A2dpStateMachine make(BluetoothDevice device, A2dpService a2dpService,
                                 A2dpNativeInterface a2dpNativeInterface, Looper looper) {
        if (DBG) {
            Log.d(TAG, "make for device " + device);
        }
        A2dpStateMachine a2dpSm = new A2dpStateMachine(device, a2dpService, a2dpNativeInterface,
                                                       looper);
        a2dpSm.start();
        return a2dpSm;
    }

    public void doQuit() {
        if (DBG) {
            Log.d(TAG, "doQuit for device " + mDevice);
        }
        quitNow();
    }

    public void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup for device " + mDevice);
        }
    }

    @VisibleForTesting
    class Disconnected extends State {
        @Override
        public void enter() {
            Log.i(TAG, "Enter Disconnected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mConnectionState = BluetoothProfile.STATE_DISCONNECTED;

            removeDeferredMessages(DISCONNECT);
            // Remove Timeout messages when moved to stable state
            removeMessages(CONNECT_TIMEOUT);

            if (mLastConnectionState != -1) {
                // Don't broadcast during startup
                broadcastConnectionState(mConnectionState, mLastConnectionState);
                if (mIsPlaying) {
                    Log.i(TAG, "Disconnected: stopped playing: " + mDevice);
                    mIsPlaying = false;
                    mA2dpService.setAvrcpAudioState(BluetoothA2dp.STATE_NOT_PLAYING);
                    broadcastAudioState(BluetoothA2dp.STATE_NOT_PLAYING,
                                        BluetoothA2dp.STATE_PLAYING);
                }
            }
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Disconnected(" + mDevice + "): "
                        + messageWhatToString(getCurrentMessage().what));
            }
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Disconnected process message(" + mDevice + "): "
                        + messageWhatToString(message.what));
            }

            switch (message.what) {
                case CONNECT:
                    Log.i(TAG, "Connecting to " + mDevice);
                    if (!mA2dpNativeInterface.connectA2dp(mDevice)) {
                        Log.e(TAG, "Disconnected: error connecting to " + mDevice);
                        break;
                    }
                    if (mA2dpService.okToConnect(mDevice)) {
                        transitionTo(mConnecting);
                        sendMessageDelayed(CONNECT_TIMEOUT, sConnectTimeoutMs);
                    } else {
                        // Reject the request and stay in Disconnected state
                        Log.w(TAG, "Outgoing A2DP Connecting request rejected: " + mDevice);
                    }
                    break;
                case DISCONNECT:
                    Log.w(TAG, "Disconnected: DISCONNECT ignored: " + mDevice);
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Disconnected: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.codecStatus);
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
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Ignore A2DP DISCONNECTED event: " + mDevice);
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTING:
                    if (mA2dpService.okToConnect(mDevice)) {
                        Log.i(TAG, "Incoming A2DP Connecting request accepted: " + mDevice);
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming A2DP Connecting request rejected: " + mDevice);
                        mA2dpNativeInterface.disconnectA2dp(mDevice);
                    }
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTED:
                    Log.w(TAG, "A2DP Connected from Disconnected state: " + mDevice);
                    if (mA2dpService.okToConnect(mDevice)) {
                        Log.i(TAG, "Incoming A2DP Connected request accepted: " + mDevice);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnected state itself
                        Log.w(TAG, "Incoming A2DP Connected request rejected: " + mDevice);
                        mA2dpNativeInterface.disconnectA2dp(mDevice);
                    }
                    break;
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    Log.w(TAG, "Ignore A2DP DISCONNECTING event: " + mDevice);
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
            mConnectionState = BluetoothProfile.STATE_CONNECTING;
            broadcastConnectionState(mConnectionState, mLastConnectionState);
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Connecting(" + mDevice + "): "
                        + messageWhatToString(getCurrentMessage().what));
            }
            mLastConnectionState = BluetoothProfile.STATE_CONNECTING;
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Connecting process message(" + mDevice + "): "
                        + messageWhatToString(message.what));
            }

            switch (message.what) {
                case CONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    Log.w(TAG, "Connecting connection timeout: " + mDevice);
                    mA2dpNativeInterface.disconnectA2dp(mDevice);
                    A2dpStackEvent event =
                            new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
                    event.device = mDevice;
                    event.valueInt = A2dpStackEvent.CONNECTION_STATE_DISCONNECTED;
                    sendMessage(STACK_EVENT, event);
                    break;
                }
                case DISCONNECT:
                    // Cancel connection
                    Log.i(TAG, "Connecting: connection canceled to " + mDevice);
                    mA2dpNativeInterface.disconnectA2dp(mDevice);
                    transitionTo(mDisconnected);
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Connecting: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.codecStatus);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
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
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Connecting device disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTED:
                    transitionTo(mConnected);
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTING:
                    // Ignored - probably an event that the outgoing connection was initiated
                    break;
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTING:
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
            mConnectionState = BluetoothProfile.STATE_DISCONNECTING;
            broadcastConnectionState(mConnectionState, mLastConnectionState);
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Disconnecting(" + mDevice + "): "
                        + messageWhatToString(getCurrentMessage().what));
            }
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTING;
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Disconnecting process message(" + mDevice + "): "
                        + messageWhatToString(message.what));
            }

            switch (message.what) {
                case CONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    Log.w(TAG, "Disconnecting connection timeout: " + mDevice);
                    mA2dpNativeInterface.disconnectA2dp(mDevice);
                    A2dpStackEvent event =
                            new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
                    event.device = mDevice;
                    event.valueInt = A2dpStackEvent.CONNECTION_STATE_DISCONNECTED;
                    sendMessage(STACK_EVENT, event);
                    break;
                }
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Disconnecting: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.codecStatus);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
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
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected: " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTED:
                    if (mA2dpService.okToConnect(mDevice)) {
                        Log.w(TAG, "Disconnecting interrupted: device is connected: " + mDevice);
                        transitionTo(mConnected);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming A2DP Connected request rejected: " + mDevice);
                        mA2dpNativeInterface.disconnectA2dp(mDevice);
                    }
                    break;
                case A2dpStackEvent.CONNECTION_STATE_CONNECTING:
                    if (mA2dpService.okToConnect(mDevice)) {
                        Log.i(TAG, "Disconnecting interrupted: try to reconnect: " + mDevice);
                        transitionTo(mConnecting);
                    } else {
                        // Reject the connection and stay in Disconnecting state
                        Log.w(TAG, "Incoming A2DP Connecting request rejected: " + mDevice);
                        mA2dpNativeInterface.disconnectA2dp(mDevice);
                    }
                    break;
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTING:
                    // We are already disconnecting, do nothing
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
            mConnectionState = BluetoothProfile.STATE_CONNECTED;

            removeDeferredMessages(CONNECT);
            // Remove Timeout messages when moved to stable state
            removeMessages(CONNECT_TIMEOUT);

            broadcastConnectionState(mConnectionState, mLastConnectionState);
            // Upon connected, the audio starts out as stopped
            broadcastAudioState(BluetoothA2dp.STATE_NOT_PLAYING,
                                BluetoothA2dp.STATE_PLAYING);
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Connected(" + mDevice + "): "
                        + messageWhatToString(getCurrentMessage().what));
            }
            mLastConnectionState = BluetoothProfile.STATE_CONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Connected process message(" + mDevice + "): "
                        + messageWhatToString(message.what));
            }

            switch (message.what) {
                case CONNECT:
                    Log.w(TAG, "Connected: CONNECT ignored: " + mDevice);
                    break;
                case DISCONNECT: {
                    Log.i(TAG, "Disconnecting from " + mDevice);
                    if (!mA2dpNativeInterface.disconnectA2dp(mDevice)) {
                        // If error in the native stack, transition directly to Disconnected state.
                        Log.e(TAG, "Connected: error disconnecting from " + mDevice);
                        transitionTo(mDisconnected);
                        break;
                    }
                    transitionTo(mDisconnecting);
                }
                break;
                case CONNECT_TIMEOUT:
                    // Ignore - nothing to timeout. We are already connected.
                    Log.w(TAG, "Connected: CONNECT_TIMEOUT ignored: " + mDevice);
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Connected: stack event: " + event);
                    }
                    if (!mDevice.equals(event.device)) {
                        Log.wtfStack(TAG, "Device(" + mDevice + "): event mismatch: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
                            processAudioStateEvent(event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.codecStatus);
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
                case A2dpStackEvent.CONNECTION_STATE_DISCONNECTED:
                    Log.i(TAG, "Disconnected from " + mDevice);
                    transitionTo(mDisconnected);
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + mDevice + " bad state: " + state);
                    break;
            }
        }

        // in Connected state
        private void processAudioStateEvent(int state) {
            switch (state) {
                case A2dpStackEvent.AUDIO_STATE_STARTED:
                    synchronized (this) {
                        if (!mIsPlaying) {
                            Log.i(TAG, "Connected: started playing: " + mDevice);
                            mIsPlaying = true;
                            mA2dpService.setAvrcpAudioState(BluetoothA2dp.STATE_PLAYING);
                            broadcastAudioState(BluetoothA2dp.STATE_PLAYING,
                                                BluetoothA2dp.STATE_NOT_PLAYING);
                        }
                    }
                    break;
                case A2dpStackEvent.AUDIO_STATE_REMOTE_SUSPEND:
                case A2dpStackEvent.AUDIO_STATE_STOPPED:
                    synchronized (this) {
                        if (mIsPlaying) {
                            Log.i(TAG, "Connected: stopped playing: " + mDevice);
                            mIsPlaying = false;
                            mA2dpService.setAvrcpAudioState(BluetoothA2dp.STATE_NOT_PLAYING);
                            broadcastAudioState(BluetoothA2dp.STATE_NOT_PLAYING,
                                                BluetoothA2dp.STATE_PLAYING);
                        }
                    }
                    break;
                default:
                    Log.e(TAG, "Audio State Device: " + mDevice + " bad state: " + state);
                    break;
            }
        }
    }

    int getConnectionState() {
        return mConnectionState;
    }

    BluetoothDevice getDevice() {
        return mDevice;
    }

    boolean isConnected() {
        synchronized (this) {
            return (getCurrentState() == mConnected);
        }
    }

    boolean isPlaying() {
        synchronized (this) {
            return mIsPlaying;
        }
    }

    BluetoothCodecStatus getCodecStatus() {
        synchronized (this) {
            return mCodecStatus;
        }
    }

    // NOTE: This event is processed in any state
    private void processCodecConfigEvent(BluetoothCodecStatus newCodecStatus) {
        BluetoothCodecConfig prevCodecConfig = null;
        synchronized (this) {
            if (mCodecStatus != null) {
                prevCodecConfig = mCodecStatus.getCodecConfig();
            }
            mCodecStatus = newCodecStatus;
        }

        if (DBG) {
            Log.d(TAG, "A2DP Codec Config: " + prevCodecConfig + "->"
                    + newCodecStatus.getCodecConfig());
            for (BluetoothCodecConfig codecConfig :
                     newCodecStatus.getCodecsLocalCapabilities()) {
                Log.d(TAG, "A2DP Codec Local Capability: " + codecConfig);
            }
            for (BluetoothCodecConfig codecConfig :
                     newCodecStatus.getCodecsSelectableCapabilities()) {
                Log.d(TAG, "A2DP Codec Selectable Capability: " + codecConfig);
            }
        }

        boolean sameAudioFeedingParameters =
                newCodecStatus.getCodecConfig().sameAudioFeedingParameters(prevCodecConfig);
        mA2dpService.codecConfigUpdated(mDevice, mCodecStatus, sameAudioFeedingParameters);
    }

    // This method does not check for error conditon (newState == prevState)
    private void broadcastConnectionState(int newState, int prevState) {
        if (DBG) {
            Log.d(TAG, "Connection state " + mDevice + ": " + profileStateToString(prevState)
                    + "->" + profileStateToString(newState));
        }

        Intent intent = new Intent(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mA2dpService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void broadcastAudioState(int newState, int prevState) {
        if (DBG) {
            Log.d(TAG, "A2DP Playing state : device: " + mDevice + " State:"
                    + audioStateToString(prevState) + "->"
                    + audioStateToString(newState));
        }

        Intent intent = new Intent(BluetoothA2dp.ACTION_PLAYING_STATE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        mA2dpService.sendBroadcast(intent, A2dpService.BLUETOOTH_PERM);
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

    private static String audioStateToString(int state) {
        switch (state) {
            case BluetoothA2dp.STATE_PLAYING:
                return "PLAYING";
            case BluetoothA2dp.STATE_NOT_PLAYING:
                return "NOT_PLAYING";
            default:
                break;
        }
        return Integer.toString(state);
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mDevice: " + mDevice);
        ProfileService.println(sb, "  StateMachine: " + this.toString());
        ProfileService.println(sb, "  mIsPlaying: " + mIsPlaying);
        synchronized (this) {
            if (mCodecStatus != null) {
                ProfileService.println(sb, "  mCodecConfig: " + mCodecStatus.getCodecConfig());
            }
        }
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
}
