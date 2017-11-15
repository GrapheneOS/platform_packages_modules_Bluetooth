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
 * Bluetooth A2dp StateMachine
 *                      (Disconnected)
 *                           |    ^
 *                   CONNECT |    | DISCONNECTED
 *                           V    |
 *                         (Pending)
 *                           |    ^
 *                 CONNECTED |    | CONNECT
 *                           V    |
 *                        (Connected)
 */
package com.android.bluetooth.a2dp;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.media.AudioManager;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.android.bluetooth.R;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.util.IState;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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
    private Pending mPending;
    private Connected mConnected;

    private A2dpService mService;
    private Context mContext;
    private A2dpNativeInterface mA2dpNativeInterface;
    private BluetoothAdapter mAdapter;
    private final AudioManager mAudioManager;
    private BluetoothCodecConfig[] mCodecConfigPriorities;

    // mCurrentDevice is the device connected before the state changes
    // mTargetDevice is the device to be connected
    // mIncomingDevice is the device connecting to us, valid only in Pending state
    //                when mIncomingDevice is not null, both mCurrentDevice
    //                  and mTargetDevice are null
    //                when either mCurrentDevice or mTargetDevice is not null,
    //                  mIncomingDevice is null
    // Stable states
    //   No connection, Disconnected state
    //                  both mCurrentDevice and mTargetDevice are null
    //   Connected, Connected state
    //              mCurrentDevice is not null, mTargetDevice is null
    // Interim states
    //   Connecting to a device, Pending
    //                           mCurrentDevice is null, mTargetDevice is not null
    //   Disconnecting device, Connecting to new device
    //     Pending
    //     Both mCurrentDevice and mTargetDevice are not null
    //   Disconnecting device Pending
    //                        mCurrentDevice is not null, mTargetDevice is null
    //   Incoming connections Pending
    //                        Both mCurrentDevice and mTargetDevice are null
    private BluetoothDevice mCurrentDevice = null;
    private BluetoothDevice mTargetDevice = null;
    private BluetoothDevice mIncomingDevice = null;
    private BluetoothDevice mPlayingA2dpDevice = null;

    private BluetoothCodecStatus mCodecStatus = null;
    private int mA2dpSourceCodecPrioritySbc = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
    private int mA2dpSourceCodecPriorityAac = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
    private int mA2dpSourceCodecPriorityAptx = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
    private int mA2dpSourceCodecPriorityAptxHd = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
    private int mA2dpSourceCodecPriorityLdac = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;

    A2dpStateMachine(A2dpService svc, Context context,
                     A2dpNativeInterface a2dpNativeInterface, Looper looper) {
        super(TAG, looper);
        mService = svc;
        mContext = context;
        mA2dpNativeInterface = a2dpNativeInterface;
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mCodecConfigPriorities = assignCodecConfigPriorities();

        mA2dpNativeInterface.init(mCodecConfigPriorities);

        mDisconnected = new Disconnected();
        mPending = new Pending();
        mConnected = new Connected();

        addState(mDisconnected);
        addState(mPending);
        addState(mConnected);

        setInitialState(mDisconnected);

        mAudioManager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
    }

    static A2dpStateMachine make(A2dpService svc, Context context,
                                 A2dpNativeInterface a2dpNativeInterface,
                                 Looper looper) {
        if (DBG) {
            Log.d(TAG, "make");
        }
        A2dpStateMachine a2dpSm = new A2dpStateMachine(svc, context,
                                                       a2dpNativeInterface,
                                                       looper);
        a2dpSm.start();
        return a2dpSm;
    }

    // Assign the A2DP Source codec config priorities
    private BluetoothCodecConfig[] assignCodecConfigPriorities() {
        Resources resources = mContext.getResources();
        if (resources == null) {
            return null;
        }

        int value;
        try {
            value = resources.getInteger(R.integer.a2dp_source_codec_priority_sbc);
        } catch (NotFoundException e) {
            value = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
        }
        if ((value >= BluetoothCodecConfig.CODEC_PRIORITY_DISABLED) && (value
                < BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST)) {
            mA2dpSourceCodecPrioritySbc = value;
        }

        try {
            value = resources.getInteger(R.integer.a2dp_source_codec_priority_aac);
        } catch (NotFoundException e) {
            value = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
        }
        if ((value >= BluetoothCodecConfig.CODEC_PRIORITY_DISABLED) && (value
                < BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST)) {
            mA2dpSourceCodecPriorityAac = value;
        }

        try {
            value = resources.getInteger(R.integer.a2dp_source_codec_priority_aptx);
        } catch (NotFoundException e) {
            value = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
        }
        if ((value >= BluetoothCodecConfig.CODEC_PRIORITY_DISABLED) && (value
                < BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST)) {
            mA2dpSourceCodecPriorityAptx = value;
        }

        try {
            value = resources.getInteger(R.integer.a2dp_source_codec_priority_aptx_hd);
        } catch (NotFoundException e) {
            value = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
        }
        if ((value >= BluetoothCodecConfig.CODEC_PRIORITY_DISABLED) && (value
                < BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST)) {
            mA2dpSourceCodecPriorityAptxHd = value;
        }

        try {
            value = resources.getInteger(R.integer.a2dp_source_codec_priority_ldac);
        } catch (NotFoundException e) {
            value = BluetoothCodecConfig.CODEC_PRIORITY_DEFAULT;
        }
        if ((value >= BluetoothCodecConfig.CODEC_PRIORITY_DISABLED) && (value
                < BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST)) {
            mA2dpSourceCodecPriorityLdac = value;
        }

        BluetoothCodecConfig codecConfig;
        BluetoothCodecConfig[] codecConfigArray =
                new BluetoothCodecConfig[BluetoothCodecConfig.SOURCE_CODEC_TYPE_MAX];
        codecConfig = new BluetoothCodecConfig(BluetoothCodecConfig.SOURCE_CODEC_TYPE_SBC,
                mA2dpSourceCodecPrioritySbc, BluetoothCodecConfig.SAMPLE_RATE_NONE,
                BluetoothCodecConfig.BITS_PER_SAMPLE_NONE, BluetoothCodecConfig
                .CHANNEL_MODE_NONE, 0 /* codecSpecific1 */,
                0 /* codecSpecific2 */, 0 /* codecSpecific3 */, 0 /* codecSpecific4 */);
        codecConfigArray[0] = codecConfig;
        codecConfig = new BluetoothCodecConfig(BluetoothCodecConfig.SOURCE_CODEC_TYPE_AAC,
                mA2dpSourceCodecPriorityAac, BluetoothCodecConfig.SAMPLE_RATE_NONE,
                BluetoothCodecConfig.BITS_PER_SAMPLE_NONE, BluetoothCodecConfig
                .CHANNEL_MODE_NONE, 0 /* codecSpecific1 */,
                0 /* codecSpecific2 */, 0 /* codecSpecific3 */, 0 /* codecSpecific4 */);
        codecConfigArray[1] = codecConfig;
        codecConfig = new BluetoothCodecConfig(BluetoothCodecConfig.SOURCE_CODEC_TYPE_APTX,
                mA2dpSourceCodecPriorityAptx, BluetoothCodecConfig.SAMPLE_RATE_NONE,
                BluetoothCodecConfig.BITS_PER_SAMPLE_NONE, BluetoothCodecConfig
                .CHANNEL_MODE_NONE, 0 /* codecSpecific1 */,
                0 /* codecSpecific2 */, 0 /* codecSpecific3 */, 0 /* codecSpecific4 */);
        codecConfigArray[2] = codecConfig;
        codecConfig = new BluetoothCodecConfig(BluetoothCodecConfig.SOURCE_CODEC_TYPE_APTX_HD,
                mA2dpSourceCodecPriorityAptxHd, BluetoothCodecConfig.SAMPLE_RATE_NONE,
                BluetoothCodecConfig.BITS_PER_SAMPLE_NONE, BluetoothCodecConfig
                .CHANNEL_MODE_NONE, 0 /* codecSpecific1 */,
                0 /* codecSpecific2 */, 0 /* codecSpecific3 */, 0 /* codecSpecific4 */);
        codecConfigArray[3] = codecConfig;
        codecConfig = new BluetoothCodecConfig(BluetoothCodecConfig.SOURCE_CODEC_TYPE_LDAC,
                mA2dpSourceCodecPriorityLdac, BluetoothCodecConfig.SAMPLE_RATE_NONE,
                BluetoothCodecConfig.BITS_PER_SAMPLE_NONE, BluetoothCodecConfig
                .CHANNEL_MODE_NONE, 0 /* codecSpecific1 */,
                0 /* codecSpecific2 */, 0 /* codecSpecific3 */, 0 /* codecSpecific4 */);
        codecConfigArray[4] = codecConfig;

        return codecConfigArray;
    }

    public void doQuit() {
        quitNow();
    }

    public void cleanup() {
        mA2dpNativeInterface.cleanup();
    }

    @VisibleForTesting
    class Disconnected extends State {
        @Override
        public void enter() {
            if (DBG) {
                Log.d(TAG, "Enter Disconnected: " + getCurrentMessage().what);
            }
            if (mCurrentDevice != null || mTargetDevice != null || mIncomingDevice != null) {
                Log.e(TAG, "ERROR: enter() inconsistent state in Disconnected: current = "
                        + mCurrentDevice + " target = " + mTargetDevice + " incoming = "
                        + mIncomingDevice);
            }
            // Remove Timeout msg when moved to stable state
            removeMessages(CONNECT_TIMEOUT);
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Disconnected process message: " + message.what);
            }
            if (mCurrentDevice != null || mTargetDevice != null || mIncomingDevice != null) {
                Log.e(TAG, "ERROR: not null state in Disconnected: current = " + mCurrentDevice
                        + " target = " + mTargetDevice + " incoming = " + mIncomingDevice);
                mCurrentDevice = null;
                mTargetDevice = null;
                mIncomingDevice = null;
            }

            boolean retValue = HANDLED;
            switch (message.what) {
                case CONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                            BluetoothProfile.STATE_DISCONNECTED);

                    if (!mA2dpNativeInterface.connectA2dp(device)) {
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        break;
                    }

                    synchronized (A2dpStateMachine.this) {
                        mTargetDevice = device;
                        transitionTo(mPending);
                    }
                    // TODO(BT) remove CONNECT_TIMEOUT when the stack
                    //          sends back events consistently
                    sendMessageDelayed(CONNECT_TIMEOUT, sConnectTimeoutMs);
                    break;
                case DISCONNECT:
                    // ignore
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Disconnected: stack event: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "Disconnected: Connection " + event.device
                                        + " state changed:" + event.valueInt);
                            }
                            processConnectionEvent(event.device, event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.device, event.codecStatus);
                            break;
                        default:
                            Log.e(TAG, "Unexpected stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return retValue;
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Disconnected: " + getCurrentMessage().what);
            }
        }

        // in Disconnected state
        private void processConnectionEvent(BluetoothDevice device, int state) {
            switch (state) {
                case CONNECTION_STATE_DISCONNECTED:
                    Log.w(TAG, "Ignore A2DP DISCONNECTED event, device: " + device);
                    break;
                case CONNECTION_STATE_CONNECTING:
                    if (okToConnect(device)) {
                        Log.i(TAG, "Incoming A2DP accepted");
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                                BluetoothProfile.STATE_DISCONNECTED);
                        synchronized (A2dpStateMachine.this) {
                            mIncomingDevice = device;
                            transitionTo(mPending);
                        }
                    } else {
                        //reject the connection and stay in Disconnected state itself
                        Log.i(TAG, "Incoming A2DP rejected");
                        mA2dpNativeInterface.disconnectA2dp(device);
                    }
                    break;
                case CONNECTION_STATE_CONNECTED:
                    Log.w(TAG, "A2DP Connected from Disconnected state");
                    if (okToConnect(device)) {
                        Log.i(TAG, "Incoming A2DP accepted");
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                        synchronized (A2dpStateMachine.this) {
                            mCurrentDevice = device;
                            transitionTo(mConnected);
                        }
                    } else {
                        //reject the connection and stay in Disconnected state itself
                        Log.i(TAG, "Incoming A2DP rejected");
                        mA2dpNativeInterface.disconnectA2dp(device);
                    }
                    break;
                case CONNECTION_STATE_DISCONNECTING:
                    Log.w(TAG, "Ignore A2dp DISCONNECTING event, device: " + device);
                    break;
                default:
                    Log.e(TAG, "Incorrect state: " + state);
                    break;
            }
        }
    }

    @VisibleForTesting
    class Pending extends State {
        @Override
        public void enter() {
            if (DBG) {
                Log.d(TAG, "Enter Pending: " + getCurrentMessage().what);
            }
            if (mTargetDevice != null && mIncomingDevice != null) {
                Log.e(TAG, "ERROR: enter() inconsistent state in Pending: current = "
                        + mCurrentDevice + " target = " + mTargetDevice + " incoming = "
                        + mIncomingDevice);
            }
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Pending process message: " + message.what);
            }

            boolean retValue = HANDLED;
            switch (message.what) {
                case CONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    Log.w(TAG, "Pending connection timeout: " + mTargetDevice);
                    mA2dpNativeInterface.disconnectA2dp(mTargetDevice);
                    A2dpStackEvent event =
                            new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
                    event.device = mTargetDevice;
                    event.valueInt = CONNECTION_STATE_DISCONNECTED;
                    sendMessage(STACK_EVENT, event);
                    break;
                }
                case DISCONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (mCurrentDevice != null && mTargetDevice != null && mTargetDevice.equals(
                            device)) {
                        // cancel connection to the mTargetDevice
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        synchronized (A2dpStateMachine.this) {
                            mTargetDevice = null;
                        }
                    } else {
                        deferMessage(message);
                    }
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Pending: stack event: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG,
                                        "Pending: Connection " + event.device + " state changed: "
                                        + event.valueInt);
                            }
                            processConnectionEvent(event.device, event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.device, event.codecStatus);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
                        default:
                            Log.e(TAG, "Pending: ignoring stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return retValue;
        }

        // in Pending state
        private void processConnectionEvent(BluetoothDevice device, int state) {
            switch (state) {
                case CONNECTION_STATE_DISCONNECTED:
                    if ((mCurrentDevice != null) && mCurrentDevice.equals(device)) {
                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_DISCONNECTING);
                        synchronized (A2dpStateMachine.this) {
                            mCurrentDevice = null;
                        }

                        if (mTargetDevice != null) {
                            if (!mA2dpNativeInterface.connectA2dp(mTargetDevice)) {
                                broadcastConnectionState(mTargetDevice,
                                        BluetoothProfile.STATE_DISCONNECTED,
                                        BluetoothProfile.STATE_CONNECTING);
                                synchronized (A2dpStateMachine.this) {
                                    mTargetDevice = null;
                                    transitionTo(mDisconnected);
                                }
                            }
                        } else {
                            synchronized (A2dpStateMachine.this) {
                                mIncomingDevice = null;
                                transitionTo(mDisconnected);
                            }
                        }
                    } else if (mTargetDevice != null && mTargetDevice.equals(device)) {
                        // outgoing connection failed
                        broadcastConnectionState(mTargetDevice, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        // check if there is some incoming connection request
                        if (mIncomingDevice != null) {
                            Log.i(TAG, "disconnect for outgoing in pending state");
                            synchronized (A2dpStateMachine.this) {
                                mTargetDevice = null;
                            }
                            break;
                        }
                        synchronized (A2dpStateMachine.this) {
                            mTargetDevice = null;
                            transitionTo(mDisconnected);
                        }
                    } else if (mIncomingDevice != null && mIncomingDevice.equals(device)) {
                        broadcastConnectionState(mIncomingDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        synchronized (A2dpStateMachine.this) {
                            mIncomingDevice = null;
                            transitionTo(mDisconnected);
                        }
                    } else {
                        Log.e(TAG, "Unknown device Disconnected: " + device);
                    }
                    break;
                case CONNECTION_STATE_CONNECTED:
                    if ((mCurrentDevice != null) && mCurrentDevice.equals(device)) {
                        // disconnection failed
                        broadcastConnectionState(mCurrentDevice, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_DISCONNECTING);
                        if (mTargetDevice != null) {
                            broadcastConnectionState(mTargetDevice,
                                    BluetoothProfile.STATE_DISCONNECTED,
                                    BluetoothProfile.STATE_CONNECTING);
                        }
                        synchronized (A2dpStateMachine.this) {
                            mTargetDevice = null;
                            transitionTo(mConnected);
                        }
                    } else if (mTargetDevice != null && mTargetDevice.equals(device)) {
                        broadcastConnectionState(mTargetDevice, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        synchronized (A2dpStateMachine.this) {
                            mCurrentDevice = mTargetDevice;
                            mTargetDevice = null;
                            transitionTo(mConnected);
                        }
                    } else if (mIncomingDevice != null && mIncomingDevice.equals(device)) {
                        broadcastConnectionState(mIncomingDevice, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        // check for a2dp connection allowed for this device in race condition
                        if (okToConnect(mIncomingDevice)) {
                            Log.i(TAG, "Ready to connect incoming Connection from pending state");
                            synchronized (A2dpStateMachine.this) {
                                mCurrentDevice = mIncomingDevice;
                                mIncomingDevice = null;
                                transitionTo(mConnected);
                            }
                        } else {
                            // A2dp connection unchecked for this device
                            Log.e(TAG, "Incoming A2DP rejected from pending state");
                            mA2dpNativeInterface.disconnectA2dp(device);
                        }
                    } else {
                        Log.e(TAG, "Unknown device Connected: " + device);
                        // something is wrong here, but sync our state with stack
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                        synchronized (A2dpStateMachine.this) {
                            mCurrentDevice = device;
                            mTargetDevice = null;
                            mIncomingDevice = null;
                            transitionTo(mConnected);
                        }
                    }
                    break;
                case CONNECTION_STATE_CONNECTING:
                    if ((mCurrentDevice != null) && mCurrentDevice.equals(device)) {
                        if (DBG) {
                            Log.d(TAG, "current device tries to connect back");
                        }
                        // TODO(BT) ignore or reject
                    } else if (mTargetDevice != null && mTargetDevice.equals(device)) {
                        // The stack is connecting to target device or
                        // there is an incoming connection from the target device at the same time
                        // we already broadcasted the intent, doing nothing here
                        if (DBG) {
                            Log.d(TAG, "Stack and target device are connecting");
                        }
                    } else if (mIncomingDevice != null && mIncomingDevice.equals(device)) {
                        Log.e(TAG, "Another connecting event on the incoming device");
                    } else {
                        // We get an incoming connecting request while Pending
                        // TODO(BT) is stack handing this case? let's ignore it for now
                        if (DBG) {
                            Log.d(TAG, "Incoming connection while pending, accept it");
                        }
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                                BluetoothProfile.STATE_DISCONNECTED);
                        mIncomingDevice = device;
                    }
                    break;
                case CONNECTION_STATE_DISCONNECTING:
                    if ((mCurrentDevice != null) && mCurrentDevice.equals(device)) {
                        // we already broadcasted the intent, doing nothing here
                        if (DBG) {
                            Log.d(TAG, "stack is disconnecting mCurrentDevice");
                        }
                    } else if (mTargetDevice != null && mTargetDevice.equals(device)) {
                        Log.e(TAG, "TargetDevice is getting disconnected");
                    } else if (mIncomingDevice != null && mIncomingDevice.equals(device)) {
                        Log.e(TAG, "IncomingDevice is getting disconnected");
                    } else {
                        Log.e(TAG, "Disconnecting unknow device: " + device);
                    }
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
            // Remove pending connection attempts that were deferred during the pending
            // state. This is to prevent auto connect attempts from disconnecting
            // devices that previously successfully connected.
            // TODO: This needs to check for multiple A2DP connections, once supported...
            removeDeferredMessages(CONNECT);

            if (DBG) {
                Log.d(TAG, "Enter Connected: " + getCurrentMessage().what);
            }
            if (mTargetDevice != null || mIncomingDevice != null) {
                Log.e(TAG, "ERROR: enter() inconsistent state in Connected: current = "
                        + mCurrentDevice + " target = " + mTargetDevice + " incoming = "
                        + mIncomingDevice);
            }

            // remove timeout for connected device only.
            if (mTargetDevice == null) {
                removeMessages(CONNECT_TIMEOUT);
            }
            // Upon connected, the audio starts out as stopped
            broadcastAudioState(mCurrentDevice, BluetoothA2dp.STATE_NOT_PLAYING,
                    BluetoothA2dp.STATE_PLAYING);
        }

        @Override
        public boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Connected process message: " + message.what);
            }
            if (mCurrentDevice == null) {
                Log.e(TAG, "ERROR: mCurrentDevice is null in Connected");
                return NOT_HANDLED;
            }

            boolean retValue = HANDLED;
            switch (message.what) {
                case CONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (mCurrentDevice.equals(device)) {
                        break;
                    }

                    broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                            BluetoothProfile.STATE_DISCONNECTED);
                    if (!mA2dpNativeInterface.disconnectA2dp(mCurrentDevice)) {
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        break;
                    } else {
                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTING,
                                BluetoothProfile.STATE_CONNECTED);
                    }

                    synchronized (A2dpStateMachine.this) {
                        mTargetDevice = device;
                        transitionTo(mPending);
                    }
                }
                break;
                case DISCONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(device)) {
                        break;
                    }
                    broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTING,
                            BluetoothProfile.STATE_CONNECTED);
                    if (!mA2dpNativeInterface.disconnectA2dp(device)) {
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_DISCONNECTING);
                        break;
                    }
                    synchronized (A2dpStateMachine.this) {
                        transitionTo(mPending);
                    }
                }
                break;
                case CONNECT_TIMEOUT:
                    if (mTargetDevice == null) {
                        Log.e(TAG, "CONNECT_TIMEOUT received for unknown device");
                    } else {
                        Log.e(TAG, "CONNECT_TIMEOUT received : connected device : " + mCurrentDevice
                                + " : timedout device : " + mTargetDevice);
                        broadcastConnectionState(mTargetDevice, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        mTargetDevice = null;
                    }
                    break;
                case STACK_EVENT:
                    A2dpStackEvent event = (A2dpStackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Connected: stack event: " + event);
                    }
                    switch (event.type) {
                        case A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(event.device, event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
                            processAudioStateEvent(event.device, event.valueInt);
                            break;
                        case A2dpStackEvent.EVENT_TYPE_CODEC_CONFIG_CHANGED:
                            processCodecConfigEvent(event.device, event.codecStatus);
                            break;
                        default:
                            Log.e(TAG, "Unexpected stack event: " + event);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return retValue;
        }

        // in Connected state
        private void processConnectionEvent(BluetoothDevice device, int state) {
            switch (state) {
                case CONNECTION_STATE_DISCONNECTED:
                    if (mCurrentDevice.equals(device)) {
                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTED);
                        synchronized (A2dpStateMachine.this) {
                            mCurrentDevice = null;
                            transitionTo(mDisconnected);
                        }
                    } else if (mTargetDevice != null && mTargetDevice.equals(device)) {
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        synchronized (A2dpStateMachine.this) {
                            mTargetDevice = null;
                        }
                        Log.i(TAG, "Disconnected from mTargetDevice in connected state device: "
                                + device);
                    } else {
                        Log.e(TAG, "Disconnected from unknown device: " + device);
                    }
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        private void processAudioStateEvent(BluetoothDevice device, int state) {
            if (!mCurrentDevice.equals(device)) {
                Log.e(TAG, "Audio State Device:" + device + "is different from ConnectedDevice:"
                        + mCurrentDevice);
                return;
            }
            switch (state) {
                case AUDIO_STATE_STARTED:
                    if (mPlayingA2dpDevice == null) {
                        mPlayingA2dpDevice = device;
                        mService.setAvrcpAudioState(BluetoothA2dp.STATE_PLAYING);
                        broadcastAudioState(device, BluetoothA2dp.STATE_PLAYING,
                                BluetoothA2dp.STATE_NOT_PLAYING);
                    }
                    break;
                case AUDIO_STATE_REMOTE_SUSPEND:
                case AUDIO_STATE_STOPPED:
                    if (mPlayingA2dpDevice != null) {
                        mPlayingA2dpDevice = null;
                        mService.setAvrcpAudioState(BluetoothA2dp.STATE_NOT_PLAYING);
                        broadcastAudioState(device, BluetoothA2dp.STATE_NOT_PLAYING,
                                BluetoothA2dp.STATE_PLAYING);
                    }
                    break;
                default:
                    Log.e(TAG, "Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }
    }

    int getConnectionState(BluetoothDevice device) {
        if (getCurrentState() == mDisconnected) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        synchronized (this) {
            IState currentState = getCurrentState();
            if (currentState == mPending) {
                if ((mTargetDevice != null) && mTargetDevice.equals(device)) {
                    return BluetoothProfile.STATE_CONNECTING;
                }
                if ((mCurrentDevice != null) && mCurrentDevice.equals(device)) {
                    return BluetoothProfile.STATE_DISCONNECTING;
                }
                if ((mIncomingDevice != null) && mIncomingDevice.equals(device)) {
                    return BluetoothProfile.STATE_CONNECTING; // incoming connection
                }
                return BluetoothProfile.STATE_DISCONNECTED;
            }

            if (currentState == mConnected) {
                if (mCurrentDevice.equals(device)) {
                    return BluetoothProfile.STATE_CONNECTED;
                }
                return BluetoothProfile.STATE_DISCONNECTED;
            } else {
                Log.e(TAG, "Bad currentState: " + currentState);
                return BluetoothProfile.STATE_DISCONNECTED;
            }
        }
    }

    List<BluetoothDevice> getConnectedDevices() {
        List<BluetoothDevice> devices = new ArrayList<BluetoothDevice>();
        synchronized (this) {
            if (getCurrentState() == mConnected) {
                devices.add(mCurrentDevice);
            }
        }
        return devices;
    }

    boolean isPlaying(BluetoothDevice device) {
        synchronized (this) {
            if (device.equals(mPlayingA2dpDevice)) {
                return true;
            }
        }
        return false;
    }

    BluetoothCodecStatus getCodecStatus() {
        synchronized (this) {
            return mCodecStatus;
        }
    }

    // NOTE: This event is processed in any state
    private void processCodecConfigEvent(BluetoothDevice device,
                                         BluetoothCodecStatus newCodecStatus) {
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

        Intent intent = new Intent(BluetoothA2dp.ACTION_CODEC_CONFIG_CHANGED);
        intent.putExtra(BluetoothCodecStatus.EXTRA_CODEC_STATUS, mCodecStatus);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);

        // Inform the Audio Service about the codec configuration change,
        // so the Audio Service can reset accordingly the audio feeding
        // parameters in the Audio HAL to the Bluetooth stack.
        if (!newCodecStatus.getCodecConfig().sameAudioFeedingParameters(prevCodecConfig)
                && (mCurrentDevice != null) && (getCurrentState() == mConnected)) {
            // Add the device only if it is currently connected
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mCurrentDevice);
            mAudioManager.handleBluetoothA2dpDeviceConfigChange(mCurrentDevice);
        }
        mService.sendBroadcast(intent, A2dpService.BLUETOOTH_PERM);
    }

    void setCodecConfigPreference(BluetoothCodecConfig codecConfig) {
        BluetoothCodecConfig[] codecConfigArray = new BluetoothCodecConfig[1];
        codecConfigArray[0] = codecConfig;
        mA2dpNativeInterface.setCodecConfigPreference(codecConfigArray);
    }

    void enableOptionalCodecs() {
        BluetoothCodecConfig[] codecConfigArray = assignCodecConfigPriorities();
        if (codecConfigArray == null) {
            return;
        }

        // Set the mandatory codec's priority to default, and remove the rest
        for (int i = 0; i < codecConfigArray.length; i++) {
            BluetoothCodecConfig codecConfig = codecConfigArray[i];
            if (!codecConfig.isMandatoryCodec()) {
                codecConfigArray[i] = null;
            }
        }

        mA2dpNativeInterface.setCodecConfigPreference(codecConfigArray);
    }

    void disableOptionalCodecs() {
        BluetoothCodecConfig[] codecConfigArray = assignCodecConfigPriorities();
        if (codecConfigArray == null) {
            return;
        }
        // Set the mandatory codec's priority to highest, and ignore the rest
        for (int i = 0; i < codecConfigArray.length; i++) {
            BluetoothCodecConfig codecConfig = codecConfigArray[i];
            if (codecConfig.isMandatoryCodec()) {
                codecConfig.setCodecPriority(BluetoothCodecConfig.CODEC_PRIORITY_HIGHEST);
            } else {
                codecConfigArray[i] = null;
            }
        }
        mA2dpNativeInterface.setCodecConfigPreference(codecConfigArray);
    }

    boolean okToConnect(BluetoothDevice device) {
        AdapterService adapterService = AdapterService.getAdapterService();
        int priority = mService.getPriority(device);
        //check if this is an incoming connection in Quiet mode.
        if ((adapterService == null) || ((adapterService.isQuietModeEnabled()) && (mTargetDevice
                == null))) {
            return false;
        }
        // check priority and accept or reject the connection. if priority is undefined
        // it is likely that our SDP has not completed and peer is initiating the
        // connection. Allow this connection, provided the device is bonded
        if ((BluetoothProfile.PRIORITY_OFF < priority) || (
                (BluetoothProfile.PRIORITY_UNDEFINED == priority) && (device.getBondState()
                        != BluetoothDevice.BOND_NONE))) {
            return true;
        }
        return false;
    }

    synchronized List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        List<BluetoothDevice> deviceList = new ArrayList<BluetoothDevice>();
        Set<BluetoothDevice> bondedDevices = mAdapter.getBondedDevices();
        int connectionState;

        for (BluetoothDevice device : bondedDevices) {
            ParcelUuid[] featureUuids = device.getUuids();
            if (!BluetoothUuid.isUuidPresent(featureUuids, BluetoothUuid.AudioSink)) {
                continue;
            }
            connectionState = getConnectionState(device);
            for (int i = 0; i < states.length; i++) {
                if (connectionState == states[i]) {
                    deviceList.add(device);
                }
            }
        }
        return deviceList;
    }

    // This method does not check for error conditon (newState == prevState)
    private void broadcastConnectionState(BluetoothDevice device, int newState,
                                          int prevState) {
        if (DBG) {
            Log.d(TAG, "Connection state " + device + ": " + prevState + "->" + newState);
        }

        mAudioManager.setBluetoothA2dpDeviceConnectionState(device, newState,
                BluetoothProfile.A2DP);

        Intent intent = new Intent(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void broadcastAudioState(BluetoothDevice device, int newState,
                                     int prevState) {
        if (DBG) {
            Log.d(TAG, "A2DP Playing state : device: " + device + " State:" + prevState
                    + "->" + newState);
        }

        Intent intent = new Intent(BluetoothA2dp.ACTION_PLAYING_STATE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        mService.sendBroadcast(intent, A2dpService.BLUETOOTH_PERM);
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mCurrentDevice: " + mCurrentDevice);
        ProfileService.println(sb, "mTargetDevice: " + mTargetDevice);
        ProfileService.println(sb, "mIncomingDevice: " + mIncomingDevice);
        ProfileService.println(sb, "mPlayingA2dpDevice: " + mPlayingA2dpDevice);
        ProfileService.println(sb, "StateMachine: " + this.toString());
    }

    // Do not modify without updating the HAL bt_av.h files.

    // match up with btav_connection_state_t enum of bt_av.h
    static final int CONNECTION_STATE_DISCONNECTED = 0;
    static final int CONNECTION_STATE_CONNECTING = 1;
    static final int CONNECTION_STATE_CONNECTED = 2;
    static final int CONNECTION_STATE_DISCONNECTING = 3;

    // match up with btav_audio_state_t enum of bt_av.h
    static final int AUDIO_STATE_REMOTE_SUSPEND = 0;
    static final int AUDIO_STATE_STOPPED = 1;
    static final int AUDIO_STATE_STARTED = 2;
}
