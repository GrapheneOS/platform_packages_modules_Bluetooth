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

package com.android.bluetooth.hfp;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAssignedNumbers;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.net.Uri;
import android.os.IDeviceIdleController;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.UserHandle;
import android.support.annotation.VisibleForTesting;
import android.telephony.PhoneNumberUtils;
import android.util.Log;

import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bluetooth Handset StateMachine
 *                        (Disconnected)
 *                           |      ^
 *                   CONNECT |      | DISCONNECTED
 *                           V      |
 *                  (Connecting)   (Disconnecting)
 *                           |      ^
 *                 CONNECTED |      | DISCONNECT
 *                           V      |
 *                          (Connected)
 *                           |      ^
 *             CONNECT_AUDIO |      | AUDIO_DISCONNECTED
 *                           V      |
 *             (AudioConnecting)   (AudioDiconnecting)
 *                           |      ^
 *           AUDIO_CONNECTED |      | DISCONNECT_AUDIO
 *                           V      |
 *                           (AudioOn)
 */
final class HeadsetStateMachine extends StateMachine {
    private static final String TAG = "HeadsetStateMachine";
    private static final boolean DBG = false;

    private static final String HEADSET_NAME = "bt_headset_name";
    private static final String HEADSET_NREC = "bt_headset_nrec";
    private static final String HEADSET_WBS = "bt_wbs";

    /* Telephone URI scheme */
    private static final String SCHEME_TEL = "tel";

    static final int CONNECT = 1;
    static final int DISCONNECT = 2;
    static final int CONNECT_AUDIO = 3;
    static final int DISCONNECT_AUDIO = 4;
    static final int VOICE_RECOGNITION_START = 5;
    static final int VOICE_RECOGNITION_STOP = 6;

    // message.obj is an intent AudioManager.VOLUME_CHANGED_ACTION
    // EXTRA_VOLUME_STREAM_TYPE is STREAM_BLUETOOTH_SCO
    static final int INTENT_SCO_VOLUME_CHANGED = 7;
    static final int INTENT_CONNECTION_ACCESS_REPLY = 8;
    static final int CALL_STATE_CHANGED = 9;
    static final int DEVICE_STATE_CHANGED = 11;
    static final int SEND_CCLC_RESPONSE = 12;
    static final int SEND_VENDOR_SPECIFIC_RESULT_CODE = 13;

    static final int VIRTUAL_CALL_START = 14;
    static final int VIRTUAL_CALL_STOP = 15;

    static final int STACK_EVENT = 101;
    private static final int DIALING_OUT_TIMEOUT = 102;
    private static final int START_VR_TIMEOUT = 103;
    private static final int CLCC_RSP_TIMEOUT = 104;

    private static final int CONNECT_TIMEOUT = 201;

    private static final int DIALING_OUT_TIMEOUT_VALUE = 10000;
    private static final int START_VR_TIMEOUT_VALUE = 5000;
    private static final int CLCC_RSP_TIMEOUT_VALUE = 5000;
    // NOTE: the value is not "final" - it is modified in the unit tests
    @VisibleForTesting static int sConnectTimeoutMillis = 30000;

    private BluetoothDevice mCurrentDevice;

    // State machine states
    private final Disconnected mDisconnected = new Disconnected();
    private final Connecting mConnecting = new Connecting();
    private final Disconnecting mDisconnecting = new Disconnecting();
    private final Connected mConnected = new Connected();
    private final AudioOn mAudioOn = new AudioOn();
    private final AudioConnecting mAudioConnecting = new AudioConnecting();
    private final AudioDisconnecting mAudioDisconnecting = new AudioDisconnecting();
    private HeadsetStateBase mPrevState;

    // Run time dependencies
    private final HeadsetService mService;
    private final HeadsetNativeInterface mNativeInterface;
    private final HeadsetSystemInterface mSystemInterface;
    private final BluetoothAdapter mAdapter;

    // Runtime states
    private boolean mVirtualCallStarted;
    private boolean mVoiceRecognitionStarted;
    private boolean mWaitingForVoiceRecognition;
    private boolean mDialingOut;
    private int mSpeakerVolume;
    private int mMicVolume;
    // Indicates whether audio can be routed to the device.
    private boolean mAudioRouteAllowed = true;
    // Indicates whether SCO audio needs to be forced to open regardless ANY OTHER restrictions
    private boolean mForceScoAudio;
    // Audio Parameters like NREC
    private final HashMap<String, Integer> mAudioParams = new HashMap<>();
    // AT Phone book keeps a group of states used by AT+CPBR commands
    private final AtPhonebook mPhonebook;

    private static final ParcelUuid[] HEADSET_UUIDS = {
            BluetoothUuid.HSP, BluetoothUuid.Handsfree,
    };
    // Keys are AT commands, and values are the company IDs.
    private static final Map<String, Integer> VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID;
    // Intent that get sent during voice recognition events.
    private static final Intent VOICE_COMMAND_INTENT;

    static {
        VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID = new HashMap<>();
        VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID.put(
                BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XEVENT,
                BluetoothAssignedNumbers.PLANTRONICS);
        VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID.put(
                BluetoothHeadset.VENDOR_RESULT_CODE_COMMAND_ANDROID,
                BluetoothAssignedNumbers.GOOGLE);
        VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID.put(
                BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XAPL,
                BluetoothAssignedNumbers.APPLE);
        VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID.put(
                BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_IPHONEACCEV,
                BluetoothAssignedNumbers.APPLE);
        VOICE_COMMAND_INTENT = new Intent(Intent.ACTION_VOICE_COMMAND);
        VOICE_COMMAND_INTENT.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    }

    private HeadsetStateMachine(Looper looper, HeadsetService service,
            HeadsetNativeInterface nativeInterface, HeadsetSystemInterface systemInterface) {
        super(TAG, looper);
        // Enable/Disable StateMachine debug logs
        setDbg(DBG);
        mService = service;
        mNativeInterface = nativeInterface;
        mSystemInterface = systemInterface;

        // Connect to system services and construct helper objects
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mPhonebook = new AtPhonebook(mService, mNativeInterface);

        // Initialize state machine
        addState(mDisconnected);
        addState(mConnecting);
        addState(mDisconnecting);
        addState(mConnected);
        addState(mAudioOn);
        addState(mAudioConnecting);
        addState(mAudioDisconnecting);
        setInitialState(mDisconnected);
    }

    static HeadsetStateMachine make(Looper looper, HeadsetService service,
            HeadsetNativeInterface nativeInterface, HeadsetSystemInterface systemInterface) {
        Log.i(TAG, "make");
        HeadsetStateMachine stateMachine =
                new HeadsetStateMachine(looper, service, nativeInterface, systemInterface);
        stateMachine.start();
        return stateMachine;
    }

    static void destroy(HeadsetStateMachine stateMachine) {
        Log.i(TAG, "destroy");
        if (stateMachine == null) {
            Log.w(TAG, "destroy(), stateMachine is null");
            return;
        }
        stateMachine.quitNow();
        stateMachine.cleanup();
    }

    public void cleanup() {
        if (mPhonebook != null) {
            mPhonebook.cleanup();
        }
        mAudioParams.clear();
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mCurrentDevice: " + mCurrentDevice);
        ProfileService.println(sb, "mVirtualCallStarted: " + mVirtualCallStarted);
        ProfileService.println(sb, "mVoiceRecognitionStarted: " + mVoiceRecognitionStarted);
        ProfileService.println(sb, "mWaitingForVoiceRecognition: " + mWaitingForVoiceRecognition);
        ProfileService.println(sb, "mForceScoAudio: " + mForceScoAudio);
        ProfileService.println(sb, "mDialingOut: " + mDialingOut);
        ProfileService.println(sb, "mAudioRouteAllowed: " + mAudioRouteAllowed);
        ProfileService.println(sb, "StateMachine: " + this);
        ProfileService.println(sb, "PreviousState: " + mPrevState);
        ProfileService.println(sb, "mAudioState: " + getAudioState());
        // Dump the state machine logs
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        super.dump(new FileDescriptor(), printWriter, new String[]{});
        printWriter.flush();
        stringWriter.flush();
        ProfileService.println(sb, "StateMachineLog: " + stringWriter.toString());
    }

    /**
     * Base class for states used in this state machine to share common infrastructures
     */
    private abstract class HeadsetStateBase extends State {
        @Override
        public void enter() {
            // Crash if current device is null and state is not Disconnected
            if (!(this instanceof Disconnected) && mCurrentDevice == null) {
                throw new IllegalStateException("mCurrentDevice is null on enter()");
            }
            // Crash if mPrevState is null and state is not Disconnected
            if (!(this instanceof Disconnected) && mPrevState == null) {
                throw new IllegalStateException("mPrevState is null on enter()");
            }
            enforceValidConnectionStateTransition();
        }

        @Override
        public void exit() {
            Message message = getCurrentMessage();
            if (message != null && !isQuit(message) && mCurrentDevice == null) {
                throw new IllegalStateException(
                        "mCurrentDevice is null on exit() to non-quitting state");
            }
            mPrevState = this;
        }

        @Override
        public String toString() {
            return getName();
        }

        /**
         * Broadcast audio and connection state changes to the system. This should be called at the
         * end of enter() method after all the setup is done
         */
        void broadcastStateTransitions() {
            if (mPrevState == null || mCurrentDevice == null) {
                return;
            }
            // TODO: Add STATE_AUDIO_DISCONNECTING constant to get rid of the 2nd part of this logic
            if (getAudioStateInt() != mPrevState.getAudioStateInt() || (
                    mPrevState instanceof AudioDisconnecting && this instanceof AudioOn)) {
                stateLogD("audio state changed: " + mCurrentDevice + ": " + mPrevState + " -> "
                        + this);
                broadcastAudioState(mCurrentDevice, mPrevState.getAudioStateInt(),
                        getAudioStateInt());
            }
            if (getConnectionStateInt() != mPrevState.getConnectionStateInt()) {
                stateLogD("connection state changed: " + mCurrentDevice + ": " + mPrevState + " -> "
                        + this);
                broadcastConnectionState(mCurrentDevice, mPrevState.getConnectionStateInt(),
                        getConnectionStateInt());
            }
        }

        // Should not be called from enter() method
        void broadcastConnectionState(BluetoothDevice device, int fromState, int toState) {
            stateLogD("broadcastConnectionState " + device + ": " + fromState + "->" + toState);
            if (fromState == BluetoothProfile.STATE_CONNECTED) {
                // Headset is disconnecting, stop Virtual call if active.
                terminateScoUsingVirtualVoiceCall();
            }
            mService.connectionStateChanged(device, fromState, toState);
            Intent intent = new Intent(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
            intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, fromState);
            intent.putExtra(BluetoothProfile.EXTRA_STATE, toState);
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
            intent.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
            mService.sendBroadcastAsUser(intent, UserHandle.ALL, HeadsetService.BLUETOOTH_PERM);
        }

        // Should not be called from enter() method
        void broadcastAudioState(BluetoothDevice device, int fromState, int toState) {
            stateLogD("broadcastAudioState: " + device + ": " + fromState + "->" + toState);
            if (fromState == BluetoothHeadset.STATE_AUDIO_CONNECTED) {
                // When SCO gets disconnected during call transfer, Virtual call
                // needs to be cleaned up.So call terminateScoUsingVirtualVoiceCall.
                terminateScoUsingVirtualVoiceCall();
            }
            Intent intent = new Intent(BluetoothHeadset.ACTION_AUDIO_STATE_CHANGED);
            intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, fromState);
            intent.putExtra(BluetoothProfile.EXTRA_STATE, toState);
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
            mService.sendBroadcastAsUser(intent, UserHandle.ALL, HeadsetService.BLUETOOTH_PERM);
        }

        /**
         * Verify if the current state transition is legal. This is supposed to be called from
         * enter() method and crash if the state transition is out of the specification
         *
         * Note:
         * This method uses state objects to verify transition because these objects should be final
         * and any other instances are invalid
         */
        void enforceValidConnectionStateTransition() {
            boolean result = false;
            if (this == mDisconnected) {
                result = mPrevState == null || mPrevState == mConnecting
                        || mPrevState == mDisconnecting
                        // TODO: edges to be removed after native stack refactoring
                        // all transitions to disconnected state should go through a pending state
                        // also, states should not go directly from an active audio state to
                        // disconnected state
                        || mPrevState == mConnected || mPrevState == mAudioOn
                        || mPrevState == mAudioConnecting || mPrevState == mAudioDisconnecting;
            } else if (this == mConnecting) {
                result = mPrevState == mDisconnected;
            } else if (this == mDisconnecting) {
                result = mPrevState == mConnected
                        // TODO: edges to be removed after native stack refactoring
                        // all transitions to disconnecting state should go through connected state
                        || mPrevState == mAudioConnecting || mPrevState == mAudioOn
                        || mPrevState == mAudioDisconnecting;
            } else if (this == mConnected) {
                result = mPrevState == mConnecting || mPrevState == mAudioDisconnecting
                        || mPrevState == mDisconnecting || mPrevState == mAudioConnecting
                        // TODO: edges to be removed after native stack refactoring
                        // all transitions to connected state should go through a pending state
                        || mPrevState == mAudioOn || mPrevState == mDisconnected;
            } else if (this == mAudioConnecting) {
                result = mPrevState == mConnected;
            } else if (this == mAudioDisconnecting) {
                result = mPrevState == mAudioOn;
            } else if (this == mAudioOn) {
                result = mPrevState == mAudioConnecting || mPrevState == mAudioDisconnecting
                        // TODO: edges to be removed after native stack refactoring
                        // all transitions to audio connected state should go through a pending
                        // state
                        || mPrevState == mConnected;
            }
            if (!result) {
                throw new IllegalStateException(
                        "Invalid state transition from " + mPrevState + " to " + this
                                + " for device " + mCurrentDevice);
            }
        }

        void stateLogD(String msg) {
            log(getName() + ": " + msg);
        }

        void stateLogW(String msg) {
            logw(getName() + ": " + msg);
        }

        void stateLogE(String msg) {
            loge(getName() + ": " + msg);
        }

        void stateLogV(String msg) {
            logv(getName() + ": " + msg);
        }

        void stateLogI(String msg) {
            logi(getName() + ": " + msg);
        }

        void stateLogWtfStack(String msg) {
            Log.wtfStack(TAG, getName() + ": " + msg);
        }

        /**
         * Process connection event
         *
         * @param message the current message for the event
         * @param state connection state to transition to
         * @param device associated device
         */
        public abstract void processConnectionEvent(Message message, int state,
                BluetoothDevice device);

        /**
         * Get a state value from {@link BluetoothProfile} that represents the connection state of
         * this headset state
         *
         * @return a value in {@link BluetoothProfile#STATE_DISCONNECTED},
         * {@link BluetoothProfile#STATE_CONNECTING}, {@link BluetoothProfile#STATE_CONNECTED}, or
         * {@link BluetoothProfile#STATE_DISCONNECTING}
         */
        abstract int getConnectionStateInt();

        /**
         * Get an audio state value from {@link BluetoothHeadset}
         * @return a value in {@link BluetoothHeadset#STATE_AUDIO_DISCONNECTED},
         * {@link BluetoothHeadset#STATE_AUDIO_CONNECTING}, or
         * {@link BluetoothHeadset#STATE_AUDIO_CONNECTED}
         */
        abstract int getAudioStateInt();

    }

    class Disconnected extends HeadsetStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_DISCONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            mPhonebook.resetAtState();
            mSystemInterface.getHeadsetPhoneState().listenForPhoneState(false);
            mVoiceRecognitionStarted = false;
            mWaitingForVoiceRecognition = false;
            mAudioParams.clear();
            processWBSEvent(HeadsetHalConstants.BTHF_WBS_NO);
            broadcastStateTransitions();
            mCurrentDevice = null;
        }

        @Override
        public boolean processMessage(Message message) {
            if (mCurrentDevice != null) {
                stateLogE("mCurrentDevice is not null");
                return NOT_HANDLED;
            }
            switch (message.what) {
                case CONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    stateLogD("Connecting to " + device);
                    if (!mNativeInterface.connectHfp(device)) {
                        // No state transition is involved, fire broadcast immediately
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                        break;
                    }
                    mCurrentDevice = device;
                    transitionTo(mConnecting);
                    break;
                case DISCONNECT:
                    // ignore
                    break;
                case CALL_STATE_CHANGED:
                    processCallState((HeadsetCallState) message.obj, message.arg1 == 1);
                    break;
                case DEVICE_STATE_CHANGED:
                    stateLogD("Ignoring DEVICE_STATE_CHANGED event");
                    break;
                case STACK_EVENT:
                    HeadsetStackEvent event = (HeadsetStackEvent) message.obj;
                    stateLogD("STACK_EVENT: " + event);
                    switch (event.type) {
                        case HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(message, event.valueInt, event.device);
                            break;
                        default:
                            stateLogE("Unexpected stack event: " + event);
                            break;
                    }
                    break;
                default:
                    stateLogE("Unexpected msg " + getMessageName(message.what) + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnected state
        @Override
        public void processConnectionEvent(Message message, int state, BluetoothDevice device) {
            stateLogD("processConnectionEvent, state=" + state + ", device=" + device);
            switch (state) {
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED:
                    stateLogW("ignore DISCONNECTED event, device=" + device);
                    break;
                // Both events result in Connecting state as SLC establishment is still required
                case HeadsetHalConstants.CONNECTION_STATE_CONNECTED:
                case HeadsetHalConstants.CONNECTION_STATE_CONNECTING:
                    if (okToAcceptConnection(device)) {
                        stateLogI("connected/connecting incoming HF, device=" + device);
                        mCurrentDevice = device;
                        transitionTo(mConnecting);
                    } else {
                        stateLogI("rejected incoming HF, priority=" + mService.getPriority(device)
                                + " bondState=" + device.getBondState() + ", device=" + device);
                        // Reject the connection and stay in Disconnected state itself
                        if (!mNativeInterface.disconnectHfp(device)) {
                            stateLogE("Failed to disconnect from " + device);
                        }
                        // Indicate rejection to other components.
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                    }
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING:
                    stateLogW("Ignore DISCONNECTING event, device=" + device);
                    break;
                default:
                    stateLogE("Incorrect state: " + state);
                    break;
            }
        }
    }

    // Per HFP 1.7.1 spec page 23/144, Pending state needs to handle
    //      AT+BRSF, AT+CIND, AT+CMER, AT+BIND, +CHLD
    // commands during SLC establishment
    class Connecting extends HeadsetStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_CONNECTING;
        }

        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_DISCONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            sendMessageDelayed(CONNECT_TIMEOUT, mCurrentDevice, sConnectTimeoutMillis);
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT:
                    // We timed out trying to connect, transition to Disconnected state
                    stateLogW("Connection timeout for " + mCurrentDevice);
                    transitionTo(mDisconnected);
                    break;
                case CALL_STATE_CHANGED:
                    processCallState((HeadsetCallState) message.obj, message.arg1 == 1);
                    break;
                case DEVICE_STATE_CHANGED:
                    stateLogD("ignoring DEVICE_STATE_CHANGED event");
                    break;
                case STACK_EVENT:
                    HeadsetStackEvent event = (HeadsetStackEvent) message.obj;
                    stateLogD("STACK_EVENT: " + event);
                    switch (event.type) {
                        case HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(message, event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CHLD:
                            processAtChld(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CIND:
                            processAtCind(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_WBS:
                            processWBSEvent(event.valueInt);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIND:
                            processAtBind(event.valueString, event.device);
                            break;
                        // Unexpected AT commands, we only handle them for comparability reasons
                        case HeadsetStackEvent.EVENT_TYPE_VR_STATE_CHANGED:
                            stateLogW("Unexpected VR event, device=" + event.device + ", state="
                                    + event.valueInt);
                            processVrEvent(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_DIAL_CALL:
                            stateLogW("Unexpected dial event, device=" + event.device);
                            processDialCall(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST:
                            stateLogW("Unexpected subscriber number event for" + event.device
                                    + ", state=" + event.valueInt);
                            processSubscriberNumberRequest(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_COPS:
                            stateLogW("Unexpected COPS event for " + event.device);
                            processAtCops(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CLCC:
                            Log.w(TAG, "Connecting: Unexpected CLCC event for" + event.device);
                            processAtClcc(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_UNKNOWN_AT:
                            stateLogW("Unexpected unknown AT event for" + event.device + ", cmd="
                                    + event.valueString);
                            processUnknownAt(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_KEY_PRESSED:
                            stateLogW("Unexpected key-press event for " + event.device);
                            processKeyPressed(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIEV:
                            stateLogW("Unexpected BIEV event for " + event.device + ", indId="
                                    + event.valueInt + ", indVal=" + event.valueInt2);
                            processAtBiev(event.valueInt, event.valueInt2, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_VOLUME_CHANGED:
                            stateLogW("Unexpected volume event for " + event.device);
                            processVolumeEvent(event.valueInt, event.valueInt2, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_ANSWER_CALL:
                            stateLogW("Unexpected answer event for " + event.device);
                            mSystemInterface.answerCall(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_HANGUP_CALL:
                            stateLogW("Unexpected hangup event for " + event.device);
                            mSystemInterface.hangupCall(event.device, isVirtualCallInProgress());
                            break;
                        default:
                            stateLogE("Unexpected event: " + event);
                            break;
                    }
                    break;
                default:
                    stateLogE("Unexpected msg " + getMessageName(message.what) + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        @Override
        public void processConnectionEvent(Message message, int state, BluetoothDevice device) {
            stateLogD("processConnectionEvent, state=" + state + ", device=" + device);
            switch (state) {
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED:
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("Unknown device disconnected" + device);
                        break;
                    }
                    transitionTo(mDisconnected);
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_CONNECTED:
                    stateLogD("RFCOMM connected for " + device);
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("Reject connection from unknown device " + device);
                        if (!mNativeInterface.disconnectHfp(device)) {
                            stateLogE("Disconnect from " + device + " failed");
                        }
                    }
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED:
                    stateLogD("SLC connected for " + device);
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("Reject SLC from unknown device " + device);
                        if (!mNativeInterface.disconnectHfp(device)) {
                            stateLogE("Disconnect SLC from " + device + " failed");
                        }
                        break;
                    }
                    configAudioParameters(device);
                    mSystemInterface.queryPhoneState();
                    transitionTo(mConnected);
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_CONNECTING:
                    // Ignored
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING:
                    stateLogD("Disconnecting for " + device);
                    if (mCurrentDevice.equals(device)) {
                        stateLogW("Current device disconnecting");
                        // ignored, wait for it to be disconnected
                    }
                    break;
                default:
                    stateLogE("Incorrect state " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            removeMessages(CONNECT_TIMEOUT);
            super.exit();
        }
    }

    class Disconnecting extends HeadsetStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_DISCONNECTING;
        }

        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_DISCONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            sendMessageDelayed(CONNECT_TIMEOUT, mCurrentDevice, sConnectTimeoutMillis);
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT:
                    stateLogE("timeout");
                    transitionTo(mDisconnected);
                    break;
                case STACK_EVENT:
                    HeadsetStackEvent event = (HeadsetStackEvent) message.obj;
                    stateLogD("STACK_EVENT: " + event);
                    switch (event.type) {
                        case HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(message, event.valueInt, event.device);
                            break;
                        default:
                            stateLogE("Unexpected event: " + event);
                            break;
                    }
                    break;
                default:
                    stateLogE("Unexpected msg " + getMessageName(message.what) + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnecting state
        @Override
        public void processConnectionEvent(Message message, int state, BluetoothDevice device) {
            if (!mCurrentDevice.equals(device)) {
                stateLogW("processConnectionEvent, unknown device " + device);
                return;
            }
            switch (state) {
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED:
                    stateLogD("Device disconnected, device=" + device);
                    transitionTo(mDisconnected);
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED:
                    stateLogD("Device connected, device=" + device);
                    transitionTo(mConnected);
                    break;
                default:
                    stateLogE("Device: " + device + " bad state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            removeMessages(CONNECT_TIMEOUT);
            super.exit();
        }
    }

    /**
     * Base class for Connected, AudioConnecting, AudioOn, AudioDisconnecting states
     */
    private abstract class ConnectedBase extends HeadsetStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_CONNECTED;
        }

        /**
         * Handle common messages in connected states. However, state specific messages must be
         * handled individually.
         *
         * @param message Incoming message to handle
         * @return True if handled successfully, False otherwise
         */
        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT:
                case DISCONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT_AUDIO:
                case CONNECT_TIMEOUT:
                    stateLogWtfStack("Illegal message in generic handler: " + message);
                    break;
                case VOICE_RECOGNITION_START:
                    processLocalVrEvent(HeadsetHalConstants.VR_STATE_STARTED,
                            (BluetoothDevice) message.obj);
                    break;
                case VOICE_RECOGNITION_STOP:
                    processLocalVrEvent(HeadsetHalConstants.VR_STATE_STOPPED,
                            (BluetoothDevice) message.obj);
                    break;
                case CALL_STATE_CHANGED:
                    processCallState((HeadsetCallState) message.obj, message.arg1 == 1);
                    break;
                case DEVICE_STATE_CHANGED:
                    processDeviceStateChanged((HeadsetDeviceState) message.obj);
                    break;
                case SEND_CCLC_RESPONSE:
                    processSendClccResponse((HeadsetClccResponse) message.obj);
                    break;
                case CLCC_RSP_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    mNativeInterface.clccResponse(device, 0, 0, 0, 0, false, "", 0);
                }
                break;
                case SEND_VENDOR_SPECIFIC_RESULT_CODE:
                    processSendVendorSpecificResultCode(
                            (HeadsetVendorSpecificResultCode) message.obj);
                    break;
                case DIALING_OUT_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (mDialingOut) {
                        mDialingOut = false;
                        mNativeInterface.atResponseCode(device,
                                HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                    }
                }
                break;
                case VIRTUAL_CALL_START:
                    initiateScoUsingVirtualVoiceCall();
                    break;
                case VIRTUAL_CALL_STOP:
                    terminateScoUsingVirtualVoiceCall();
                    break;
                case START_VR_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (mWaitingForVoiceRecognition) {
                        device = (BluetoothDevice) message.obj;
                        mWaitingForVoiceRecognition = false;
                        stateLogE("Timeout waiting for voice recognition to start");
                        mNativeInterface.atResponseCode(device,
                                HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                    }
                }
                break;
                case INTENT_CONNECTION_ACCESS_REPLY:
                    handleAccessPermissionResult((Intent) message.obj);
                    break;
                case STACK_EVENT:
                    HeadsetStackEvent event = (HeadsetStackEvent) message.obj;
                    stateLogD("STACK_EVENT: " + event);
                    switch (event.type) {
                        case HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(message, event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
                            processAudioEvent(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_VR_STATE_CHANGED:
                            processVrEvent(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_ANSWER_CALL:
                            mSystemInterface.answerCall(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_HANGUP_CALL:
                            mSystemInterface.hangupCall(event.device, mVirtualCallStarted);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_VOLUME_CHANGED:
                            processVolumeEvent(event.valueInt, event.valueInt2, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_DIAL_CALL:
                            processDialCall(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_SEND_DTMF:
                            mSystemInterface.sendDtmf(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_NOICE_REDUCTION:
                            processNoiseReductionEvent(event.valueInt == 1, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_WBS:
                            processWBSEvent(event.valueInt);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CHLD:
                            processAtChld(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST:
                            processSubscriberNumberRequest(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CIND:
                            processAtCind(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_COPS:
                            processAtCops(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CLCC:
                            processAtClcc(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_UNKNOWN_AT:
                            processUnknownAt(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_KEY_PRESSED:
                            processKeyPressed(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIND:
                            processAtBind(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIEV:
                            processAtBiev(event.valueInt, event.valueInt2, event.device);
                            break;
                        default:
                            stateLogE("Unknown stack event: " + event);
                            break;
                    }
                    break;
                default:
                    stateLogE("Unexpected msg " + getMessageName(message.what) + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        @Override
        public void processConnectionEvent(Message message, int state, BluetoothDevice device) {
            stateLogD("processConnectionEvent, state=" + state + ", device=" + device);
            switch (state) {
                case HeadsetHalConstants.CONNECTION_STATE_CONNECTED:
                    if (mCurrentDevice.equals(device)) {
                        stateLogE("Same device connect RFCOMM again, should never happen");
                        break;
                    }
                    // reject the connection and stay in Connected state itself
                    stateLogI("Incoming Hf rejected. priority=" + mService.getPriority(device)
                            + " bondState=" + device.getBondState());
                    if (!mNativeInterface.disconnectHfp(device)) {
                        stateLogW("Fail to disconnect " + device);
                        break;
                    }
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED:
                    // Should have been rejected in CONNECTION_STATE_CONNECTED
                    if (mCurrentDevice.equals(device)) {
                        stateLogE("Same device connected SLC again");
                        break;
                    }
                    // reject the connection and stay in Connected state itself
                    stateLogI("Incoming Hf SLC rejected. priority=" + mService.getPriority(device)
                            + " bondState=" + device.getBondState());
                    if (!mNativeInterface.disconnectHfp(device)) {
                        stateLogW("Fail to disconnect " + device);
                        break;
                    }
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING:
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("Unknown device disconnecting, device=" + device);
                        break;
                    }
                    stateLogI("Current device disconnecting " + mCurrentDevice);
                    transitionTo(mDisconnecting);
                    break;
                case HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED:
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("Unknown device disconnected " + device);
                        break;
                    }
                    stateLogI("Current device disconnected " + mCurrentDevice);
                    transitionTo(mDisconnected);
                    break;
                default:
                    stateLogE("Connection State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        /**
         * Each state should handle audio events differently
         *
         * @param state audio state
         * @param device associated device
         */
        public abstract void processAudioEvent(int state, BluetoothDevice device);
    }

    class Connected extends ConnectedBase {
        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_DISCONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            // start phone state listener here so that the CIND response as part of SLC can be
            // responded to, correctly.
            // listenForPhoneState(boolean) internally handles multiple calls to start listen
            mSystemInterface.getHeadsetPhoneState().listenForPhoneState(true);
            if (mPrevState == mConnecting) {
                // Remove pending connection attempts that were deferred during the pending
                // state. This is to prevent auto connect attempts from disconnecting
                // devices that previously successfully connected.
                removeDeferredMessages(CONNECT);
            }
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    stateLogI("CONNECT, device " + device);
                    if (mCurrentDevice.equals(device)) {
                        stateLogW("CONNECT, device " + device + " is already connected");
                        break;
                    }
                    stateLogD("CONNECT, disconnect current device " + mCurrentDevice);
                    if (!mNativeInterface.disconnectHfp(mCurrentDevice)) {
                        stateLogW("CONNECT, Failed to disconnect " + mCurrentDevice);
                        // broadcast immediately as no state transition is involved
                        // TODO: to be removed with multi-HFP implementation
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                        break;
                    }
                    // Defer connect message to future state
                    deferMessage(message);
                    transitionTo(mDisconnecting);
                }
                break;
                case DISCONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    stateLogD("DISCONNECT from device=" + device);
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("DISCONNECT, device " + device + " not connected");
                        break;
                    }
                    if (!mNativeInterface.disconnectHfp(device)) {
                        // broadcast immediately as no state transition is involved
                        stateLogE("DISCONNECT from " + device + " failed");
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_CONNECTED);
                        break;
                    }
                    transitionTo(mDisconnecting);
                }
                break;
                case CONNECT_AUDIO:
                    stateLogD("CONNECT_AUDIO, device=" + mCurrentDevice);
                    if (!isScoAcceptable()) {
                        stateLogW("CONNECT_AUDIO No Active/Held call, no call setup, and no "
                                + "in-band ringing, not allowing SCO, device=" + mCurrentDevice);
                        break;
                    }
                    if (!mNativeInterface.connectAudio(mCurrentDevice)) {
                        stateLogE("Failed to connect SCO audio for " + mCurrentDevice);
                        // No state change involved, fire broadcast immediately
                        broadcastAudioState(mCurrentDevice,
                                BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                                BluetoothHeadset.STATE_AUDIO_DISCONNECTED);
                        break;
                    }
                    transitionTo(mAudioConnecting);
                    break;
                case DISCONNECT_AUDIO:
                    stateLogD("DISCONNECT_AUDIO, device=" + mCurrentDevice);
                    // ignore
                    break;
                default:
                    return super.processMessage(message);
            }
            return HANDLED;
        }

        @Override
        public void processAudioEvent(int state, BluetoothDevice device) {
            stateLogD("processAudioEvent, state=" + state + ", device=" + device);
            if (!mCurrentDevice.equals(device)) {
                // Crash if audio is connected for unknown device
                stateLogWtfStack("Audio changed on unknown device: " + device);
                return;
            }
            switch (state) {
                case HeadsetHalConstants.AUDIO_STATE_CONNECTED:
                    if (!isScoAcceptable()) {
                        stateLogW("Rejecting incoming audio connection from " + device);
                        if (!mNativeInterface.disconnectAudio(device)) {
                            stateLogE("Fail to disconnect audio for " + device);
                        }
                        break;
                    }
                    stateLogI("Audio connected for " + device);
                    transitionTo(mAudioOn);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_CONNECTING:
                    if (!isScoAcceptable()) {
                        stateLogW("Rejecting incoming pending audio connection from " + device);
                        if (!mNativeInterface.disconnectAudio(device)) {
                            stateLogE("Fail to disconnect audio for " + device);
                        }
                        break;
                    }
                    stateLogI("Audio connecting for " + device);
                    transitionTo(mAudioConnecting);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTED:
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTING:
                    // ignore
                    break;
                default:
                    stateLogE("Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }
    }

    class AudioConnecting extends ConnectedBase {
        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_CONNECTING;
        }

        @Override
        public void enter() {
            super.enter();
            sendMessageDelayed(CONNECT_TIMEOUT, mCurrentDevice, sConnectTimeoutMillis);
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT:
                case DISCONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT_AUDIO:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("CONNECT_TIMEOUT for unknown device " + device);
                        break;
                    }
                    stateLogW("CONNECT_TIMEOUT");
                    transitionTo(mConnected);
                    break;
                }
                default:
                    return super.processMessage(message);
            }
            return HANDLED;
        }

        @Override
        public void processAudioEvent(int state, BluetoothDevice device) {
            if (!mCurrentDevice.equals(device)) {
                // Crash on unknown device audio state change
                stateLogWtfStack("Audio state changed on unknown device: " + device);
                return;
            }
            switch (state) {
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTED:
                    stateLogW("Audio connection failed");
                    transitionTo(mConnected);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_CONNECTING:
                    // ignore, already in audio connecting state
                    break;
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTING:
                    // ignore, there is no BluetoothHeadset.STATE_AUDIO_DISCONNECTING
                    break;
                case HeadsetHalConstants.AUDIO_STATE_CONNECTED:
                    stateLogI("Audio connected for device " + device);
                    transitionTo(mAudioOn);
                    break;
                default:
                    stateLogE("Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            removeMessages(CONNECT_TIMEOUT);
            super.exit();
        }
    }

    class AudioOn extends ConnectedBase {
        @Override
        int getAudioStateInt() {
            return BluetoothHeadset.STATE_AUDIO_CONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            removeDeferredMessages(CONNECT_AUDIO);
            setAudioParameters(mCurrentDevice);
            mSystemInterface.getAudioManager().setBluetoothScoOn(true);
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    stateLogD("CONNECT, device=" + device);
                    if (mCurrentDevice.equals(device)) {
                        stateLogW("CONNECT, device " + device + " is connected");
                        break;
                    }
                    // When connecting separate device, disconnect the current one first
                    // Disconnect audio and then disconnect SLC
                    stateLogD("Disconnecting SCO, device=" + mCurrentDevice);
                    if (!mNativeInterface.disconnectAudio(mCurrentDevice)) {
                        stateLogE("Disconnect SCO failed, device=" + mCurrentDevice
                                + ", abort connection to " + device);
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_DISCONNECTED);
                        break;
                    }
                    deferMessage(message);
                    transitionTo(mAudioDisconnecting);
                    break;
                }
                case DISCONNECT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    stateLogD("DISCONNECT, device=" + device);
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("DISCONNECT, device " + device + " not connected");
                        break;
                    }
                    // Disconnect BT SCO first
                    if (!mNativeInterface.disconnectAudio(mCurrentDevice)) {
                        stateLogW("DISCONNECT failed, device=" + mCurrentDevice);
                        // if disconnect BT SCO failed, transition to mConnected state to force
                        // disconnect device
                    }
                    deferMessage(obtainMessage(DISCONNECT, mCurrentDevice));
                    transitionTo(mConnected);
                    break;
                }
                case CONNECT_AUDIO: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("CONNECT_AUDIO device is not connected " + device);
                        break;
                    }
                    stateLogW("CONNECT_AUDIO device auido is already connected " + device);
                    break;
                }
                case DISCONNECT_AUDIO:
                    if (mNativeInterface.disconnectAudio(mCurrentDevice)) {
                        stateLogD("DISCONNECT_AUDIO, device=" + mCurrentDevice);
                        transitionTo(mAudioDisconnecting);
                    } else {
                        stateLogW("DISCONNECT_AUDIO failed, device=" + mCurrentDevice);
                    }
                    break;
                case VOICE_RECOGNITION_START:
                    processLocalVrEvent(HeadsetHalConstants.VR_STATE_STARTED,
                            (BluetoothDevice) message.obj);
                    break;
                case VOICE_RECOGNITION_STOP:
                    processLocalVrEvent(HeadsetHalConstants.VR_STATE_STOPPED,
                            (BluetoothDevice) message.obj);
                    break;
                case INTENT_SCO_VOLUME_CHANGED:
                    processIntentScoVolume((Intent) message.obj, mCurrentDevice);
                    break;
                case CALL_STATE_CHANGED:
                    processCallState((HeadsetCallState) message.obj, message.arg1 == 1);
                    break;
                case DEVICE_STATE_CHANGED:
                    processDeviceStateChanged((HeadsetDeviceState) message.obj);
                    break;
                case SEND_CCLC_RESPONSE:
                    processSendClccResponse((HeadsetClccResponse) message.obj);
                    break;
                case CLCC_RSP_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    mNativeInterface.clccResponse(device, 0, 0, 0, 0, false, "", 0);
                    break;
                }
                case SEND_VENDOR_SPECIFIC_RESULT_CODE:
                    processSendVendorSpecificResultCode(
                            (HeadsetVendorSpecificResultCode) message.obj);
                    break;

                case VIRTUAL_CALL_START:
                    initiateScoUsingVirtualVoiceCall();
                    break;
                case VIRTUAL_CALL_STOP:
                    terminateScoUsingVirtualVoiceCall();
                    break;

                case DIALING_OUT_TIMEOUT: {
                    if (mDialingOut) {
                        BluetoothDevice device = (BluetoothDevice) message.obj;
                        mDialingOut = false;
                        mNativeInterface.atResponseCode(device,
                                HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                    }
                    break;
                }
                case START_VR_TIMEOUT: {
                    if (mWaitingForVoiceRecognition) {
                        BluetoothDevice device = (BluetoothDevice) message.obj;
                        mWaitingForVoiceRecognition = false;
                        stateLogE("Timeout waiting for voice recognition to start");
                        mNativeInterface.atResponseCode(device,
                                HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                    }
                    break;
                }
                case STACK_EVENT:
                    HeadsetStackEvent event = (HeadsetStackEvent) message.obj;
                    stateLogD("STACK_EVENT: " + event);
                    switch (event.type) {
                        case HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            processConnectionEvent(message, event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED:
                            processAudioEvent(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_VR_STATE_CHANGED:
                            processVrEvent(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_ANSWER_CALL:
                            mSystemInterface.answerCall(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_HANGUP_CALL:
                            mSystemInterface.hangupCall(event.device, mVirtualCallStarted);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_VOLUME_CHANGED:
                            processVolumeEvent(event.valueInt, event.valueInt2, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_DIAL_CALL:
                            processDialCall(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_SEND_DTMF:
                            mSystemInterface.sendDtmf(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_NOICE_REDUCTION:
                            processNoiseReductionEvent(event.valueInt == 1, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CHLD:
                            processAtChld(event.valueInt, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST:
                            processSubscriberNumberRequest(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CIND:
                            processAtCind(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_COPS:
                            processAtCops(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_AT_CLCC:
                            processAtClcc(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_UNKNOWN_AT:
                            processUnknownAt(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_KEY_PRESSED:
                            processKeyPressed(event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIND:
                            processAtBind(event.valueString, event.device);
                            break;
                        case HeadsetStackEvent.EVENT_TYPE_BIEV:
                            processAtBiev(event.valueInt, event.valueInt2, event.device);
                            break;
                        default:
                            stateLogE("Unknown stack event: " + event);
                            break;
                    }
                    break;
                default:
                    stateLogE("Unexpected msg " + getMessageName(message.what) + ": " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in AudioOn state
        @Override
        public void processAudioEvent(int state, BluetoothDevice device) {
            if (!mCurrentDevice.equals(device)) {
                stateLogE("Audio changed on unknown device: " + device);
                return;
            }
            switch (state) {
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTED:
                    stateLogI("Audio disconnected by remote");
                    transitionTo(mConnected);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTING:
                    stateLogI("Audio being disconnected by remote");
                    transitionTo(mAudioDisconnecting);
                    break;
                default:
                    stateLogE("Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        private void processIntentScoVolume(Intent intent, BluetoothDevice device) {
            int volumeValue = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_VALUE, 0);
            if (mSpeakerVolume != volumeValue) {
                mSpeakerVolume = volumeValue;
                mNativeInterface.setVolume(device, HeadsetHalConstants.VOLUME_TYPE_SPK,
                        mSpeakerVolume);
            }
        }

        @Override
        public void exit() {
            mSystemInterface.getAudioManager().setBluetoothScoOn(false);
            super.exit();
        }
    }

    class AudioDisconnecting extends ConnectedBase {
        @Override
        int getAudioStateInt() {
            // TODO: need BluetoothHeadset.STATE_AUDIO_DISCONNECTING
            return BluetoothHeadset.STATE_AUDIO_CONNECTED;
        }

        @Override
        public void enter() {
            super.enter();
            sendMessageDelayed(CONNECT_TIMEOUT, mCurrentDevice, sConnectTimeoutMillis);
            broadcastStateTransitions();
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case CONNECT:
                case DISCONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT_AUDIO:
                    deferMessage(message);
                    break;
                case CONNECT_TIMEOUT: {
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(device)) {
                        stateLogW("CONNECT_TIMEOUT for unknown device " + device);
                        break;
                    }
                    stateLogW("CONNECT_TIMEOUT");
                    transitionTo(mConnected);
                    break;
                }
                default:
                    return super.processMessage(message);
            }
            return HANDLED;
        }

        @Override
        public void processAudioEvent(int state, BluetoothDevice device) {
            if (!mCurrentDevice.equals(device)) {
                // Crash if audio state change happen for unknown device
                stateLogWtfStack("Audio changed on unknown device: " + device);
                return;
            }
            switch (state) {
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTED:
                    stateLogI("Audio disconnected for " + device);
                    transitionTo(mConnected);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_DISCONNECTING:
                    // ignore
                    break;
                case HeadsetHalConstants.AUDIO_STATE_CONNECTED:
                    stateLogW("Audio disconnection failed for " + device);
                    transitionTo(mAudioOn);
                    break;
                case HeadsetHalConstants.AUDIO_STATE_CONNECTING:
                    // ignore, see if it goes into connected state, otherwise, timeout
                    break;
                default:
                    stateLogE("Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            removeMessages(CONNECT_TIMEOUT);
            super.exit();
        }
    }

    synchronized BluetoothDevice getCurrentDevice() {
        return mCurrentDevice;
    }

    synchronized int getConnectionState(BluetoothDevice device) {
        if (mCurrentDevice == null) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }
        if (!mCurrentDevice.equals(device)) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }
        return ((HeadsetStateBase) getCurrentState()).getConnectionStateInt();
    }

    List<BluetoothDevice> getConnectedDevices() {
        List<BluetoothDevice> devices = new ArrayList<>();
        synchronized (this) {
            if (getCurrentState() instanceof ConnectedBase) {
                devices.add(mCurrentDevice);
            }
        }
        return devices;
    }

    void setAudioRouteAllowed(boolean allowed) {
        mAudioRouteAllowed = allowed;
        mNativeInterface.setScoAllowed(allowed);
    }

    boolean getAudioRouteAllowed() {
        return mAudioRouteAllowed;
    }

    void setForceScoAudio(boolean forced) {
        mForceScoAudio = forced;
    }

    synchronized int getAudioState() {
        return ((HeadsetStateBase) getCurrentState()).getAudioStateInt();
    }

    private void processVrEvent(int state, BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processVrEvent device is null");
            return;
        }
        Log.d(TAG, "processVrEvent: state=" + state + " mVoiceRecognitionStarted: "
                + mVoiceRecognitionStarted + " mWaitingforVoiceRecognition: "
                + mWaitingForVoiceRecognition + " isInCall: " + isInCall());
        if (state == HeadsetHalConstants.VR_STATE_STARTED) {
            if (!isVirtualCallInProgress() && !isInCall()) {
                IDeviceIdleController dic = IDeviceIdleController.Stub.asInterface(
                        ServiceManager.getService(Context.DEVICE_IDLE_CONTROLLER));
                if (dic != null) {
                    try {
                        dic.exitIdle("voice-command");
                    } catch (RemoteException e) {
                    }
                }
                try {
                    mService.startActivity(VOICE_COMMAND_INTENT);
                } catch (ActivityNotFoundException e) {
                    mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR,
                            0);
                    return;
                }
                expectVoiceRecognition(device);
            } else {
                // send error response if call is ongoing
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                return;
            }
        } else if (state == HeadsetHalConstants.VR_STATE_STOPPED) {
            if (mVoiceRecognitionStarted || mWaitingForVoiceRecognition) {
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
                mVoiceRecognitionStarted = false;
                mWaitingForVoiceRecognition = false;
                if (!isInCall() && (getAudioState() != BluetoothHeadset.STATE_AUDIO_DISCONNECTED)) {
                    mNativeInterface.disconnectAudio(mCurrentDevice);
                    mSystemInterface.getAudioManager().setParameters("A2dpSuspended=false");
                }
            } else {
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
            }
        } else {
            Log.e(TAG, "Bad Voice Recognition state: " + state);
        }
    }

    private void processLocalVrEvent(int state, BluetoothDevice device1) {
        BluetoothDevice device = null;
        if (state == HeadsetHalConstants.VR_STATE_STARTED) {
            boolean needAudio = true;
            if (mVoiceRecognitionStarted || isInCall()) {
                Log.e(TAG, "Voice recognition started when call is active. isInCall:" + isInCall()
                        + " mVoiceRecognitionStarted: " + mVoiceRecognitionStarted);
                return;
            }
            mVoiceRecognitionStarted = true;

            if (mWaitingForVoiceRecognition) {
                device = getDeviceForMessage(START_VR_TIMEOUT);
                if (device == null) {
                    return;
                }

                Log.d(TAG, "Voice recognition started successfully");
                mWaitingForVoiceRecognition = false;
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
                removeMessages(START_VR_TIMEOUT);
            } else {
                Log.d(TAG, "Voice recognition started locally");
                needAudio = mNativeInterface.startVoiceRecognition(mCurrentDevice);
                if (mCurrentDevice != null) {
                    device = mCurrentDevice;
                }
            }

            if (needAudio && getAudioState() == BluetoothHeadset.STATE_AUDIO_DISCONNECTED) {
                Log.d(TAG, "Initiating audio connection for Voice Recognition");
                // At this stage, we need to be sure that AVDTP is not streaming. This is needed
                // to be compliant with the AV+HFP Whitepaper as we cannot have A2DP in
                // streaming state while a SCO connection is established.
                // This is needed for VoiceDial scenario alone and not for
                // incoming call/outgoing call scenarios as the phone enters MODE_RINGTONE
                // or MODE_IN_CALL which shall automatically suspend the AVDTP stream if needed.
                // Whereas for VoiceDial we want to activate the SCO connection but we are still
                // in MODE_NORMAL and hence the need to explicitly suspend the A2DP stream
                mSystemInterface.getAudioManager().setParameters("A2dpSuspended=true");
                if (device != null) {
                    mNativeInterface.connectAudio(device);
                } else {
                    Log.e(TAG, "device not found for VR");
                }
            }

            if (mSystemInterface.getVoiceRecognitionWakeLock().isHeld()) {
                mSystemInterface.getVoiceRecognitionWakeLock().release();
            }
        } else {
            Log.d(TAG, "Voice Recognition stopped. mVoiceRecognitionStarted: "
                    + mVoiceRecognitionStarted + " mWaitingForVoiceRecognition: "
                    + mWaitingForVoiceRecognition);
            if (mVoiceRecognitionStarted || mWaitingForVoiceRecognition) {
                mVoiceRecognitionStarted = false;
                mWaitingForVoiceRecognition = false;

                if (mNativeInterface.stopVoiceRecognition(mCurrentDevice) && !isInCall()
                        && getAudioState() != BluetoothHeadset.STATE_AUDIO_DISCONNECTED) {
                    mNativeInterface.disconnectAudio(mCurrentDevice);
                    mSystemInterface.getAudioManager().setParameters("A2dpSuspended=false");
                }
            }
        }
    }

    private synchronized void expectVoiceRecognition(BluetoothDevice device) {
        mWaitingForVoiceRecognition = true;
        Message m = obtainMessage(START_VR_TIMEOUT);
        m.obj = getMatchingDevice(device);
        sendMessageDelayed(m, START_VR_TIMEOUT_VALUE);

        if (!mSystemInterface.getVoiceRecognitionWakeLock().isHeld()) {
            mSystemInterface.getVoiceRecognitionWakeLock().acquire(START_VR_TIMEOUT_VALUE);
        }
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        List<BluetoothDevice> deviceList = new ArrayList<BluetoothDevice>();
        Set<BluetoothDevice> bondedDevices = mAdapter.getBondedDevices();
        if (bondedDevices == null) {
            return deviceList;
        }
        synchronized (this) {
            for (BluetoothDevice device : bondedDevices) {
                ParcelUuid[] featureUuids = device.getUuids();
                if (!BluetoothUuid.containsAnyUuid(featureUuids, HEADSET_UUIDS)) {
                    continue;
                }
                int connectionState = getConnectionState(device);
                for (int state : states) {
                    if (connectionState == state) {
                        deviceList.add(device);
                    }
                }
            }
        }
        return deviceList;
    }

    private BluetoothDevice getDeviceForMessage(int what) {
        if (what == CONNECT_TIMEOUT) {
            log("getDeviceForMessage: returning mTargetDevice for what=" + what);
            return mCurrentDevice;
        }
        if (mCurrentDevice == null) {
            log("getDeviceForMessage: No connected device. what=" + what);
            return null;
        }
        if (getHandler().hasMessages(what, mCurrentDevice)) {
            log("getDeviceForMessage: returning " + mCurrentDevice);
            return mCurrentDevice;
        }
        log("getDeviceForMessage: No matching device for " + what + ". Returning null");
        return null;
    }

    private BluetoothDevice getMatchingDevice(BluetoothDevice device) {
        if (mCurrentDevice.equals(device)) {
            return mCurrentDevice;
        }
        return null;
    }

    /*
     * Put the AT command, company ID, arguments, and device in an Intent and broadcast it.
     */
    private void broadcastVendorSpecificEventIntent(String command, int companyId, int commandType,
            Object[] arguments, BluetoothDevice device) {
        log("broadcastVendorSpecificEventIntent(" + command + ")");
        Intent intent = new Intent(BluetoothHeadset.ACTION_VENDOR_SPECIFIC_HEADSET_EVENT);
        intent.putExtra(BluetoothHeadset.EXTRA_VENDOR_SPECIFIC_HEADSET_EVENT_CMD, command);
        intent.putExtra(BluetoothHeadset.EXTRA_VENDOR_SPECIFIC_HEADSET_EVENT_CMD_TYPE, commandType);
        // assert: all elements of args are Serializable
        intent.putExtra(BluetoothHeadset.EXTRA_VENDOR_SPECIFIC_HEADSET_EVENT_ARGS, arguments);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);

        intent.addCategory(BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_COMPANY_ID_CATEGORY + "."
                + Integer.toString(companyId));

        mService.sendBroadcastAsUser(intent, UserHandle.ALL, HeadsetService.BLUETOOTH_PERM);
    }

    private void configAudioParameters(BluetoothDevice device) {
        // Reset NREC on connect event. Headset will override later
        mAudioParams.put("NREC", 1);
        mSystemInterface.getAudioManager()
                .setParameters(
                        HEADSET_NAME + "=" + getCurrentDeviceName(device) + ";" + HEADSET_NREC
                                + "=on");
        Log.d(TAG,
                "configAudioParameters for device:" + device + " are: nrec = " + mAudioParams.get(
                        "NREC"));
    }

    private void setAudioParameters(BluetoothDevice device) {
        // 1. update nrec value
        // 2. update headset name
        int mNrec = 0;
        if (!mAudioParams.isEmpty()) {
            mNrec = mAudioParams.get("NREC");
        } else {
            Log.e(TAG, "setAudioParameters: audioParam not found");
        }

        if (mNrec == 1) {
            Log.d(TAG, "Set NREC: 1 for device:" + device);
            mSystemInterface.getAudioManager().setParameters(HEADSET_NREC + "=on");
        } else {
            Log.d(TAG, "Set NREC: 0 for device:" + device);
            mSystemInterface.getAudioManager().setParameters(HEADSET_NREC + "=off");
        }
        mSystemInterface.getAudioManager()
                .setParameters(HEADSET_NAME + "=" + getCurrentDeviceName(device));
    }

    private String parseUnknownAt(String atString) {
        StringBuilder atCommand = new StringBuilder(atString.length());
        String result = null;

        for (int i = 0; i < atString.length(); i++) {
            char c = atString.charAt(i);
            if (c == '"') {
                int j = atString.indexOf('"', i + 1); // search for closing "
                if (j == -1) { // unmatched ", insert one.
                    atCommand.append(atString.substring(i, atString.length()));
                    atCommand.append('"');
                    break;
                }
                atCommand.append(atString.substring(i, j + 1));
                i = j;
            } else if (c != ' ') {
                atCommand.append(Character.toUpperCase(c));
            }
        }
        result = atCommand.toString();
        return result;
    }

    private int getAtCommandType(String atCommand) {
        int commandType = AtPhonebook.TYPE_UNKNOWN;
        String atString = null;
        atCommand = atCommand.trim();
        if (atCommand.length() > 5) {
            atString = atCommand.substring(5);
            if (atString.startsWith("?")) { // Read
                commandType = AtPhonebook.TYPE_READ;
            } else if (atString.startsWith("=?")) { // Test
                commandType = AtPhonebook.TYPE_TEST;
            } else if (atString.startsWith("=")) { // Set
                commandType = AtPhonebook.TYPE_SET;
            } else {
                commandType = AtPhonebook.TYPE_UNKNOWN;
            }
        }
        return commandType;
    }

    /* Method to check if Virtual Call in Progress */
    private boolean isVirtualCallInProgress() {
        return mVirtualCallStarted;
    }

    private void setVirtualCallInProgress(boolean state) {
        mVirtualCallStarted = state;
    }

    /* NOTE: Currently the VirtualCall API does not support handling of
    call transfers. If it is initiated from the handsfree device,
    HeadsetStateMachine will end the virtual call by calling
    terminateScoUsingVirtualVoiceCall() in broadcastAudioState() */
    private synchronized boolean initiateScoUsingVirtualVoiceCall() {
        log("initiateScoUsingVirtualVoiceCall: Received");
        // 1. Check if the SCO state is idle
        if (isInCall() || mVoiceRecognitionStarted) {
            Log.e(TAG, "initiateScoUsingVirtualVoiceCall: Call in progress.");
            return false;
        }

        // 2. Send virtual phone state changed to initialize SCO
        processCallState(new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_DIALING, "", 0),
                true);
        processCallState(new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_ALERTING, "", 0),
                true);
        processCallState(new HeadsetCallState(1, 0, HeadsetHalConstants.CALL_STATE_IDLE, "", 0),
                true);
        setVirtualCallInProgress(true);
        // Done
        log("initiateScoUsingVirtualVoiceCall: Done");
        return true;
    }

    private synchronized boolean terminateScoUsingVirtualVoiceCall() {
        log("terminateScoUsingVirtualVoiceCall: Received");

        if (!isVirtualCallInProgress()) {
            Log.w(TAG, "terminateScoUsingVirtualVoiceCall: No present call to terminate");
            return false;
        }

        // 2. Send virtual phone state changed to close SCO
        processCallState(new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_IDLE, "", 0),
                true);
        setVirtualCallInProgress(false);
        // Done
        log("terminateScoUsingVirtualVoiceCall: Done");
        return true;
    }


    private void processDialCall(String number, BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processDialCall device is null");
            return;
        }

        String dialNumber;
        if (mDialingOut) {
            log("processDialCall, already dialling");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
            return;
        }
        if ((number == null) || (number.length() == 0)) {
            dialNumber = mPhonebook.getLastDialledNumber();
            if (dialNumber == null) {
                log("processDialCall, last dial number null");
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                return;
            }
        } else if (number.charAt(0) == '>') {
            // Yuck - memory dialling requested.
            // Just dial last number for now
            if (number.startsWith(">9999")) { // for PTS test
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                return;
            }
            log("processDialCall, memory dial do last dial for now");
            dialNumber = mPhonebook.getLastDialledNumber();
            if (dialNumber == null) {
                log("processDialCall, last dial number null");
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
                return;
            }
        } else {
            // Remove trailing ';'
            if (number.charAt(number.length() - 1) == ';') {
                number = number.substring(0, number.length() - 1);
            }

            dialNumber = PhoneNumberUtils.convertPreDial(number);
        }
        // Check for virtual call to terminate before sending Call Intent
        terminateScoUsingVirtualVoiceCall();

        Intent intent = new Intent(Intent.ACTION_CALL_PRIVILEGED,
                Uri.fromParts(SCHEME_TEL, dialNumber, null));
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        mService.startActivity(intent);
        // TODO(BT) continue send OK reults code after call starts
        //          hold wait lock, start a timer, set wait call flag
        //          Get call started indication from bluetooth phone
        mDialingOut = true;
        Message m = obtainMessage(DIALING_OUT_TIMEOUT);
        m.obj = getMatchingDevice(device);
        sendMessageDelayed(m, DIALING_OUT_TIMEOUT_VALUE);
    }

    private void processVolumeEvent(int volumeType, int volume, BluetoothDevice device) {
        if (!mCurrentDevice.equals(device)) {
            Log.w(TAG, "processVolumeEvent, ignored for unknown device " + device);
            return;
        }
        // When there is an active call, only device in audio focus can change SCO volume
        if (mSystemInterface.getHeadsetPhoneState().isInCall()
                && getAudioState() != BluetoothHeadset.STATE_AUDIO_CONNECTED) {
            Log.w(TAG, "processVolumeEvent, ignored because " + mCurrentDevice
                    + " does not have audio focus");
        }
        if (volumeType == HeadsetHalConstants.VOLUME_TYPE_SPK) {
            mSpeakerVolume = volume;
            int flag = (getCurrentState() == mAudioOn) ? AudioManager.FLAG_SHOW_UI : 0;
            mSystemInterface.getAudioManager()
                    .setStreamVolume(AudioManager.STREAM_BLUETOOTH_SCO, volume, flag);
        } else if (volumeType == HeadsetHalConstants.VOLUME_TYPE_MIC) {
            // Not used currently
            mMicVolume = volume;
        } else {
            Log.e(TAG, "Bad voluem type: " + volumeType);
        }
    }

    private void processCallState(HeadsetCallState callState, boolean isVirtualCall) {
        mSystemInterface.getHeadsetPhoneState().setNumActiveCall(callState.mNumActive);
        mSystemInterface.getHeadsetPhoneState().setNumHeldCall(callState.mNumHeld);
        mSystemInterface.getHeadsetPhoneState().setCallState(callState.mCallState);
        if (mDialingOut) {
            if (callState.mCallState == HeadsetHalConstants.CALL_STATE_DIALING) {
                BluetoothDevice device = getDeviceForMessage(DIALING_OUT_TIMEOUT);
                if (device == null) {
                    return;
                }
                mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
                removeMessages(DIALING_OUT_TIMEOUT);
            } else if (callState.mCallState == HeadsetHalConstants.CALL_STATE_ACTIVE
                    || callState.mCallState == HeadsetHalConstants.CALL_STATE_IDLE) {
                mDialingOut = false;
            }
        }

        log("mNumActive: " + callState.mNumActive + " mNumHeld: " + callState.mNumHeld
                + " mCallState: " + callState.mCallState);
        log("mNumber: " + callState.mNumber + " mType: " + callState.mType);

        if (isVirtualCall) {
            // virtual call state update
            if (getCurrentState() != mDisconnected) {
                mNativeInterface.phoneStateChange(callState);
            }
        } else {
            // circuit-switch voice call update
            // stop virtual voice call if there is a CSV call ongoing
            if (callState.mNumActive > 0 || callState.mNumHeld > 0
                    || callState.mCallState != HeadsetHalConstants.CALL_STATE_IDLE) {
                terminateScoUsingVirtualVoiceCall();
            }

            // Specific handling for case of starting MO/MT call while VOIP
            // ongoing, terminateScoUsingVirtualVoiceCall() resets callState
            // INCOMING/DIALING to IDLE. Some HS send AT+CIND? to read call
            // and get wrong value of callsetup. This case is hit only
            // SCO for VOIP call is not terminated via SDK API call.
            if (mSystemInterface.getHeadsetPhoneState().getCallState() != callState.mCallState) {
                mSystemInterface.getHeadsetPhoneState().setCallState(callState.mCallState);
            }

            // at this step: if there is virtual call ongoing, it means there is no CSV call
            // let virtual call continue and skip phone state update
            if (!isVirtualCallInProgress()) {
                if (getCurrentState() != mDisconnected) {
                    mNativeInterface.phoneStateChange(callState);
                }
            }
        }
    }

    private void processNoiseReductionEvent(boolean enable, BluetoothDevice device) {
        if (!mAudioParams.isEmpty()) {
            if (enable) {
                mAudioParams.put("NREC", 1);
            } else {
                mAudioParams.put("NREC", 0);
            }
            log("NREC value for device :" + device + " is: " + mAudioParams.get("NREC"));
        } else {
            Log.e(TAG, "processNoiseReductionEvent: audioParamNrec is null ");
        }

        if (mCurrentDevice != null && mCurrentDevice.equals(device)
                && getAudioState() == BluetoothHeadset.STATE_AUDIO_CONNECTED) {
            setAudioParameters(device);
        }
    }

    private void processWBSEvent(int wbsConfig) {
        switch (wbsConfig) {
            case HeadsetHalConstants.BTHF_WBS_YES:
                Log.d(TAG, "AudioManager.setParameters: bt_wbs=on");
                mSystemInterface.getAudioManager().setParameters(HEADSET_WBS + "=on");
                break;
            case HeadsetHalConstants.BTHF_WBS_NO:
            case HeadsetHalConstants.BTHF_WBS_NONE:
                Log.d(TAG, "AudioManager.setParameters: bt_wbs=off, wbsConfig=" + wbsConfig);
                mSystemInterface.getAudioManager().setParameters(HEADSET_WBS + "=off");
                break;
            default:
                Log.e(TAG, "processWBSEvent, unknown wbsConfig " + wbsConfig);
        }
    }

    private void processAtChld(int chld, BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processAtChld device is null");
            return;
        }
        if (mSystemInterface.processChld(chld)) {
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
        } else {
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        }
    }

    private void processSubscriberNumberRequest(BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processSubscriberNumberRequest device is null");
            return;
        }
        String number = mSystemInterface.getSubscriberNumber();
        if (number != null) {
            mNativeInterface.atResponseString(device,
                    "+CNUM: ,\"" + number + "\"," + PhoneNumberUtils.toaFromString(number) + ",,4");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
        } else {
            Log.e(TAG, "getSubscriberNumber returns null");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        }
    }

    private void processAtCind(BluetoothDevice device) {
        int call, callSetup;
        if (device == null) {
            Log.w(TAG, "processAtCind device is null");
            return;
        }
        final HeadsetPhoneState phoneState = mSystemInterface.getHeadsetPhoneState();

        /* Handsfree carkits expect that +CIND is properly responded to
         Hence we ensure that a proper response is sent
         for the virtual call too.*/
        if (isVirtualCallInProgress()) {
            call = 1;
            callSetup = 0;
        } else {
            // regular phone call
            call = phoneState.getNumActiveCall();
            callSetup = phoneState.getNumHeldCall();
        }

        mNativeInterface.cindResponse(device, phoneState.getCindService(), call, callSetup,
                phoneState.getCallState(), phoneState.getCindSignal(), phoneState.getCindRoam(),
                phoneState.getCindBatteryCharge());
    }

    private void processAtCops(BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processAtCops device is null");
            return;
        }
        String operatorName = mSystemInterface.getNetworkOperator();
        if (operatorName == null) {
            operatorName = "";
        }
        mNativeInterface.copsResponse(device, operatorName);
    }

    private void processAtClcc(BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processAtClcc device is null");
            return;
        }
        if (isVirtualCallInProgress()) {
            // In virtual call, send our phone number instead of remote phone number
            String phoneNumber = mSystemInterface.getSubscriberNumber();
            if (phoneNumber == null) {
                phoneNumber = "";
            }
            int type = PhoneNumberUtils.toaFromString(phoneNumber);
            mNativeInterface.clccResponse(device, 1, 0, 0, 0, false, phoneNumber, type);
            mNativeInterface.clccResponse(device, 0, 0, 0, 0, false, "", 0);
        } else {
            // In Telecom call, ask Telecom to send send remote phone number
            if (!mSystemInterface.listCurrentCalls()) {
                Log.e(TAG, "processAtClcc: failed to list current calls for " + device);
                mNativeInterface.clccResponse(device, 0, 0, 0, 0, false, "", 0);
            } else {
                Message m = obtainMessage(CLCC_RSP_TIMEOUT);
                m.obj = getMatchingDevice(device);
                sendMessageDelayed(m, CLCC_RSP_TIMEOUT_VALUE);
            }
        }
    }

    private void processAtCscs(String atString, int type, BluetoothDevice device) {
        log("processAtCscs - atString = " + atString);
        if (mPhonebook != null) {
            mPhonebook.handleCscsCommand(atString, type, device);
        } else {
            Log.e(TAG, "Phonebook handle null for At+CSCS");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        }
    }

    private void processAtCpbs(String atString, int type, BluetoothDevice device) {
        log("processAtCpbs - atString = " + atString);
        if (mPhonebook != null) {
            mPhonebook.handleCpbsCommand(atString, type, device);
        } else {
            Log.e(TAG, "Phonebook handle null for At+CPBS");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        }
    }

    private void processAtCpbr(String atString, int type, BluetoothDevice device) {
        log("processAtCpbr - atString = " + atString);
        if (mPhonebook != null) {
            mPhonebook.handleCpbrCommand(atString, type, device);
        } else {
            Log.e(TAG, "Phonebook handle null for At+CPBR");
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        }
    }

    /**
     * Find a character ch, ignoring quoted sections.
     * Return input.length() if not found.
     */
    private static int findChar(char ch, String input, int fromIndex) {
        for (int i = fromIndex; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '"') {
                i = input.indexOf('"', i + 1);
                if (i == -1) {
                    return input.length();
                }
            } else if (c == ch) {
                return i;
            }
        }
        return input.length();
    }

    /**
     * Break an argument string into individual arguments (comma delimited).
     * Integer arguments are turned into Integer objects. Otherwise a String
     * object is used.
     */
    private static Object[] generateArgs(String input) {
        int i = 0;
        int j;
        ArrayList<Object> out = new ArrayList<Object>();
        while (i <= input.length()) {
            j = findChar(',', input, i);

            String arg = input.substring(i, j);
            try {
                out.add(new Integer(arg));
            } catch (NumberFormatException e) {
                out.add(arg);
            }

            i = j + 1; // move past comma
        }
        return out.toArray();
    }

    /**
     * Process vendor specific AT commands
     *
     * @param atString AT command after the "AT+" prefix
     * @param device Remote device that has sent this command
     */
    private void processVendorSpecificAt(String atString, BluetoothDevice device) {
        log("processVendorSpecificAt - atString = " + atString);

        // Currently we accept only SET type commands.
        int indexOfEqual = atString.indexOf("=");
        if (indexOfEqual == -1) {
            Log.e(TAG, "processVendorSpecificAt: command type error in " + atString);
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
            return;
        }

        String command = atString.substring(0, indexOfEqual);
        Integer companyId = VENDOR_SPECIFIC_AT_COMMAND_COMPANY_ID.get(command);
        if (companyId == null) {
            Log.e(TAG, "processVendorSpecificAt: unsupported command: " + atString);
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
            return;
        }

        String arg = atString.substring(indexOfEqual + 1);
        if (arg.startsWith("?")) {
            Log.e(TAG, "processVendorSpecificAt: command type error in " + atString);
            mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
            return;
        }

        Object[] args = generateArgs(arg);
        if (command.equals(BluetoothHeadset.VENDOR_SPECIFIC_HEADSET_EVENT_XAPL)) {
            processAtXapl(args, device);
        }
        broadcastVendorSpecificEventIntent(command, companyId, BluetoothHeadset.AT_CMD_TYPE_SET,
                args, device);
        mNativeInterface.atResponseCode(device, HeadsetHalConstants.AT_RESPONSE_OK, 0);
    }

    /**
     * Process AT+XAPL AT command
     *
     * @param args command arguments after the equal sign
     * @param device Remote device that has sent this command
     */
    private void processAtXapl(Object[] args, BluetoothDevice device) {
        if (args.length != 2) {
            Log.w(TAG, "processAtXapl() args length must be 2: " + String.valueOf(args.length));
            return;
        }
        if (!(args[0] instanceof String) || !(args[1] instanceof Integer)) {
            Log.w(TAG, "processAtXapl() argument types not match");
            return;
        }
        // feature = 2 indicates that we support battery level reporting only
        mNativeInterface.atResponseString(device, "+XAPL=iPhone," + String.valueOf(2));
    }

    private void processUnknownAt(String atString, BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processUnknownAt device is null");
            return;
        }
        log("processUnknownAt - atString = " + atString);
        String atCommand = parseUnknownAt(atString);
        int commandType = getAtCommandType(atCommand);
        if (atCommand.startsWith("+CSCS")) {
            processAtCscs(atCommand.substring(5), commandType, device);
        } else if (atCommand.startsWith("+CPBS")) {
            processAtCpbs(atCommand.substring(5), commandType, device);
        } else if (atCommand.startsWith("+CPBR")) {
            processAtCpbr(atCommand.substring(5), commandType, device);
        } else {
            processVendorSpecificAt(atCommand, device);
        }
    }

    private void processKeyPressed(BluetoothDevice device) {
        if (device == null) {
            Log.w(TAG, "processKeyPressed device is null");
            return;
        }
        final HeadsetPhoneState phoneState = mSystemInterface.getHeadsetPhoneState();
        if (phoneState.getCallState() == HeadsetHalConstants.CALL_STATE_INCOMING) {
            mSystemInterface.answerCall(device);
        } else if (phoneState.getNumActiveCall() > 0) {
            if (getAudioState() != BluetoothHeadset.STATE_AUDIO_DISCONNECTED) {
                mNativeInterface.connectAudio(mCurrentDevice);
            } else {
                mSystemInterface.hangupCall(device, false);
            }
        } else {
            String dialNumber = mPhonebook.getLastDialledNumber();
            if (dialNumber == null) {
                log("processKeyPressed, last dial number null");
                return;
            }
            Intent intent = new Intent(Intent.ACTION_CALL_PRIVILEGED,
                    Uri.fromParts(SCHEME_TEL, dialNumber, null));
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            mService.startActivity(intent);
        }
    }

    /**
     * Send HF indicator value changed intent
     *
     * @param device Device whose HF indicator value has changed
     * @param indId Indicator ID [0-65535]
     * @param indValue Indicator Value [0-65535], -1 means invalid but indId is supported
     */
    private void sendIndicatorIntent(BluetoothDevice device, int indId, int indValue) {
        Intent intent = new Intent(BluetoothHeadset.ACTION_HF_INDICATORS_VALUE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothHeadset.EXTRA_HF_INDICATORS_IND_ID, indId);
        intent.putExtra(BluetoothHeadset.EXTRA_HF_INDICATORS_IND_VALUE, indValue);

        mService.sendBroadcast(intent, HeadsetService.BLUETOOTH_PERM);
    }

    private void processAtBind(String atString, BluetoothDevice device) {
        log("processAtBind: " + atString);

        // Parse the AT String to find the Indicator Ids that are supported
        int indId = 0;
        int iter = 0;
        int iter1 = 0;

        while (iter < atString.length()) {
            iter1 = findChar(',', atString, iter);
            String id = atString.substring(iter, iter1);

            try {
                indId = Integer.valueOf(id);
            } catch (NumberFormatException e) {
                Log.e(TAG, Log.getStackTraceString(new Throwable()));
            }

            switch (indId) {
                case HeadsetHalConstants.HF_INDICATOR_ENHANCED_DRIVER_SAFETY:
                    log("Send Broadcast intent for the Enhanced Driver Safety indicator.");
                    sendIndicatorIntent(device, indId, -1);
                    break;
                case HeadsetHalConstants.HF_INDICATOR_BATTERY_LEVEL_STATUS:
                    log("Send Broadcast intent for the Battery Level indicator.");
                    sendIndicatorIntent(device, indId, -1);
                    break;
                default:
                    log("Invalid HF Indicator Received");
                    break;
            }

            iter = iter1 + 1; // move past comma
        }
    }

    private void processAtBiev(int indId, int indValue, BluetoothDevice device) {
        log("processAtBiev: ind_id=" + indId + ", ind_value=" + indValue);
        sendIndicatorIntent(device, indId, indValue);
    }

    private void processDeviceStateChanged(HeadsetDeviceState deviceState) {
        mNativeInterface.notifyDeviceStatus(deviceState);
    }

    private void processSendClccResponse(HeadsetClccResponse clcc) {
        BluetoothDevice device = getDeviceForMessage(CLCC_RSP_TIMEOUT);
        if (device == null) {
            return;
        }
        if (clcc.mIndex == 0) {
            removeMessages(CLCC_RSP_TIMEOUT);
        }
        mNativeInterface.clccResponse(device, clcc.mIndex, clcc.mDirection, clcc.mStatus,
                clcc.mMode, clcc.mMpty, clcc.mNumber, clcc.mType);
    }

    private void processSendVendorSpecificResultCode(HeadsetVendorSpecificResultCode resultCode) {
        String stringToSend = resultCode.mCommand + ": ";
        if (resultCode.mArg != null) {
            stringToSend += resultCode.mArg;
        }
        mNativeInterface.atResponseString(resultCode.mDevice, stringToSend);
    }

    private String getCurrentDeviceName(BluetoothDevice device) {
        String defaultName = "<unknown>";

        if (device == null) {
            return defaultName;
        }

        String deviceName = device.getName();
        if (deviceName == null) {
            return defaultName;
        }
        return deviceName;
    }

    private boolean isInCall() {
        final HeadsetPhoneState phoneState = mSystemInterface.getHeadsetPhoneState();
        return ((phoneState.getNumActiveCall() > 0) || (phoneState.getNumHeldCall() > 0) || (
                (phoneState.getCallState() != HeadsetHalConstants.CALL_STATE_IDLE) && (
                        phoneState.getCallState() != HeadsetHalConstants.CALL_STATE_INCOMING)));
    }

    private boolean isRinging() {
        return mSystemInterface.getHeadsetPhoneState().getCallState()
                == HeadsetHalConstants.CALL_STATE_INCOMING;
    }

    // Accept incoming SCO only when there is in-band ringing, incoming call,
    // active call, VR activated, active VOIP call
    private boolean isScoAcceptable() {
        if (mForceScoAudio) {
            return true;
        }
        if (!mService.getAudioRouteAllowed()) {
            return false;
        }
        if (isInCall() || mVoiceRecognitionStarted) {
            return true;
        }
        if (isRinging() && BluetoothHeadset.isInbandRingingSupported(mService)) {
            return true;
        }
        return false;
    }

    private boolean okToAcceptConnection(BluetoothDevice device) {
        AdapterService adapterService = AdapterService.getAdapterService();
        // check if this is an incoming connection in Quiet mode.
        if (adapterService == null) {
            Log.e(TAG, "okToAcceptConnection, cannot get adapterService");
            return false;
        }
        if (adapterService.isQuietModeEnabled() && mCurrentDevice == null) {
            Log.i(TAG, "okToAcceptConnection, quiet mode enabled and current device is null");
            return false;
        }
        // check priority and accept or reject the connection. if priority is undefined
        // it is likely that our SDP has not completed and peer is initiating the
        // connection. Allow this connection, provided the device is bonded
        int priority = mService.getPriority(device);
        int bondState = device.getBondState();
        if ((priority > BluetoothProfile.PRIORITY_OFF) || (
                (priority == BluetoothProfile.PRIORITY_UNDEFINED)
                        && bondState != BluetoothDevice.BOND_NONE)) {
            return true;
        }
        Log.i(TAG, "okToAcceptConnection, rejected, priority=" + priority + ", bondState="
                + bondState);
        return false;
    }

    @Override
    protected void log(String msg) {
        if (DBG) {
            super.log(msg);
        }
    }

    private void handleAccessPermissionResult(Intent intent) {
        log("handleAccessPermissionResult");
        BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
        if (!mPhonebook.getCheckingAccessPermission()) {
            return;
        }
        int atCommandResult = 0;
        int atCommandErrorCode = 0;
        // HeadsetBase headset = mHandsfree.getHeadset();
        // ASSERT: (headset != null) && headSet.isConnected()
        // REASON: mCheckingAccessPermission is true, otherwise resetAtState
        // has set mCheckingAccessPermission to false
        if (intent.getAction().equals(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY)) {
            if (intent.getIntExtra(BluetoothDevice.EXTRA_CONNECTION_ACCESS_RESULT,
                    BluetoothDevice.CONNECTION_ACCESS_NO)
                    == BluetoothDevice.CONNECTION_ACCESS_YES) {
                if (intent.getBooleanExtra(BluetoothDevice.EXTRA_ALWAYS_ALLOWED, false)) {
                    mCurrentDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_ALLOWED);
                }
                atCommandResult = mPhonebook.processCpbrCommand(device);
            } else {
                if (intent.getBooleanExtra(BluetoothDevice.EXTRA_ALWAYS_ALLOWED, false)) {
                    mCurrentDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_REJECTED);
                }
            }
        }
        mPhonebook.setCpbrIndex(-1);
        mPhonebook.setCheckingAccessPermission(false);
        if (atCommandResult >= 0) {
            mNativeInterface.atResponseCode(device, atCommandResult, atCommandErrorCode);
        } else {
            log("handleAccessPermissionResult - RESULT_NONE");
        }
    }

    static String getMessageName(int what) {
        switch (what) {
            case CONNECT:
                return "CONNECT";
            case DISCONNECT:
                return "DISCONNECT";
            case CONNECT_AUDIO:
                return "CONNECT_AUDIO";
            case DISCONNECT_AUDIO:
                return "DISCONNECT_AUDIO";
            case VOICE_RECOGNITION_START:
                return "VOICE_RECOGNITION_START";
            case VOICE_RECOGNITION_STOP:
                return "VOICE_RECOGNITION_STOP";
            case INTENT_SCO_VOLUME_CHANGED:
                return "INTENT_SCO_VOLUME_CHANGED";
            case INTENT_CONNECTION_ACCESS_REPLY:
                return "INTENT_CONNECTION_ACCESS_REPLY";
            case CALL_STATE_CHANGED:
                return "CALL_STATE_CHANGED";
            case DEVICE_STATE_CHANGED:
                return "DEVICE_STATE_CHANGED";
            case SEND_CCLC_RESPONSE:
                return "SEND_CCLC_RESPONSE";
            case SEND_VENDOR_SPECIFIC_RESULT_CODE:
                return "SEND_VENDOR_SPECIFIC_RESULT_CODE";
            case VIRTUAL_CALL_START:
                return "VIRTUAL_CALL_START";
            case VIRTUAL_CALL_STOP:
                return "VIRTUAL_CALL_STOP";
            case STACK_EVENT:
                return "STACK_EVENT";
            case DIALING_OUT_TIMEOUT:
                return "DIALING_OUT_TIMEOUT";
            case START_VR_TIMEOUT:
                return "START_VR_TIMEOUT";
            case CLCC_RSP_TIMEOUT:
                return "CLCC_RSP_TIMEOUT";
            case CONNECT_TIMEOUT:
                return "CONNECT_TIMEOUT";
            default:
                return "UNKNOWN";
        }
    }
}
