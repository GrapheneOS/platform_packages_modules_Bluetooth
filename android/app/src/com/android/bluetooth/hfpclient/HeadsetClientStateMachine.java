/*
 * Copyright (c) 2014 The Android Open Source Project
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
 * Bluetooth Headset Client StateMachine
 *                      (Disconnected)
 *                           | ^  ^
 *                   CONNECT | |  | DISCONNECTED
 *                           V |  |
 *                   (Connecting) |
 *                           |    |
 *                 CONNECTED |    | DISCONNECT
 *                           V    |
 *                        (Connected)
 *                           |    ^
 *             CONNECT_AUDIO |    | DISCONNECT_AUDIO
 *                           V    |
 *                         (AudioOn)
 */

package com.android.bluetooth.hfpclient;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothHeadsetClientCall;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.os.Bundle;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.util.Log;
import android.util.Pair;
import android.telecom.TelecomManager;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.hfpclient.connserv.HfpClientConnectionService;
import com.android.internal.util.IState;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import com.android.bluetooth.R;

final class HeadsetClientStateMachine extends StateMachine {
    private static final String TAG = "HeadsetClientStateMachine";
    private static final boolean DBG = false;

    static final int NO_ACTION = 0;

    // external actions
    public static final int CONNECT = 1;
    public static final int DISCONNECT = 2;
    public static final int CONNECT_AUDIO = 3;
    public static final int DISCONNECT_AUDIO = 4;
    public static final int VOICE_RECOGNITION_START = 5;
    public static final int VOICE_RECOGNITION_STOP = 6;
    public static final int SET_MIC_VOLUME = 7;
    public static final int SET_SPEAKER_VOLUME = 8;
    public static final int DIAL_NUMBER = 10;
    public static final int ACCEPT_CALL = 12;
    public static final int REJECT_CALL = 13;
    public static final int HOLD_CALL = 14;
    public static final int TERMINATE_CALL = 15;
    public static final int ENTER_PRIVATE_MODE = 16;
    public static final int SEND_DTMF = 17;
    public static final int EXPLICIT_CALL_TRANSFER = 18;
    public static final int LAST_VTAG_NUMBER = 19;
    public static final int DISABLE_NREC = 20;

    // internal actions
    private static final int QUERY_CURRENT_CALLS = 50;
    private static final int QUERY_OPERATOR_NAME = 51;
    private static final int SUBSCRIBER_INFO = 52;
    private static final int CONNECTING_TIMEOUT = 53;

    // special action to handle terminating specific call from multiparty call
    static final int TERMINATE_SPECIFIC_CALL = 53;

    // Timeouts.
    static final int CONNECTING_TIMEOUT_MS = 10000;  // 10s

    static final int MAX_HFP_SCO_VOICE_CALL_VOLUME = 15; // HFP 1.5 spec.
    static final int MIN_HFP_SCO_VOICE_CALL_VOLUME = 1; // HFP 1.5 spec.

    private static final int STACK_EVENT = 100;

    public static final Integer HF_ORIGINATED_CALL_ID = new Integer(-1);
    private long OUTGOING_TIMEOUT_MILLI = 10 * 1000; // 10 seconds
    private long QUERY_CURRENT_CALLS_WAIT_MILLIS = 2 * 1000; // 2 seconds

    private final Disconnected mDisconnected;
    private final Connecting mConnecting;
    private final Connected mConnected;
    private final AudioOn mAudioOn;
    private long mClccTimer = 0;

    private final HeadsetClientService mService;

    // Set of calls that represent the accurate state of calls that exists on AG and the calls that
    // are currently in process of being notified to the AG from HF.
    private final Hashtable<Integer, BluetoothHeadsetClientCall> mCalls = new Hashtable<>();
    // Set of calls received from AG via the AT+CLCC command. We use this map to update the mCalls
    // which is eventually used to inform the telephony stack of any changes to call on HF.
    private final Hashtable<Integer, BluetoothHeadsetClientCall> mCallsUpdate = new Hashtable<>();

    private int mIndicatorNetworkState;
    private int mIndicatorNetworkType;
    private int mIndicatorNetworkSignal;
    private int mIndicatorBatteryLevel;

    private int mIndicatorCall;
    private int mIndicatorCallSetup;
    private int mIndicatorCallHeld;
    private boolean mVgsFromStack = false;
    private boolean mVgmFromStack = false;

    private String mOperatorName;
    private String mSubscriberInfo;

    private int mVoiceRecognitionActive;
    private int mInBandRingtone;

    private int mMaxAmVcVol;
    private int mMinAmVcVol;

    // queue of send actions (pair action, action_data)
    private Queue<Pair<Integer, Object>> mQueuedActions;

    // last executed command, before action is complete e.g. waiting for some
    // indicator
    private Pair<Integer, Object> mPendingAction;

    private final AudioManager mAudioManager;
    private int mAudioState;
    // Indicates whether audio can be routed to the device.
    private boolean mAudioRouteAllowed;
    private boolean mAudioWbs;
    private final BluetoothAdapter mAdapter;
    private boolean mNativeAvailable;
    private TelecomManager mTelecomManager;

    // currently connected device
    private BluetoothDevice mCurrentDevice = null;

    // general peer features and call handling features
    private int mPeerFeatures;
    private int mChldFeatures;

    static {
        classInitNative();
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mCurrentDevice: " + mCurrentDevice);
        ProfileService.println(sb, "mAudioOn: " + mAudioOn);
        ProfileService.println(sb, "mAudioState: " + mAudioState);
        ProfileService.println(sb, "mAudioWbs: " + mAudioWbs);
        ProfileService.println(sb, "mIndicatorNetworkState: " + mIndicatorNetworkState);
        ProfileService.println(sb, "mIndicatorNetworkType: " + mIndicatorNetworkType);
        ProfileService.println(sb, "mIndicatorNetworkSignal: " + mIndicatorNetworkSignal);
        ProfileService.println(sb, "mIndicatorBatteryLevel: " + mIndicatorBatteryLevel);
        ProfileService.println(sb, "mIndicatorCall: " + mIndicatorCall);
        ProfileService.println(sb, "mIndicatorCallSetup: " + mIndicatorCallSetup);
        ProfileService.println(sb, "mIndicatorCallHeld: " + mIndicatorCallHeld);
        ProfileService.println(sb, "mVgsFromStack: " + mVgsFromStack);
        ProfileService.println(sb, "mVgmFromStack: " + mVgmFromStack);
        ProfileService.println(sb, "mOperatorName: " + mOperatorName);
        ProfileService.println(sb, "mSubscriberInfo: " + mSubscriberInfo);
        ProfileService.println(sb, "mVoiceRecognitionActive: " + mVoiceRecognitionActive);
        ProfileService.println(sb, "mInBandRingtone: " + mInBandRingtone);

        ProfileService.println(sb, "mCalls:");
        if (mCalls != null) {
            for (BluetoothHeadsetClientCall call : mCalls.values()) {
                ProfileService.println(sb, "  " + call);
            }
        }

        ProfileService.println(sb, "mCallsUpdate:");
        if (mCallsUpdate != null) {
            for (BluetoothHeadsetClientCall call : mCallsUpdate.values()) {
                ProfileService.println(sb, "  " + call);
            }
        }
    }

    private void clearPendingAction() {
        mPendingAction = new Pair<Integer, Object>(NO_ACTION, 0);
    }

    private void addQueuedAction(int action) {
        addQueuedAction(action, 0);
    }

    private void addQueuedAction(int action, Object data) {
        mQueuedActions.add(new Pair<Integer, Object>(action, data));
    }

    private void addQueuedAction(int action, int data) {
        mQueuedActions.add(new Pair<Integer, Object>(action, data));
    }

    private BluetoothHeadsetClientCall getCall(int... states) {
        if (DBG) {
            Log.d(TAG, "getFromCallsWithStates states:" + Arrays.toString(states));
        }
        for (BluetoothHeadsetClientCall c : mCalls.values()) {
            for (int s : states) {
                if (c.getState() == s) {
                    return c;
                }
            }
        }
        return null;
    }

    private int callsInState(int state) {
        int i = 0;
        for (BluetoothHeadsetClientCall c : mCalls.values()) {
            if (c.getState() == state) {
                i++;
            }
        }

        return i;
    }

    private void updateCallsMultiParty() {
        boolean multi = callsInState(BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) > 1;

        for (BluetoothHeadsetClientCall c : mCalls.values()) {
            if (c.getState() == BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) {
                if (c.isMultiParty() == multi) {
                    continue;
                }

                c.setMultiParty(multi);
                sendCallChangedIntent(c);
            } else {
                if (c.isMultiParty()) {
                    c.setMultiParty(false);
                    sendCallChangedIntent(c);
                }
            }
        }
    }

    private void setCallState(BluetoothHeadsetClientCall c, int state) {
        if (state == c.getState()) {
            return;
        }
        c.setState(state);
        sendCallChangedIntent(c);
    }

    private void sendCallChangedIntent(BluetoothHeadsetClientCall c) {
        if (DBG) {
            Log.d(TAG, "sendCallChangedIntent " + c);
        }
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_CALL_CHANGED);
        intent.addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
        intent.putExtra(BluetoothHeadsetClient.EXTRA_CALL, c);
        mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void updateCallIndicator(int call) {
        if (DBG) {
            Log.d(TAG, "updateCallIndicator " + call);
        }
        mIndicatorCall = call;
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private void updateCallSetupIndicator(int callSetup) {
        if (DBG) {
            Log.d(TAG, "updateCallSetupIndicator " + callSetup + " " + mPendingAction.first);
        }
        mIndicatorCallSetup = callSetup;
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private void updateCallHeldIndicator(int callHeld) {
        if (DBG) {
            Log.d(TAG, "updateCallHeld " + callHeld);
        }
        mIndicatorCallHeld = callHeld;
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private void updateRespAndHold(int resp_and_hold) {
        if (DBG) {
            Log.d(TAG, "updatRespAndHold " + resp_and_hold);
        }
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private void updateClip(String number) {
        if (DBG) {
            Log.d(TAG, "updateClip " + number);
        }
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private void updateCCWA(String number) {
        if (DBG) {
            Log.d(TAG, "updateCCWA " + number);
        }
        sendMessage(QUERY_CURRENT_CALLS);
    }

    private boolean queryCallsStart() {
        if (DBG) {
            Log.d(TAG, "queryCallsStart");
        }
        clearPendingAction();
        queryCurrentCallsNative(getByteAddress(mCurrentDevice));
        addQueuedAction(QUERY_CURRENT_CALLS, 0);
        return true;
    }

    private void queryCallsDone() {
        if (DBG) {
            Log.d(TAG, "queryCallsDone");
        }
        Iterator<Hashtable.Entry<Integer, BluetoothHeadsetClientCall>> it;

        // mCalls has two types of calls:
        // (a) Calls that are received from AG of a previous iteration of queryCallsStart()
        // (b) Calls that are outgoing initiated from HF
        // mCallsUpdate has all calls received from queryCallsUpdate() in current iteration of
        // queryCallsStart().
        //
        // We use the following steps to make sure that calls are update correctly.
        //
        // If there are no calls initiated from HF (i.e. ID = -1) then:
        // 1. All IDs which are common in mCalls & mCallsUpdate are updated and the upper layers are
        // informed of the change calls (if any changes).
        // 2. All IDs that are in mCalls but *not* in mCallsUpdate will be removed from mCalls and
        // the calls should be terminated
        // 3. All IDs that are new in mCallsUpdated should be added as new calls to mCalls.
        //
        // If there is an outgoing HF call, it is important to associate that call with one of the
        // mCallsUpdated calls hence,
        // 1. If from the above procedure we get N extra calls (i.e. {3}):
        // choose the first call as the one to associate with the HF call.

        // Create set of IDs for added calls, removed calls and consitent calls.
        // WARN!!! Java Map -> Set has association hence changes to Set are reflected in the Map
        // itself (i.e. removing an element from Set removes it from the Map hence use copy).
        Set<Integer> currCallIdSet = new HashSet<Integer>();
        currCallIdSet.addAll(mCalls.keySet());
        // Remove the entry for unassigned call.
        currCallIdSet.remove(HF_ORIGINATED_CALL_ID);

        Set<Integer> newCallIdSet = new HashSet<Integer>();
        newCallIdSet.addAll(mCallsUpdate.keySet());

        // Added.
        Set<Integer> callAddedIds = new HashSet<Integer>();
        callAddedIds.addAll(newCallIdSet);
        callAddedIds.removeAll(currCallIdSet);

        // Removed.
        Set<Integer> callRemovedIds = new HashSet<Integer>();
        callRemovedIds.addAll(currCallIdSet);
        callRemovedIds.removeAll(newCallIdSet);

        // Retained.
        Set<Integer> callRetainedIds = new HashSet<Integer>();
        callRetainedIds.addAll(currCallIdSet);
        callRetainedIds.retainAll(newCallIdSet);

        if (DBG) {
            Log.d(TAG, "currCallIdSet " + mCalls.keySet() + " newCallIdSet " + newCallIdSet +
                " callAddedIds " + callAddedIds + " callRemovedIds " + callRemovedIds +
                " callRetainedIds " + callRetainedIds);
        }

        // First thing is to try to associate the outgoing HF with a valid call.
        Integer hfOriginatedAssoc = -1;
        if (mCalls.containsKey(HF_ORIGINATED_CALL_ID)) {
            BluetoothHeadsetClientCall c = mCalls.get(HF_ORIGINATED_CALL_ID);
            long cCreationElapsed = c.getCreationElapsedMilli();
            if (callAddedIds.size() > 0) {
                if (DBG) {
                    Log.d(TAG, "Associating the first call with HF originated call");
                }
                hfOriginatedAssoc = (Integer) callAddedIds.toArray()[0];
                mCalls.put(hfOriginatedAssoc, mCalls.get(HF_ORIGINATED_CALL_ID));
                mCalls.remove(HF_ORIGINATED_CALL_ID);

                // Adjust this call in above sets.
                callAddedIds.remove(hfOriginatedAssoc);
                callRetainedIds.add(hfOriginatedAssoc);
            } else if (SystemClock.elapsedRealtime() - cCreationElapsed > OUTGOING_TIMEOUT_MILLI) {
                Log.w(TAG, "Outgoing call did not see a response, clear the calls and send CHUP");
                // We send a terminate because we are in a bad state and trying to
                // recover.
                terminateCall();

                // Clean out the state for outgoing call.
                for (Integer idx : mCalls.keySet()) {
                    BluetoothHeadsetClientCall c1 = mCalls.get(idx);
                    c1.setState(BluetoothHeadsetClientCall.CALL_STATE_TERMINATED);
                    sendCallChangedIntent(c1);
                }
                mCalls.clear();

                // We return here, if there's any update to the phone we should get a
                // follow up by getting some call indicators and hence update the calls.
                return;
            }
        }

        if (DBG) {
            Log.d(TAG, "ADJUST: currCallIdSet " + mCalls.keySet() + " newCallIdSet " +
                newCallIdSet + " callAddedIds " + callAddedIds + " callRemovedIds " +
                callRemovedIds + " callRetainedIds " + callRetainedIds);
        }

        // Terminate & remove the calls that are done.
        for (Integer idx : callRemovedIds) {
            BluetoothHeadsetClientCall c = mCalls.remove(idx);
            c.setState(BluetoothHeadsetClientCall.CALL_STATE_TERMINATED);
            sendCallChangedIntent(c);
        }

        // Add the new calls.
        for (Integer idx : callAddedIds) {
            BluetoothHeadsetClientCall c = mCallsUpdate.get(idx);
            mCalls.put(idx, c);
            sendCallChangedIntent(c);
        }

        // Update the existing calls.
        for (Integer idx : callRetainedIds) {
            BluetoothHeadsetClientCall cOrig = mCalls.get(idx);
            BluetoothHeadsetClientCall cUpdate = mCallsUpdate.get(idx);

            // Update the necessary fields.
            cOrig.setNumber(cUpdate.getNumber());
            cOrig.setState(cUpdate.getState());
            cOrig.setMultiParty(cUpdate.isMultiParty());

            // Send update with original object (UUID, idx).
            sendCallChangedIntent(cOrig);
        }

        if (loopQueryCalls()) {
            sendMessageDelayed(QUERY_CURRENT_CALLS, QUERY_CURRENT_CALLS_WAIT_MILLIS);
        }

        mCallsUpdate.clear();
    }

    private void queryCallsUpdate(int id, int state, String number, boolean multiParty,
            boolean outgoing) {
        if (DBG) {
            Log.d(TAG, "queryCallsUpdate: " + id);
        }
        mCallsUpdate.put(id, new BluetoothHeadsetClientCall(mCurrentDevice, id, state, number,
                multiParty, outgoing));
    }

    // helper function for determining if query calls should be looped
    private boolean loopQueryCalls() {
        if (DBG) {
            Log.d(TAG, "loopQueryCalls, starting call query loop");
        }
        return (mCalls.size() > 0);
    }

    private void acceptCall(int flag, boolean retry) {
        int action = -1;

        if (DBG) {
            Log.d(TAG, "acceptCall: (" + flag + ")");
        }

        BluetoothHeadsetClientCall c = getCall(BluetoothHeadsetClientCall.CALL_STATE_INCOMING,
                BluetoothHeadsetClientCall.CALL_STATE_WAITING);
        if (c == null) {
            c = getCall(BluetoothHeadsetClientCall.CALL_STATE_HELD_BY_RESPONSE_AND_HOLD,
                    BluetoothHeadsetClientCall.CALL_STATE_HELD);

            if (c == null) {
                return;
            }
        }

        if (DBG) {
            Log.d(TAG, "Call to accept: " + c);
        }
        switch (c.getState()) {
            case BluetoothHeadsetClientCall.CALL_STATE_INCOMING:
                if (flag != BluetoothHeadsetClient.CALL_ACCEPT_NONE) {
                    return;
                }

                // Some NOKIA phones with Windows Phone 7.8 and MeeGo requires CHLD=1
                // for accepting incoming call if it is the only call present after
                // second active remote has disconnected (3WC scenario - call state
                // changes from waiting to incoming). On the other hand some Android
                // phones and iPhone requires ATA. Try to handle those gently by
                // first issuing ATA. Failing means that AG is probably one of those
                // phones that requires CHLD=1. Handle this case when we are retrying.
                // Accepting incoming calls when there is held one and
                // no active should also be handled by ATA.
                action = HeadsetClientHalConstants.CALL_ACTION_ATA;

                if (mCalls.size() == 1 && retry) {
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_1;
                }
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_WAITING:
                if (callsInState(BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) == 0) {
                    // if no active calls present only plain accept is allowed
                    if (flag != BluetoothHeadsetClient.CALL_ACCEPT_NONE) {
                        return;
                    }

                    // Some phones (WP7) require ATA instead of CHLD=2
                    // to accept waiting call if no active calls are present.
                    if (retry) {
                        action = HeadsetClientHalConstants.CALL_ACTION_ATA;
                    } else {
                        action = HeadsetClientHalConstants.CALL_ACTION_CHLD_2;
                    }
                    break;
                }

                // if active calls are present then we have the option to either terminate the
                // existing call or hold the existing call. We hold the other call by default.
                if (flag == BluetoothHeadsetClient.CALL_ACCEPT_HOLD ||
                    flag == BluetoothHeadsetClient.CALL_ACCEPT_NONE) {
                    if (DBG) {
                        Log.d(TAG, "Accepting call with accept and hold");
                    }
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_2;
                } else if (flag == BluetoothHeadsetClient.CALL_ACCEPT_TERMINATE) {
                    if (DBG) {
                        Log.d(TAG, "Accepting call with accept and reject");
                    }
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_1;
                } else {
                    Log.e(TAG, "Aceept call with invalid flag: " + flag);
                    return;
                }
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_HELD:
                if (flag == BluetoothHeadsetClient.CALL_ACCEPT_HOLD) {
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_2;
                } else if (flag == BluetoothHeadsetClient.CALL_ACCEPT_TERMINATE) {
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_1;
                } else if (getCall(BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) != null) {
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_3;
                } else {
                    action = HeadsetClientHalConstants.CALL_ACTION_CHLD_2;
                }
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_HELD_BY_RESPONSE_AND_HOLD:
                action = HeadsetClientHalConstants.CALL_ACTION_BTRH_1;
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_ALERTING:
            case BluetoothHeadsetClientCall.CALL_STATE_ACTIVE:
            case BluetoothHeadsetClientCall.CALL_STATE_DIALING:
            default:
                return;
        }

        if (flag == BluetoothHeadsetClient.CALL_ACCEPT_HOLD) {
            // HFP is disabled when a call is put on hold to ensure correct audio routing for
            // cellular calls accepted while an HFP call is in progress. Reenable HFP when the HFP
            // call is put off hold.
            Log.d(TAG,"hfp_enable=true");
            mAudioManager.setParameters("hfp_enable=true");
        }

        if (handleCallActionNative(getByteAddress(mCurrentDevice), action, 0)) {
            addQueuedAction(ACCEPT_CALL, action);
        } else {
            Log.e(TAG, "ERROR: Couldn't accept a call, action:" + action);
        }
    }

    private void rejectCall() {
        int action;

        if (DBG) {
            Log.d(TAG, "rejectCall");
        }

        BluetoothHeadsetClientCall c =
                getCall(BluetoothHeadsetClientCall.CALL_STATE_INCOMING,
                BluetoothHeadsetClientCall.CALL_STATE_WAITING,
                BluetoothHeadsetClientCall.CALL_STATE_HELD_BY_RESPONSE_AND_HOLD,
                BluetoothHeadsetClientCall.CALL_STATE_HELD);
        if (c == null) {
            if (DBG) {
                Log.d(TAG, "No call to reject, returning.");
            }
            return;
        }

        switch (c.getState()) {
            case BluetoothHeadsetClientCall.CALL_STATE_INCOMING:
                action = HeadsetClientHalConstants.CALL_ACTION_CHUP;
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_WAITING:
            case BluetoothHeadsetClientCall.CALL_STATE_HELD:
                action = HeadsetClientHalConstants.CALL_ACTION_CHLD_0;
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_HELD_BY_RESPONSE_AND_HOLD:
                action = HeadsetClientHalConstants.CALL_ACTION_BTRH_2;
                break;
            case BluetoothHeadsetClientCall.CALL_STATE_ACTIVE:
            case BluetoothHeadsetClientCall.CALL_STATE_DIALING:
            case BluetoothHeadsetClientCall.CALL_STATE_ALERTING:
            default:
                return;
        }

        if (DBG) {
            Log.d(TAG, "Reject call action " + action);
        }
        if (handleCallActionNative(getByteAddress(mCurrentDevice), action, 0)) {
            addQueuedAction(REJECT_CALL, action);
        } else {
            Log.e(TAG, "ERROR: Couldn't reject a call, action:" + action);
        }
    }

    private void holdCall() {
        int action;

        if (DBG) {
            Log.d(TAG, "holdCall");
        }

        BluetoothHeadsetClientCall c = getCall(BluetoothHeadsetClientCall.CALL_STATE_INCOMING);
        if (c != null) {
            action = HeadsetClientHalConstants.CALL_ACTION_BTRH_0;
        } else {
            c = getCall(BluetoothHeadsetClientCall.CALL_STATE_ACTIVE);
            if (c == null) {
                return;
            }

            action = HeadsetClientHalConstants.CALL_ACTION_CHLD_2;
        }

        // Set HFP enable to false in case the call is being held to accept a cellular call. This
        // allows the cellular call's audio to be correctly routed.
        Log.d(TAG,"hfp_enable=false");
        mAudioManager.setParameters("hfp_enable=false");

        if (handleCallActionNative(getByteAddress(mCurrentDevice), action, 0)) {
            addQueuedAction(HOLD_CALL, action);
        } else {
            Log.e(TAG, "ERROR: Couldn't hold a call, action:" + action);
        }
    }

    private void terminateCall() {
        if (DBG) {
            Log.d(TAG, "terminateCall");
        }

        int action = HeadsetClientHalConstants.CALL_ACTION_CHUP;

        BluetoothHeadsetClientCall c = getCall(
                BluetoothHeadsetClientCall.CALL_STATE_DIALING,
                BluetoothHeadsetClientCall.CALL_STATE_ALERTING,
                BluetoothHeadsetClientCall.CALL_STATE_ACTIVE);
        if (c != null) {
            if (handleCallActionNative(getByteAddress(mCurrentDevice), action, 0)) {
                addQueuedAction(TERMINATE_CALL, action);
            } else {
                Log.e(TAG, "ERROR: Couldn't terminate outgoing call");
            }
        }
    }

    private void enterPrivateMode(int idx) {
        if (DBG) {
            Log.d(TAG, "enterPrivateMode: " + idx);
        }

        BluetoothHeadsetClientCall c = mCalls.get(idx);

        if (c == null) {
            return;
        }

        if (c.getState() != BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) {
            return;
        }

        if (!c.isMultiParty()) {
            return;
        }

        if (handleCallActionNative(getByteAddress(mCurrentDevice),
                HeadsetClientHalConstants.CALL_ACTION_CHLD_2x, idx)) {
            addQueuedAction(ENTER_PRIVATE_MODE, c);
        } else {
            Log.e(TAG, "ERROR: Couldn't enter private " + " id:" + idx);
        }
    }

    private void explicitCallTransfer() {
        if (DBG) {
            Log.d(TAG, "explicitCallTransfer");
        }

        // can't transfer call if there is not enough call parties
        if (mCalls.size() < 2) {
            return;
        }

        if (handleCallActionNative(getByteAddress(mCurrentDevice),
              HeadsetClientHalConstants.CALL_ACTION_CHLD_4, -1)) {
            addQueuedAction(EXPLICIT_CALL_TRANSFER);
        } else {
            Log.e(TAG, "ERROR: Couldn't transfer call");
        }
    }

    public Bundle getCurrentAgFeatures()
    {
        Bundle b = new Bundle();
        if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_3WAY) ==
                HeadsetClientHalConstants.PEER_FEAT_3WAY) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_3WAY_CALLING, true);
        }
        if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_VREC) ==
                HeadsetClientHalConstants.PEER_FEAT_VREC) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_VOICE_RECOGNITION, true);
        }
        if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_VTAG) ==
                HeadsetClientHalConstants.PEER_FEAT_VTAG) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ATTACH_NUMBER_TO_VT, true);
        }
        if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_REJECT) ==
                HeadsetClientHalConstants.PEER_FEAT_REJECT) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_REJECT_CALL, true);
        }
        if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_ECC) ==
                HeadsetClientHalConstants.PEER_FEAT_ECC) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ECC, true);
        }

        // add individual CHLD support extras
        if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC) ==
                HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ACCEPT_HELD_OR_WAITING_CALL, true);
        }
        if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_REL) ==
                HeadsetClientHalConstants.CHLD_FEAT_REL) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_HELD_OR_WAITING_CALL, true);
        }
        if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_REL_ACC) ==
                HeadsetClientHalConstants.CHLD_FEAT_REL_ACC) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_AND_ACCEPT, true);
        }
        if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_MERGE) ==
                HeadsetClientHalConstants.CHLD_FEAT_MERGE) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE, true);
        }
        if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH) ==
                HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH) {
            b.putBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE_AND_DETACH, true);
        }

        return b;
    }

    private HeadsetClientStateMachine(HeadsetClientService context) {
        super(TAG);
        mService = context;

        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mAudioManager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
        mAudioState = BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED;
        mAudioWbs = false;

        mAudioRouteAllowed = context.getResources().getBoolean(
                R.bool.headset_client_initial_audio_route_allowed);

        mTelecomManager = (TelecomManager) context.getSystemService(context.TELECOM_SERVICE);

        mIndicatorNetworkState = HeadsetClientHalConstants.NETWORK_STATE_NOT_AVAILABLE;
        mIndicatorNetworkType = HeadsetClientHalConstants.SERVICE_TYPE_HOME;
        mIndicatorNetworkSignal = 0;
        mIndicatorBatteryLevel = 0;

        // all will be set on connected
        mIndicatorCall = -1;
        mIndicatorCallSetup = -1;
        mIndicatorCallHeld = -1;

        mMaxAmVcVol = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_VOICE_CALL);
        mMinAmVcVol = mAudioManager.getStreamMinVolume(AudioManager.STREAM_VOICE_CALL);

        mOperatorName = null;
        mSubscriberInfo = null;

        mVoiceRecognitionActive = HeadsetClientHalConstants.VR_STATE_STOPPED;
        mInBandRingtone = HeadsetClientHalConstants.IN_BAND_RING_NOT_PROVIDED;

        mQueuedActions = new LinkedList<Pair<Integer, Object>>();
        clearPendingAction();

        mCalls.clear();
        mCallsUpdate.clear();

        initializeNative();
        mNativeAvailable = true;

        mDisconnected = new Disconnected();
        mConnecting = new Connecting();
        mConnected = new Connected();
        mAudioOn = new AudioOn();

        addState(mDisconnected);
        addState(mConnecting);
        addState(mConnected);
        addState(mAudioOn, mConnected);

        setInitialState(mDisconnected);
    }

    static HeadsetClientStateMachine make(HeadsetClientService context) {
        if (DBG) {
            Log.d(TAG, "make");
        }
        HeadsetClientStateMachine hfcsm = new HeadsetClientStateMachine(context);
        hfcsm.start();
        return hfcsm;
    }

    public void doQuit() {
        Log.d(TAG, "doQuit");
        if (mAudioManager != null) {
            mAudioManager.setParameters("hfp_enable=false");
        }
        quitNow();
    }

    public void cleanup() {
        if (mNativeAvailable) {
            cleanupNative();
            mNativeAvailable = false;
        }
    }

    private int hfToAmVol(int hfVol) {
        int amRange = mMaxAmVcVol - mMinAmVcVol;
        int hfRange = MAX_HFP_SCO_VOICE_CALL_VOLUME - MIN_HFP_SCO_VOICE_CALL_VOLUME;
        int amOffset =
            (amRange * (hfVol - MIN_HFP_SCO_VOICE_CALL_VOLUME)) / hfRange;
        int amVol = mMinAmVcVol + amOffset;
        Log.d(TAG, "HF -> AM " + hfVol + " " + amVol);
        return amVol;
    }

    private int amToHfVol(int amVol) {
        int amRange = mMaxAmVcVol - mMinAmVcVol;
        int hfRange = MAX_HFP_SCO_VOICE_CALL_VOLUME - MIN_HFP_SCO_VOICE_CALL_VOLUME;
        int hfOffset = (hfRange * (amVol - mMinAmVcVol)) / amRange;
        int hfVol = MIN_HFP_SCO_VOICE_CALL_VOLUME + hfOffset;
        Log.d(TAG, "AM -> HF " + amVol + " " + hfVol);
        return hfVol;
    }

    private class Disconnected extends State {
        @Override
        public void enter() {
            Log.d(TAG, "Enter Disconnected: " + getCurrentMessage().what);

            // cleanup
            mIndicatorNetworkState = HeadsetClientHalConstants.NETWORK_STATE_NOT_AVAILABLE;
            mIndicatorNetworkType = HeadsetClientHalConstants.SERVICE_TYPE_HOME;
            mIndicatorNetworkSignal = 0;
            mIndicatorBatteryLevel = 0;

            mAudioWbs = false;

            // will be set on connect
            mIndicatorCall = -1;
            mIndicatorCallSetup = -1;
            mIndicatorCallHeld = -1;

            mOperatorName = null;
            mSubscriberInfo = null;

            mQueuedActions = new LinkedList<Pair<Integer, Object>>();
            clearPendingAction();

            mVoiceRecognitionActive = HeadsetClientHalConstants.VR_STATE_STOPPED;
            mInBandRingtone = HeadsetClientHalConstants.IN_BAND_RING_NOT_PROVIDED;

            mCurrentDevice = null;

            mCalls.clear();
            mCallsUpdate.clear();

            mPeerFeatures = 0;
            mChldFeatures = 0;

            removeMessages(QUERY_CURRENT_CALLS);
        }

        @Override
        public synchronized boolean processMessage(Message message) {
            Log.d(TAG, "Disconnected process message: " + message.what);

            if (mCurrentDevice != null) {
                Log.e(TAG, "ERROR: current device not null in Disconnected");
                return NOT_HANDLED;
            }

            switch (message.what) {
                case CONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;

                    broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                            BluetoothProfile.STATE_DISCONNECTED);

                    if (!connectNative(getByteAddress(device))) {
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        break;
                    }

                    mCurrentDevice = device;

                    transitionTo(mConnecting);
                    break;
                case DISCONNECT:
                    // ignore
                    break;
                case STACK_EVENT:
                    StackEvent event = (StackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Stack event type: " + event.type);
                    }
                    switch (event.type) {
                        case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "Disconnected: Connection " + event.device
                                        + " state changed:" + event.valueInt);
                            }
                            processConnectionEvent(event.valueInt, event.device);
                            break;
                        default:
                            Log.e(TAG, "Disconnected: Unexpected stack event: " + event.type);
                            break;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Disconnected state
        private void processConnectionEvent(int state, BluetoothDevice device)
        {
            switch (state) {
                case HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED:
                    Log.w(TAG, "HFPClient Connecting from Disconnected state");
                    if (okToConnect(device)) {
                        Log.i(TAG, "Incoming AG accepted");
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                                BluetoothProfile.STATE_DISCONNECTED);
                        mCurrentDevice = device;
                        transitionTo(mConnecting);
                    } else {
                        Log.i(TAG, "Incoming AG rejected. priority=" + mService.getPriority(device)
                                +
                                " bondState=" + device.getBondState());
                        // reject the connection and stay in Disconnected state
                        // itself
                        disconnectNative(getByteAddress(device));
                        // the other profile connection should be initiated
                        AdapterService adapterService = AdapterService.getAdapterService();
                        if (adapterService != null) {
                            adapterService.connectOtherProfile(device,
                                    AdapterService.PROFILE_CONN_REJECTED);
                        }
                    }
                    break;
                case HeadsetClientHalConstants.CONNECTION_STATE_CONNECTING:
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTED:
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTING:
                default:
                    Log.i(TAG, "ignoring state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Disconnected: " + getCurrentMessage().what);
            }
        }
    }

    private class Connecting extends State {
        @Override
        public void enter() {
            if (DBG) {
                Log.d(TAG, "Enter Connecting: " + getCurrentMessage().what);
            }
            // This message is either consumed in processMessage or
            // removed in exit. It is safe to send a CONNECTING_TIMEOUT here since
            // the only transition is when connection attempt is initiated.
            sendMessageDelayed(CONNECTING_TIMEOUT, CONNECTING_TIMEOUT_MS);
        }

        @Override
        public synchronized boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Connecting process message: " + message.what);
            }

            switch (message.what) {
                case CONNECT:
                case CONNECT_AUDIO:
                case DISCONNECT:
                    deferMessage(message);
                    break;
                case STACK_EVENT:
                    StackEvent event = (StackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Connecting: event type: " + event.type);
                    }
                    switch (event.type) {
                        case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "Connecting: Connection " + event.device + " state changed:"
                                        + event.valueInt);
                            }
                            processConnectionEvent(event.valueInt, event.valueInt2,
                                    event.valueInt3, event.device);
                            break;
                        case EVENT_TYPE_AUDIO_STATE_CHANGED:
                        case EVENT_TYPE_VR_STATE_CHANGED:
                        case EVENT_TYPE_NETWORK_STATE:
                        case EVENT_TYPE_ROAMING_STATE:
                        case EVENT_TYPE_NETWORK_SIGNAL:
                        case EVENT_TYPE_BATTERY_LEVEL:
                        case EVENT_TYPE_CALL:
                        case EVENT_TYPE_CALLSETUP:
                        case EVENT_TYPE_CALLHELD:
                        case EVENT_TYPE_RESP_AND_HOLD:
                        case EVENT_TYPE_CLIP:
                        case EVENT_TYPE_CALL_WAITING:
                        case EVENT_TYPE_VOLUME_CHANGED:
                        case EVENT_TYPE_IN_BAND_RING:
                            deferMessage(message);
                            break;
                        case EVENT_TYPE_CMD_RESULT:
                        case EVENT_TYPE_SUBSCRIBER_INFO:
                        case EVENT_TYPE_CURRENT_CALLS:
                        case EVENT_TYPE_OPERATOR_NAME:
                        default:
                            Log.e(TAG, "Connecting: ignoring stack event: " + event.type);
                            break;
                    }
                    break;
                case CONNECTING_TIMEOUT:
                      // We timed out trying to connect, transition to disconnected.
                      Log.w(TAG, "Connection timeout for " + mCurrentDevice);
                      transitionTo(mDisconnected);
                      broadcastConnectionState(
                          mCurrentDevice,
                          BluetoothProfile.STATE_DISCONNECTED,
                          BluetoothProfile.STATE_CONNECTING);
                      break;

                default:
                    Log.w(TAG, "Message not handled " + message);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in Connecting state
        private void processConnectionEvent(
                int state, int peer_feat, int chld_feat, BluetoothDevice device) {
            switch (state) {
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTED:
                    broadcastConnectionState(mCurrentDevice, BluetoothProfile.STATE_DISCONNECTED,
                            BluetoothProfile.STATE_CONNECTING);
                    transitionTo(mDisconnected);
                    break;

                case HeadsetClientHalConstants.CONNECTION_STATE_SLC_CONNECTED:
                    Log.d(TAG, "HFPClient Connected from Connecting state");

                    mPeerFeatures = peer_feat;
                    mChldFeatures = chld_feat;

                    // We do not support devices which do not support enhanced call status (ECS).
                    if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_ECS) == 0) {
                        disconnectNative(getByteAddress(device));
                        return;
                    }

                    broadcastConnectionState(mCurrentDevice, BluetoothProfile.STATE_CONNECTED,
                        BluetoothProfile.STATE_CONNECTING);

                    // Send AT+NREC to remote if supported by audio
                    if (HeadsetClientHalConstants.HANDSFREECLIENT_NREC_SUPPORTED &&
                            ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_ECNR) ==
                                    HeadsetClientHalConstants.PEER_FEAT_ECNR)) {
                        if (sendATCmdNative(getByteAddress(mCurrentDevice),
                              HeadsetClientHalConstants.HANDSFREECLIENT_AT_CMD_NREC,
                              1 , 0, null)) {
                            addQueuedAction(DISABLE_NREC);
                        } else {
                            Log.e(TAG, "Failed to send NREC");
                        }
                    }
                    transitionTo(mConnected);

                    int amVol = mAudioManager.getStreamVolume(AudioManager.STREAM_VOICE_CALL);
                    sendMessage(
                            obtainMessage(HeadsetClientStateMachine.SET_SPEAKER_VOLUME, amVol, 0));
                    // Mic is either in ON state (full volume) or OFF state. There is no way in
                    // Android to change the MIC volume.
                    sendMessage(obtainMessage(HeadsetClientStateMachine.SET_MIC_VOLUME,
                            mAudioManager.isMicrophoneMute() ? 0 : 15, 0));

                    // query subscriber info
                    sendMessage(HeadsetClientStateMachine.SUBSCRIBER_INFO);
                    break;

                case HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED:
                    if (!mCurrentDevice.equals(device)) {
                        Log.w(TAG, "incoming connection event, device: " + device);

                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                                BluetoothProfile.STATE_DISCONNECTED);

                        mCurrentDevice = device;
                    }
                    break;
                case HeadsetClientHalConstants.CONNECTION_STATE_CONNECTING:
                    /* outgoing connecting started */
                    if (DBG) {
                        Log.d(TAG, "outgoing connection started, ignore");
                    }
                    break;
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTING:
                default:
                    Log.e(TAG, "Incorrect state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Connecting: " + getCurrentMessage().what);
            }
            removeMessages(CONNECTING_TIMEOUT);
        }
    }

    private class Connected extends State {
        @Override
        public void enter() {
            if (DBG) {
                Log.d(TAG, "Enter Connected: " + getCurrentMessage().what);
            }
            mAudioWbs = false;
        }

        @Override
        public synchronized boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "Connected process message: " + message.what);
            }
            if (DBG) {
                if (mCurrentDevice == null) {
                    Log.e(TAG, "ERROR: mCurrentDevice is null in Connected");
                    return NOT_HANDLED;
                }
            }

            switch (message.what) {
                case CONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (mCurrentDevice.equals(device)) {
                        // already connected to this device, do nothing
                        break;
                    }

                    if (!disconnectNative(getByteAddress(mCurrentDevice))) {
                        // if succeed this will be handled from disconnected
                        // state
                        broadcastConnectionState(device, BluetoothProfile.STATE_CONNECTING,
                                BluetoothProfile.STATE_DISCONNECTED);
                        broadcastConnectionState(device, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTING);
                        break;
                    }

                    // will be handled when entered disconnected
                    deferMessage(message);
                    break;
                case DISCONNECT:
                    BluetoothDevice dev = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(dev)) {
                        break;
                    }
                    broadcastConnectionState(dev, BluetoothProfile.STATE_DISCONNECTING,
                            BluetoothProfile.STATE_CONNECTED);
                    if (!disconnectNative(getByteAddress(dev))) {
                        // disconnecting failed
                        broadcastConnectionState(dev, BluetoothProfile.STATE_CONNECTED,
                                BluetoothProfile.STATE_DISCONNECTING);
                        break;
                    }
                    break;
                case CONNECT_AUDIO:
                    // TODO: handle audio connection failure
                    if (!connectAudioNative(getByteAddress(mCurrentDevice))) {
                        Log.e(TAG, "ERROR: Couldn't connect Audio.");
                    }
                    break;
                case DISCONNECT_AUDIO:
                    // TODO: handle audio disconnection failure
                    if (!disconnectAudioNative(getByteAddress(mCurrentDevice))) {
                        Log.e(TAG, "ERROR: Couldn't connect Audio.");
                    }
                    break;
                case VOICE_RECOGNITION_START:
                    if (mVoiceRecognitionActive == HeadsetClientHalConstants.VR_STATE_STOPPED) {
                        if (startVoiceRecognitionNative(getByteAddress(mCurrentDevice))) {
                            addQueuedAction(VOICE_RECOGNITION_START);
                        } else {
                            Log.e(TAG, "ERROR: Couldn't start voice recognition");
                        }
                    }
                    break;
                case VOICE_RECOGNITION_STOP:
                    if (mVoiceRecognitionActive == HeadsetClientHalConstants.VR_STATE_STARTED) {
                        if (stopVoiceRecognitionNative(getByteAddress(mCurrentDevice))) {
                            addQueuedAction(VOICE_RECOGNITION_STOP);
                        } else {
                            Log.e(TAG, "ERROR: Couldn't stop voice recognition");
                        }
                    }
                    break;
                // Called only for Mute/Un-mute - Mic volume change is not allowed.
                case SET_MIC_VOLUME:
                    if (mVgmFromStack) {
                        mVgmFromStack = false;
                        break;
                    }
                    if (setVolumeNative(
                            getByteAddress(mCurrentDevice),
                            HeadsetClientHalConstants.VOLUME_TYPE_MIC,
                            message.arg1)) {
                        addQueuedAction(SET_MIC_VOLUME);
                    }
                    break;
                case SET_SPEAKER_VOLUME:
                    // This message should always contain the volume in AudioManager max normalized.
                    int amVol = message.arg1;
                    int hfVol = amToHfVol(amVol);
                    Log.d(TAG,"HF volume is set to " + hfVol);
                    mAudioManager.setParameters("hfp_volume=" + hfVol);
                    if (mVgsFromStack) {
                        mVgsFromStack = false;
                        break;
                    }
                    if (setVolumeNative(getByteAddress(mCurrentDevice),
                          HeadsetClientHalConstants.VOLUME_TYPE_SPK, hfVol)) {
                        addQueuedAction(SET_SPEAKER_VOLUME);
                    }
                    break;
                case DIAL_NUMBER:
                    // Add the call as an outgoing call.
                    BluetoothHeadsetClientCall c = (BluetoothHeadsetClientCall) message.obj;
                    mCalls.put(HF_ORIGINATED_CALL_ID, c);

                    if (dialNative(getByteAddress(mCurrentDevice), c.getNumber())) {
                        addQueuedAction(DIAL_NUMBER, c.getNumber());
                        // Start looping on calling current calls.
                        sendMessage(QUERY_CURRENT_CALLS);
                    } else {
                        Log.e(TAG, "ERROR: Cannot dial with a given number:" + (String) message.obj);
                        // Set the call to terminated remove.
                        c.setState(BluetoothHeadsetClientCall.CALL_STATE_TERMINATED);
                        sendCallChangedIntent(c);
                        mCalls.remove(HF_ORIGINATED_CALL_ID);
                    }
                    break;
                case ACCEPT_CALL:
                    acceptCall(message.arg1, false);
                    break;
                case REJECT_CALL:
                    rejectCall();
                    break;
                case HOLD_CALL:
                    holdCall();
                    break;
                case TERMINATE_CALL:
                    terminateCall();
                    break;
                case ENTER_PRIVATE_MODE:
                    enterPrivateMode(message.arg1);
                    break;
                case EXPLICIT_CALL_TRANSFER:
                    explicitCallTransfer();
                    break;
                case SEND_DTMF:
                    if (sendDtmfNative(getByteAddress(mCurrentDevice), (byte) message.arg1)) {
                        addQueuedAction(SEND_DTMF);
                    } else {
                        Log.e(TAG, "ERROR: Couldn't send DTMF");
                    }
                    break;
                case SUBSCRIBER_INFO:
                    if (retrieveSubscriberInfoNative(getByteAddress(mCurrentDevice))) {
                        addQueuedAction(SUBSCRIBER_INFO);
                    } else {
                        Log.e(TAG, "ERROR: Couldn't retrieve subscriber info");
                    }
                    break;
                case LAST_VTAG_NUMBER:
                    if (requestLastVoiceTagNumberNative(getByteAddress(mCurrentDevice))) {
                        addQueuedAction(LAST_VTAG_NUMBER);
                    } else {
                        Log.e(TAG, "ERROR: Couldn't get last VTAG number");
                    }
                    break;
                case QUERY_CURRENT_CALLS:
                    // Whenever the timer expires we query calls if there are outstanding requests
                    // for query calls.
                    long currentElapsed = SystemClock.elapsedRealtime();
                    if (mClccTimer < currentElapsed) {
                        queryCallsStart();
                        mClccTimer = currentElapsed + QUERY_CURRENT_CALLS_WAIT_MILLIS;
                        // Request satisfied, ignore all other call query messages.
                        removeMessages(QUERY_CURRENT_CALLS);
                    } else {
                        // Replace all messages with one concrete message.
                        removeMessages(QUERY_CURRENT_CALLS);
                        sendMessageDelayed(QUERY_CURRENT_CALLS, QUERY_CURRENT_CALLS_WAIT_MILLIS);
                    }
                    break;
                case STACK_EVENT:
                    Intent intent = null;
                    StackEvent event = (StackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "Connected: event type: " + event.type);
                    }

                    switch (event.type) {
                        case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "Connected: Connection state changed: " + event.device
                                        + ": " + event.valueInt);
                            }
                            processConnectionEvent(event.valueInt, event.device);
                            break;
                        case EVENT_TYPE_AUDIO_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "Connected: Audio state changed: " + event.device + ": "
                                        + event.valueInt);
                            }
                            processAudioEvent(event.valueInt, event.device);
                            break;
                        case EVENT_TYPE_NETWORK_STATE:
                            if (DBG) {
                                Log.d(TAG, "Connected: Network state: " + event.valueInt);
                            }
                            mIndicatorNetworkState = event.valueInt;

                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_NETWORK_STATUS,
                                    event.valueInt);

                            if (mIndicatorNetworkState ==
                                    HeadsetClientHalConstants.NETWORK_STATE_NOT_AVAILABLE) {
                                mOperatorName = null;
                                intent.putExtra(BluetoothHeadsetClient.EXTRA_OPERATOR_NAME,
                                        mOperatorName);
                            }

                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);

                            if (mIndicatorNetworkState ==
                                    HeadsetClientHalConstants.NETWORK_STATE_AVAILABLE) {
                                if (queryCurrentOperatorNameNative(getByteAddress(mCurrentDevice))) {
                                    addQueuedAction(QUERY_OPERATOR_NAME);
                                } else {
                                    Log.e(TAG, "ERROR: Couldn't querry operator name");
                                }
                            }
                            break;
                        case EVENT_TYPE_ROAMING_STATE:
                            mIndicatorNetworkType = event.valueInt;

                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_NETWORK_ROAMING,
                                    event.valueInt);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_NETWORK_SIGNAL:
                            mIndicatorNetworkSignal = event.valueInt;

                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_NETWORK_SIGNAL_STRENGTH,
                                    event.valueInt);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_BATTERY_LEVEL:
                            mIndicatorBatteryLevel = event.valueInt;

                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_BATTERY_LEVEL,
                                    event.valueInt);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_OPERATOR_NAME:
                            mOperatorName = event.valueString;

                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_OPERATOR_NAME,
                                    event.valueString);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_VR_STATE_CHANGED:
                            if (mVoiceRecognitionActive != event.valueInt) {
                                mVoiceRecognitionActive = event.valueInt;

                                intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                                intent.putExtra(BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION,
                                        mVoiceRecognitionActive);
                                intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                                mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            }
                            break;
                        case EVENT_TYPE_CALL:
                            updateCallIndicator(event.valueInt);
                            break;
                        case EVENT_TYPE_CALLSETUP:
                            updateCallSetupIndicator(event.valueInt);
                            break;
                        case EVENT_TYPE_CALLHELD:
                            updateCallHeldIndicator(event.valueInt);
                            break;
                        case EVENT_TYPE_RESP_AND_HOLD:
                            updateRespAndHold(event.valueInt);
                            break;
                        case EVENT_TYPE_CLIP:
                            updateClip(event.valueString);
                            break;
                        case EVENT_TYPE_CALL_WAITING:
                            updateCCWA(event.valueString);
                            break;
                        case EVENT_TYPE_IN_BAND_RING:
                            if (mInBandRingtone != event.valueInt) {
                                mInBandRingtone = event.valueInt;
                                intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                                intent.putExtra(BluetoothHeadsetClient.EXTRA_IN_BAND_RING,
                                        mInBandRingtone);
                                intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                                mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            }
                            break;
                        case EVENT_TYPE_CURRENT_CALLS:
                            queryCallsUpdate(
                                    event.valueInt,
                                    event.valueInt3,
                                    event.valueString,
                                    event.valueInt4 ==
                                            HeadsetClientHalConstants.CALL_MPTY_TYPE_MULTI,
                                    event.valueInt2 ==
                                            HeadsetClientHalConstants.CALL_DIRECTION_OUTGOING);
                            break;
                        case EVENT_TYPE_VOLUME_CHANGED:
                            if (event.valueInt == HeadsetClientHalConstants.VOLUME_TYPE_SPK) {
                                Log.d(TAG, "AM volume set to " +
                                      hfToAmVol(event.valueInt2));
                                mAudioManager.setStreamVolume(
                                    AudioManager.STREAM_VOICE_CALL,
                                    hfToAmVol(event.valueInt2),
                                    AudioManager.FLAG_SHOW_UI);
                                mVgsFromStack = true;
                            } else if (event.valueInt ==
                                HeadsetClientHalConstants.VOLUME_TYPE_MIC) {
                                mAudioManager.setMicrophoneMute(event.valueInt2 == 0);

                                mVgmFromStack = true;
                            }
                            break;
                        case EVENT_TYPE_CMD_RESULT:
                            Pair<Integer, Object> queuedAction = mQueuedActions.poll();

                            // should not happen but...
                            if (queuedAction == null || queuedAction.first == NO_ACTION) {
                                clearPendingAction();
                                break;
                            }

                            if (DBG) {
                                Log.d(TAG, "Connected: command result: " + event.valueInt
                                        + " queuedAction: " + queuedAction.first);
                            }

                            switch (queuedAction.first) {
                                case VOICE_RECOGNITION_STOP:
                                case VOICE_RECOGNITION_START:
                                    if (event.valueInt == HeadsetClientHalConstants.CMD_COMPLETE_OK) {
                                        if (queuedAction.first == VOICE_RECOGNITION_STOP) {
                                            mVoiceRecognitionActive =
                                                    HeadsetClientHalConstants.VR_STATE_STOPPED;
                                        } else {
                                            mVoiceRecognitionActive =
                                                    HeadsetClientHalConstants.VR_STATE_STARTED;
                                        }
                                    }
                                    intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                                    intent.putExtra(
                                            BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION,
                                            mVoiceRecognitionActive);
                                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                                    mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                                    break;
                                case QUERY_CURRENT_CALLS:
                                    queryCallsDone();
                                    break;
                                case ACCEPT_CALL:
                                    if (event.valueInt == BluetoothHeadsetClient.ACTION_RESULT_OK) {
                                        mPendingAction = queuedAction;
                                    } else {
                                        if (callsInState(BluetoothHeadsetClientCall.CALL_STATE_ACTIVE) == 0) {
                                            if(getCall(BluetoothHeadsetClientCall.CALL_STATE_INCOMING) != null &&
                                                (Integer) mPendingAction.second == HeadsetClientHalConstants.CALL_ACTION_ATA) {
                                                acceptCall(BluetoothHeadsetClient.CALL_ACCEPT_NONE, true);
                                                break;
                                            } else if(getCall(BluetoothHeadsetClientCall.CALL_STATE_WAITING) != null &&
                                                     (Integer) mPendingAction.second == HeadsetClientHalConstants.CALL_ACTION_CHLD_2) {
                                                acceptCall(BluetoothHeadsetClient.CALL_ACCEPT_NONE, true);
                                                break;
                                            }
                                        }
                                        sendActionResultIntent(event);
                                    }
                                    break;
                                case DIAL_NUMBER:
                                case REJECT_CALL:
                                case HOLD_CALL:
                                case TERMINATE_CALL:
                                case ENTER_PRIVATE_MODE:
                                case TERMINATE_SPECIFIC_CALL:
                                    // if terminating specific succeed no other
                                    // event is send
                                    if (event.valueInt != BluetoothHeadsetClient.ACTION_RESULT_OK) {
                                        sendActionResultIntent(event);
                                    }
                                    break;
                                case LAST_VTAG_NUMBER:
                                    if (event.valueInt != BluetoothHeadsetClient.ACTION_RESULT_OK) {
                                        sendActionResultIntent(event);
                                    }
                                    break;
                                case DISABLE_NREC:
                                    if (event.valueInt != HeadsetClientHalConstants.CMD_COMPLETE_OK) {
                                        Log.w(TAG, "Failed to disable AG's EC and NR");
                                    }
                                    break;
                                case SET_MIC_VOLUME:
                                case SET_SPEAKER_VOLUME:
                                case SUBSCRIBER_INFO:
                                case QUERY_OPERATOR_NAME:
                                    break;
                                default:
                                    sendActionResultIntent(event);
                                    break;
                            }

                            break;
                        case EVENT_TYPE_SUBSCRIBER_INFO:
                            /* TODO should we handle type as well? */
                            mSubscriberInfo = event.valueString;
                            intent = new Intent(BluetoothHeadsetClient.ACTION_AG_EVENT);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_SUBSCRIBER_INFO,
                                    mSubscriberInfo);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_LAST_VOICE_TAG_NUMBER:
                            intent = new Intent(BluetoothHeadsetClient.ACTION_LAST_VTAG);
                            intent.putExtra(BluetoothHeadsetClient.EXTRA_NUMBER,
                                    event.valueString);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
                            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                            break;
                        case EVENT_TYPE_RING_INDICATION:
                            // Ringing is not handled at this indication and rather should be
                            // implemented (by the client of this service). Use the
                            // CALL_STATE_INCOMING (and similar) handle ringing.
                            break;
                        default:
                            Log.e(TAG, "Unknown stack event: " + event.type);
                            break;
                    }

                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        private void sendActionResultIntent(StackEvent event) {
            Intent intent = new Intent(BluetoothHeadsetClient.ACTION_RESULT);
            intent.putExtra(BluetoothHeadsetClient.EXTRA_RESULT_CODE, event.valueInt);
            if (event.valueInt == BluetoothHeadsetClient.ACTION_RESULT_ERROR_CME) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_CME_CODE, event.valueInt2);
            }
            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, event.device);
            mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
        }

        // in Connected state
        private void processConnectionEvent(int state, BluetoothDevice device) {
            switch (state) {
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTED:
                    if (DBG) {
                        Log.d(TAG, "Connected disconnects.");
                    }
                    // AG disconnects
                    if (mCurrentDevice.equals(device)) {
                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTED);
                        transitionTo(mDisconnected);
                    } else {
                        Log.e(TAG, "Disconnected from unknown device: " + device);
                    }
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        // in Connected state
        private void processAudioEvent(int state, BluetoothDevice device) {
            // message from old device
            if (!mCurrentDevice.equals(device)) {
                Log.e(TAG, "Audio changed on disconnected device: " + device);
                return;
            }

            switch (state) {
                case HeadsetClientHalConstants.AUDIO_STATE_CONNECTED_MSBC:
                    mAudioWbs = true;
                    // fall through
                case HeadsetClientHalConstants.AUDIO_STATE_CONNECTED:
                    if (!mAudioRouteAllowed) {
                        sendMessage(HeadsetClientStateMachine.DISCONNECT_AUDIO);
                        break;
                    }

                    // Audio state is split in two parts, the audio focus is maintained by the
                    // entity exercising this service (typically the Telecom stack) and audio
                    // routing is handled by the bluetooth stack itself. The only reason to do so is
                    // because Bluetooth SCO connection from the HF role is not entirely supported
                    // for routing and volume purposes.
                    // NOTE: All calls here are routed via the setParameters which changes the
                    // routing at the Audio HAL level.
                    mAudioState = BluetoothHeadsetClient.STATE_AUDIO_CONNECTED;

                    // We need to set the volume after switching into HFP mode as some Audio HALs
                    // reset the volume to a known-default on mode switch.
                    final int amVol =
                            mAudioManager.getStreamVolume(AudioManager.STREAM_VOICE_CALL);
                    final int hfVol = amToHfVol(amVol);

                    if (DBG) {
                        Log.d(TAG,"hfp_enable=true mAudioWbs is " + mAudioWbs);
                    }
                    if (mAudioWbs) {
                        if (DBG) {
                            Log.d(TAG,"Setting sampling rate as 16000");
                        }
                        mAudioManager.setParameters("hfp_set_sampling_rate=16000");
                    }
                    else {
                        if (DBG) {
                            Log.d(TAG,"Setting sampling rate as 8000");
                        }
                        mAudioManager.setParameters("hfp_set_sampling_rate=8000");
                    }
                    if (DBG) {
                        Log.d(TAG, "hf_volume " + hfVol);
                    }
                    mAudioManager.setParameters("hfp_enable=true");
                    mAudioManager.setParameters("hfp_volume=" + hfVol);
                    transitionTo(mAudioOn);
                    break;
                case HeadsetClientHalConstants.AUDIO_STATE_CONNECTING:
                    mAudioState = BluetoothHeadsetClient.STATE_AUDIO_CONNECTING;
                    broadcastAudioState(device, BluetoothHeadsetClient.STATE_AUDIO_CONNECTING,
                            BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED);
                    break;
                case HeadsetClientHalConstants.AUDIO_STATE_DISCONNECTED:
                    if (mAudioState == BluetoothHeadsetClient.STATE_AUDIO_CONNECTING) {
                        mAudioState = BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED;
                        broadcastAudioState(device,
                                BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED,
                                BluetoothHeadsetClient.STATE_AUDIO_CONNECTING);
                    }
                    break;
                default:
                    Log.e(TAG, "Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit Connected: " + getCurrentMessage().what);
            }
        }
    }

    private class AudioOn extends State {
        @Override
        public void enter() {
            if (DBG) {
                Log.d(TAG, "Enter AudioOn: " + getCurrentMessage().what);
            }
            broadcastAudioState(mCurrentDevice, BluetoothHeadsetClient.STATE_AUDIO_CONNECTED,
                BluetoothHeadsetClient.STATE_AUDIO_CONNECTING);
        }

        @Override
        public synchronized boolean processMessage(Message message) {
            if (DBG) {
                Log.d(TAG, "AudioOn process message: " + message.what);
            }
            if (DBG) {
                if (mCurrentDevice == null) {
                    Log.e(TAG, "ERROR: mCurrentDevice is null in Connected");
                    return NOT_HANDLED;
                }
            }

            switch (message.what) {
                case DISCONNECT:
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mCurrentDevice.equals(device)) {
                        break;
                    }
                    deferMessage(message);
                    /*
                     * fall through - disconnect audio first then expect
                     * deferred DISCONNECT message in Connected state
                     */
                case DISCONNECT_AUDIO:
                    /*
                     * just disconnect audio and wait for
                     * EVENT_TYPE_AUDIO_STATE_CHANGED, that triggers State
                     * Machines state changing
                     */
                    if (disconnectAudioNative(getByteAddress(mCurrentDevice))) {
                        mAudioState = BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED;
                        if (DBG) {
                            Log.d(TAG,"hfp_enable=false");
                        }
                        mAudioManager.setParameters("hfp_enable=false");
                        broadcastAudioState(mCurrentDevice,
                                BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED,
                                BluetoothHeadsetClient.STATE_AUDIO_CONNECTED);
                    }
                    break;
                case STACK_EVENT:
                    StackEvent event = (StackEvent) message.obj;
                    if (DBG) {
                        Log.d(TAG, "AudioOn: event type: " + event.type);
                    }
                    switch (event.type) {
                        case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "AudioOn connection state changed" + event.device + ": "
                                        + event.valueInt);
                            }
                            processConnectionEvent(event.valueInt, event.device);
                            break;
                        case EVENT_TYPE_AUDIO_STATE_CHANGED:
                            if (DBG) {
                                Log.d(TAG, "AudioOn audio state changed" + event.device + ": "
                                        + event.valueInt);
                            }
                            processAudioEvent(event.valueInt, event.device);
                            break;
                        default:
                            return NOT_HANDLED;
                    }
                    break;
                default:
                    return NOT_HANDLED;
            }
            return HANDLED;
        }

        // in AudioOn state. Can AG disconnect RFCOMM prior to SCO? Handle this
        private void processConnectionEvent(int state, BluetoothDevice device) {
            switch (state) {
                case HeadsetClientHalConstants.CONNECTION_STATE_DISCONNECTED:
                    if (mCurrentDevice.equals(device)) {
                        processAudioEvent(HeadsetClientHalConstants.AUDIO_STATE_DISCONNECTED,
                                device);
                        broadcastConnectionState(mCurrentDevice,
                                BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.STATE_CONNECTED);
                        transitionTo(mDisconnected);
                    } else {
                        Log.e(TAG, "Disconnected from unknown device: " + device);
                    }
                    break;
                default:
                    Log.e(TAG, "Connection State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        // in AudioOn state
        private void processAudioEvent(int state, BluetoothDevice device) {
            if (!mCurrentDevice.equals(device)) {
                Log.e(TAG, "Audio changed on disconnected device: " + device);
                return;
            }

            switch (state) {
                case HeadsetClientHalConstants.AUDIO_STATE_DISCONNECTED:
                    if (mAudioState != BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED) {
                        mAudioState = BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED;
                        // Audio focus may still be held by the entity controlling the actual call
                        // (such as Telecom) and hence this will still keep the call around, there
                        // is not much we can do here since dropping the call without user consent
                        // even if the audio connection snapped may not be a good idea.
                        if (DBG) {
                            Log.d(TAG,"hfp_enable=false");
                        }
                        mAudioManager.setParameters("hfp_enable=false");
                        broadcastAudioState(device,
                                BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED,
                                BluetoothHeadsetClient.STATE_AUDIO_CONNECTED);
                    }

                    transitionTo(mConnected);
                    break;
                default:
                    Log.e(TAG, "Audio State Device: " + device + " bad state: " + state);
                    break;
            }
        }

        @Override
        public void exit() {
            if (DBG) {
                Log.d(TAG, "Exit AudioOn: " + getCurrentMessage().what);
            }
        }
    }

    /**
     * @hide
     */
    public synchronized int getConnectionState(BluetoothDevice device) {
        if (mCurrentDevice == null) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        if (!mCurrentDevice.equals(device)) {
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        IState currentState = getCurrentState();
        if (currentState == mConnecting) {
            return BluetoothProfile.STATE_CONNECTING;
        }

        if (currentState == mConnected || currentState == mAudioOn) {
            return BluetoothProfile.STATE_CONNECTED;
        }

        Log.e(TAG, "Bad currentState: " + currentState);
        return BluetoothProfile.STATE_DISCONNECTED;
    }

    private void broadcastAudioState(BluetoothDevice device, int newState, int prevState) {
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_AUDIO_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);

        if (newState == BluetoothHeadsetClient.STATE_AUDIO_CONNECTED) {
            intent.putExtra(BluetoothHeadsetClient.EXTRA_AUDIO_WBS, mAudioWbs);
        }

        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
        if (DBG) {
            Log.d(TAG, "Audio state " + device + ": " + prevState + "->" + newState);
        }
    }

    // This method does not check for error condition (newState == prevState)
    private void broadcastConnectionState(BluetoothDevice device, int newState, int prevState) {
        if (DBG) {
            Log.d(TAG, "Connection state " + device + ": " + prevState + "->" + newState);
        }
        /*
         * Notifying the connection state change of the profile before sending
         * the intent for connection state change, as it was causing a race
         * condition, with the UI not being updated with the correct connection
         * state.
         */
        mService.notifyProfileConnectionStateChanged(device, BluetoothProfile.HEADSET_CLIENT,
                newState, prevState);
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);

        // add feature extras when connected
        if (newState == BluetoothProfile.STATE_CONNECTED) {
            if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_3WAY) ==
                    HeadsetClientHalConstants.PEER_FEAT_3WAY) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_3WAY_CALLING, true);
            }
            if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_VREC) ==
                    HeadsetClientHalConstants.PEER_FEAT_VREC) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_VOICE_RECOGNITION, true);
            }
            if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_VTAG) ==
                    HeadsetClientHalConstants.PEER_FEAT_VTAG) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ATTACH_NUMBER_TO_VT, true);
            }
            if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_REJECT) ==
                    HeadsetClientHalConstants.PEER_FEAT_REJECT) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_REJECT_CALL, true);
            }
            if ((mPeerFeatures & HeadsetClientHalConstants.PEER_FEAT_ECC) ==
                    HeadsetClientHalConstants.PEER_FEAT_ECC) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ECC, true);
            }

            // add individual CHLD support extras
            if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC) ==
                    HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ACCEPT_HELD_OR_WAITING_CALL, true);
            }
            if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_REL) ==
                    HeadsetClientHalConstants.CHLD_FEAT_REL) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_HELD_OR_WAITING_CALL, true);
            }
            if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_REL_ACC) ==
                    HeadsetClientHalConstants.CHLD_FEAT_REL_ACC) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_AND_ACCEPT, true);
            }
            if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_MERGE) ==
                    HeadsetClientHalConstants.CHLD_FEAT_MERGE) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE, true);
            }
            if ((mChldFeatures & HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH) ==
                    HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH) {
                intent.putExtra(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE_AND_DETACH, true);
            }
        }
        mService.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    boolean isConnected() {
        IState currentState = getCurrentState();
        return (currentState == mConnected || currentState == mAudioOn);
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        List<BluetoothDevice> deviceList = new ArrayList<BluetoothDevice>();
        Set<BluetoothDevice> bondedDevices = mAdapter.getBondedDevices();
        int connectionState;
        synchronized (this) {
            for (BluetoothDevice device : bondedDevices) {
                ParcelUuid[] featureUuids = device.getUuids();
                if (!BluetoothUuid.isUuidPresent(featureUuids, BluetoothUuid.Handsfree_AG)) {
                    continue;
                }
                connectionState = getConnectionState(device);
                for (int state : states) {
                    if (connectionState == state) {
                        deviceList.add(device);
                    }
                }
            }
        }
        return deviceList;
    }

    boolean okToConnect(BluetoothDevice device) {
        int priority = mService.getPriority(device);
        boolean ret = false;
        // check priority and accept or reject the connection. if priority is
        // undefined
        // it is likely that our SDP has not completed and peer is initiating
        // the
        // connection. Allow this connection, provided the device is bonded
        if ((BluetoothProfile.PRIORITY_OFF < priority) ||
                ((BluetoothProfile.PRIORITY_UNDEFINED == priority) &&
                (device.getBondState() != BluetoothDevice.BOND_NONE))) {
            ret = true;
        }
        return ret;
    }

    boolean isAudioOn() {
        return (getCurrentState() == mAudioOn);
    }

    public void setAudioRouteAllowed(boolean allowed) {
        mAudioRouteAllowed = allowed;
    }

    public boolean getAudioRouteAllowed() {
        return mAudioRouteAllowed;
    }

    synchronized int getAudioState(BluetoothDevice device) {
        if (mCurrentDevice == null || !mCurrentDevice.equals(device)) {
            return BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED;
        }
        return mAudioState;
    }

    /**
     * @hide
     */
    List<BluetoothDevice> getConnectedDevices() {
        List<BluetoothDevice> devices = new ArrayList<BluetoothDevice>();
        synchronized (this) {
            if (isConnected()) {
                devices.add(mCurrentDevice);
            }
        }
        return devices;
    }

    private BluetoothDevice getDevice(byte[] address) {
        return mAdapter.getRemoteDevice(Utils.getAddressStringFromByte(address));
    }

    private void onConnectionStateChanged(int state, int peer_feat, int chld_feat, byte[] address) {
        StackEvent event = new StackEvent(EVENT_TYPE_CONNECTION_STATE_CHANGED);
        event.valueInt = state;
        event.valueInt2 = peer_feat;
        event.valueInt3 = chld_feat;
        event.device = getDevice(address);
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onAudioStateChanged(int state, byte[] address) {
        StackEvent event = new StackEvent(EVENT_TYPE_AUDIO_STATE_CHANGED);
        event.valueInt = state;
        event.device = getDevice(address);
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onVrStateChanged(int state) {
        StackEvent event = new StackEvent(EVENT_TYPE_VR_STATE_CHANGED);
        event.valueInt = state;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onNetworkState(int state) {
        StackEvent event = new StackEvent(EVENT_TYPE_NETWORK_STATE);
        event.valueInt = state;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onNetworkRoaming(int state) {
        StackEvent event = new StackEvent(EVENT_TYPE_ROAMING_STATE);
        event.valueInt = state;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onNetworkSignal(int signal) {
        StackEvent event = new StackEvent(EVENT_TYPE_NETWORK_SIGNAL);
        event.valueInt = signal;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onBatteryLevel(int level) {
        StackEvent event = new StackEvent(EVENT_TYPE_BATTERY_LEVEL);
        event.valueInt = level;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onCurrentOperator(String name) {
        StackEvent event = new StackEvent(EVENT_TYPE_OPERATOR_NAME);
        event.valueString = name;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    /**
     * CIEV (Call indicators) notifying if a call is in progress.
     *
     * Values Include:
     * 0 - No call in progress
     * 1 - Atleast 1 call is in progress
     */
    private void onCall(int call) {
        StackEvent event = new StackEvent(EVENT_TYPE_CALL);
        event.valueInt = call;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    /**
     * CIEV (Call indicators) notifying if call(s) are getting set up.
     *
     * Values incldue:
     * 0 - No current call is in setup
     * 1 - Incoming call process ongoing
     * 2 - Outgoing call process ongoing
     * 3 - Remote party being alerted for outgoing call
     */
    private void onCallSetup(int callsetup) {
        StackEvent event = new StackEvent(EVENT_TYPE_CALLSETUP);
        event.valueInt = callsetup;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    /**
     * CIEV (Call indicators) notifying call held states.
     *
     * Values include:
     * 0 - No calls held
     * 1 - Call is placed on hold or active/held calls wapped (The AG has both an ACTIVE and HELD
     * call)
     * 2 - Call on hold, no active call
     */
    private void onCallHeld(int callheld) {
        StackEvent event = new StackEvent(EVENT_TYPE_CALLHELD);
        event.valueInt = callheld;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onRespAndHold(int resp_and_hold) {
        StackEvent event = new StackEvent(EVENT_TYPE_RESP_AND_HOLD);
        event.valueInt = resp_and_hold;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onClip(String number) {
        StackEvent event = new StackEvent(EVENT_TYPE_CLIP);
        event.valueString = number;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onCallWaiting(String number) {
        StackEvent event = new StackEvent(EVENT_TYPE_CALL_WAITING);
        event.valueString = number;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onCurrentCalls(int index, int dir, int state, int mparty, String number) {
        StackEvent event = new StackEvent(EVENT_TYPE_CURRENT_CALLS);
        event.valueInt = index;
        event.valueInt2 = dir;
        event.valueInt3 = state;
        event.valueInt4 = mparty;
        event.valueString = number;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onVolumeChange(int type, int volume) {
        StackEvent event = new StackEvent(EVENT_TYPE_VOLUME_CHANGED);
        event.valueInt = type;
        event.valueInt2 = volume;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onCmdResult(int type, int cme) {
        StackEvent event = new StackEvent(EVENT_TYPE_CMD_RESULT);
        event.valueInt = type;
        event.valueInt2 = cme;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onSubscriberInfo(String number, int type) {
        StackEvent event = new StackEvent(EVENT_TYPE_SUBSCRIBER_INFO);
        event.valueInt = type;
        event.valueString = number;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onInBandRing(int in_band) {
        StackEvent event = new StackEvent(EVENT_TYPE_IN_BAND_RING);
        event.valueInt = in_band;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onLastVoiceTagNumber(String number) {
        StackEvent event = new StackEvent(EVENT_TYPE_LAST_VOICE_TAG_NUMBER);
        event.valueString = number;
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private void onRingIndication() {
        StackEvent event = new StackEvent(EVENT_TYPE_RING_INDICATION);
        if (DBG) {
            Log.d(TAG, "incoming" + event);
        }
        sendMessage(STACK_EVENT, event);
    }

    private String getCurrentDeviceName() {
        String defaultName = "<unknown>";
        if (mCurrentDevice == null) {
            return defaultName;
        }
        String deviceName = mCurrentDevice.getName();
        if (deviceName == null) {
            return defaultName;
        }
        return deviceName;
    }

    private byte[] getByteAddress(BluetoothDevice device) {
        return Utils.getBytesFromAddress(device.getAddress());
    }

    // Event types for STACK_EVENT message
    final private static int EVENT_TYPE_NONE = 0;
    final private static int EVENT_TYPE_CONNECTION_STATE_CHANGED = 1;
    final private static int EVENT_TYPE_AUDIO_STATE_CHANGED = 2;
    final private static int EVENT_TYPE_VR_STATE_CHANGED = 3;
    final private static int EVENT_TYPE_NETWORK_STATE = 4;
    final private static int EVENT_TYPE_ROAMING_STATE = 5;
    final private static int EVENT_TYPE_NETWORK_SIGNAL = 6;
    final private static int EVENT_TYPE_BATTERY_LEVEL = 7;
    final private static int EVENT_TYPE_OPERATOR_NAME = 8;
    final private static int EVENT_TYPE_CALL = 9;
    final private static int EVENT_TYPE_CALLSETUP = 10;
    final private static int EVENT_TYPE_CALLHELD = 11;
    final private static int EVENT_TYPE_CLIP = 12;
    final private static int EVENT_TYPE_CALL_WAITING = 13;
    final private static int EVENT_TYPE_CURRENT_CALLS = 14;
    final private static int EVENT_TYPE_VOLUME_CHANGED = 15;
    final private static int EVENT_TYPE_CMD_RESULT = 16;
    final private static int EVENT_TYPE_SUBSCRIBER_INFO = 17;
    final private static int EVENT_TYPE_RESP_AND_HOLD = 18;
    final private static int EVENT_TYPE_IN_BAND_RING = 19;
    final private static int EVENT_TYPE_LAST_VOICE_TAG_NUMBER = 20;
    final private static int EVENT_TYPE_RING_INDICATION= 21;

    // for debugging only
    private final String EVENT_TYPE_NAMES[] =
    {
            "EVENT_TYPE_NONE",
            "EVENT_TYPE_CONNECTION_STATE_CHANGED",
            "EVENT_TYPE_AUDIO_STATE_CHANGED",
            "EVENT_TYPE_VR_STATE_CHANGED",
            "EVENT_TYPE_NETWORK_STATE",
            "EVENT_TYPE_ROAMING_STATE",
            "EVENT_TYPE_NETWORK_SIGNAL",
            "EVENT_TYPE_BATTERY_LEVEL",
            "EVENT_TYPE_OPERATOR_NAME",
            "EVENT_TYPE_CALL",
            "EVENT_TYPE_CALLSETUP",
            "EVENT_TYPE_CALLHELD",
            "EVENT_TYPE_CLIP",
            "EVENT_TYPE_CALL_WAITING",
            "EVENT_TYPE_CURRENT_CALLS",
            "EVENT_TYPE_VOLUME_CHANGED",
            "EVENT_TYPE_CMD_RESULT",
            "EVENT_TYPE_SUBSCRIBER_INFO",
            "EVENT_TYPE_RESP_AND_HOLD",
            "EVENT_TYPE_IN_BAND_RING",
            "EVENT_TYPE_LAST_VOICE_TAG_NUMBER",
            "EVENT_TYPE_RING_INDICATION",
    };

    private class StackEvent {
        int type = EVENT_TYPE_NONE;
        int valueInt = 0;
        int valueInt2 = 0;
        int valueInt3 = 0;
        int valueInt4 = 0;
        String valueString = null;
        BluetoothDevice device = null;

        private StackEvent(int type) {
            this.type = type;
        }

        @Override
        public String toString() {
            // event dump
            StringBuilder result = new StringBuilder();
            result.append("StackEvent {type:" + EVENT_TYPE_NAMES[type]);
            result.append(", value1:" + valueInt);
            result.append(", value2:" + valueInt2);
            result.append(", value3:" + valueInt3);
            result.append(", value4:" + valueInt4);
            result.append(", string: \"" + valueString + "\"");
            result.append(", device:" + device + "}");
            return result.toString();
        }
    }

    private native static void classInitNative();

    private native void initializeNative();

    private native void cleanupNative();

    private native boolean connectNative(byte[] address);

    private native boolean disconnectNative(byte[] address);

    private native boolean connectAudioNative(byte[] address);

    private native boolean disconnectAudioNative(byte[] address);

    private native boolean startVoiceRecognitionNative(byte[] address);

    private native boolean stopVoiceRecognitionNative(byte[] address);

    private native boolean setVolumeNative(byte[] address, int volumeType, int volume);

    private native boolean dialNative(byte[] address, String number);

    private native boolean dialMemoryNative(byte[] address, int location);

    private native boolean handleCallActionNative(byte[] address, int action, int index);

    private native boolean queryCurrentCallsNative(byte[] address);

    private native boolean queryCurrentOperatorNameNative(byte[] address);

    private native boolean retrieveSubscriberInfoNative(byte[] address);

    private native boolean sendDtmfNative(byte[] address, byte code);

    private native boolean requestLastVoiceTagNumberNative(byte[] address);

    private native boolean sendATCmdNative(byte[] address, int atCmd, int val1,
            int val2, String arg);

    public List<BluetoothHeadsetClientCall> getCurrentCalls() {
        return new ArrayList<BluetoothHeadsetClientCall>(mCalls.values());
    }

    public Bundle getCurrentAgEvents() {
        Bundle b = new Bundle();
        b.putInt(BluetoothHeadsetClient.EXTRA_NETWORK_STATUS, mIndicatorNetworkState);
        b.putInt(BluetoothHeadsetClient.EXTRA_NETWORK_SIGNAL_STRENGTH, mIndicatorNetworkSignal);
        b.putInt(BluetoothHeadsetClient.EXTRA_NETWORK_ROAMING, mIndicatorNetworkType);
        b.putInt(BluetoothHeadsetClient.EXTRA_BATTERY_LEVEL, mIndicatorBatteryLevel);
        b.putString(BluetoothHeadsetClient.EXTRA_OPERATOR_NAME, mOperatorName);
        b.putInt(BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION, mVoiceRecognitionActive);
        b.putInt(BluetoothHeadsetClient.EXTRA_IN_BAND_RING, mInBandRingtone);
        b.putString(BluetoothHeadsetClient.EXTRA_SUBSCRIBER_INFO, mSubscriberInfo);
        return b;
    }
}
