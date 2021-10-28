/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.
 *
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
 * Bass CSET managet StateMachine. There is one instance per Coordinated "set Id".
 *  - "Idle" and "Locked" are steady states.
 *  - "Locking" is a transient states until the
 *     Locking confirmation comes from upper layers.
 *  - Once lock is acquired, profile dont try to unlock
 *
 *                             (Idle)
 *                           |       ^
 *                   LOCK    |       | UNLOCK
 *                           V       |
 *                      (Locking)<->(Unlocking)
 *                           |       ^
 *                 ON_LOCK   |       | ON_UNLOCK
 *                           V       |
 *                          (Locked)
 *
 *
 */

package com.android.bluetooth.bc;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothSyncHelper;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.IBleBroadcastAudioScanAssistCallback;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.PeriodicAdvertisingCallback;
import android.bluetooth.le.PeriodicAdvertisingManager;
import android.bluetooth.le.PeriodicAdvertisingReport;

///*_CSIP
//CSET
import android.bluetooth.BluetoothDeviceGroup;
import com.android.bluetooth.groupclient.GroupService;
//_CSIP*/

import android.bluetooth.IBluetoothManager;
import android.os.ServiceManager;
import android.os.IBinder;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import android.content.Intent;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import java.util.UUID;
import java.util.Collection;
import android.os.UserHandle;

import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.lang.String;
import java.lang.StringBuffer;
import java.lang.Integer;

import java.nio.ByteBuffer;
import java.lang.Byte;
import java.util.stream.IntStream;
import android.os.SystemProperties;
import android.os.ParcelUuid;

final class BassCsetManager extends StateMachine {
    private static final String TAG = "BassCsetManager";

    //Considered as Coordinated ops
    static final int BASS_GRP_START_SCAN_OFFLOAD = 6;
    static final int BASS_GRP_STOP_SCAN_OFFLOAD = 7;
    static final int BASS_GRP_ADD_BCAST_SOURCE = 9;
    static final int BASS_GRP_UPDATE_BCAST_SOURCE = 10;
    static final int BASS_GRP_SET_BCAST_CODE = 11;
    static final int BASS_GRP_REMOVE_BCAST_SOURCE = 12;

    static final int LOCK = 17;
    static final int UNLOCK = 18;
    static final int LOCK_STATE_CHANGED = 3;
    static final int LOCK_TIMEOUT = 4;
    static final int ON_CSIP_CONNECTED = 5;

    //10 secs time out for all gatt writes
    static final int LOCK_TIMEOUT_MS = 10000;


    @VisibleForTesting
    private static final int CONNECT_TIMEOUT = 201;

    private final Idle mIdle;
    private final Locking mLocking;
    private final Locked mLocked;
    private final LockedProcessing mLockedProcessing;
    private final Unlocking mUnlocking;

    private BCService mBCService;
    private final BluetoothDevice mDevice;
    private final int mSetId;
    private List<BluetoothDevice> mMemberDevices = null;

    ///*_CSIP
    //CSIP Locking Interfaces
    private GroupService mSetCoordinator = GroupService.getGroupService();
    //_CSIP*/

    BassCsetManager(int setId, BluetoothDevice masterDevice, BCService svc,
            Looper looper) {
        super(TAG, looper);
        mSetId = setId;
        mBCService = svc;

        mIdle = new Idle();
        mLocked = new Locked();
        mLockedProcessing = new LockedProcessing();
        mLocking = new Locking();
        mUnlocking = new Unlocking();

        addState(mIdle);
        addState(mLocking);
        addState(mLocked);
        addState(mLockedProcessing);
        addState(mUnlocking);

        setInitialState(mIdle);
        mDevice = masterDevice;
        mMemberDevices = new ArrayList<BluetoothDevice>();

    }

    static BassCsetManager make(int setId, BluetoothDevice masterDevice, BCService svc,
            Looper looper) {
        Log.d(TAG, "make for setId, setId " + setId + ": masterDevice" + masterDevice);
        BassCsetManager BassclientSm = new BassCsetManager(setId, masterDevice, svc,
                looper);
        BassclientSm.start();
        return BassclientSm;
    }

    public void doQuit() {
        log("doQuit for device " + mDevice);
        quitNow();
    }

    public void cleanup() {
        log("cleanup for device " + mDevice);
    }

    @VisibleForTesting
    class Idle extends State {
        @Override
        public void enter() {
            log( "Enter Idle(" + mSetId + "): " + messageWhatToString(
                    getCurrentMessage().what));
            mMemberDevices = null;

        }

        @Override
        public void exit() {
            log("Exit Idle(" + mSetId + "): " + messageWhatToString(
                    getCurrentMessage().what));
        }

        @Override
        public boolean processMessage(Message message) {
            log("Idle process message(" + mSetId + "): " + messageWhatToString(
                    message.what));

            switch (message.what) {
                case BASS_GRP_START_SCAN_OFFLOAD:
                case BASS_GRP_STOP_SCAN_OFFLOAD:
                case BASS_GRP_ADD_BCAST_SOURCE:
                case BASS_GRP_UPDATE_BCAST_SOURCE:
                case BASS_GRP_SET_BCAST_CODE:
                case BASS_GRP_REMOVE_BCAST_SOURCE:
                    //defer the meesage and move to Locked
                    deferMessage(message);
                    //Intentional miss of break
                case LOCK:
                    //treat Connect & Lock as same request
                    log("Locking to " + mSetId);
                    //get CSIP connection status for BluetoothDevice
                    //if CSIP disconnected: start Connect Procedure (mostly hpns only at first time)
                    //if CSIP connected: start Lock Procedure
                    ///*_CSIP
                    mSetCoordinator.setLockValue(mBCService.mCsipAppId, mSetId, null, BluetoothDeviceGroup.ACCESS_GRANTED);
                    //_CSIP*/
                    transitionTo(mLocking);

                    //transitionTo(mLocked);
                    break;
                case UNLOCK:
                    Log.w(TAG, "Idle: UNLOCK ignored: " + mSetId);
                    break;
                case LOCK_STATE_CHANGED:
                    //This most likely not happen
                    ///*_CSIP
                    int value = (int)message.arg1;
                    List<BluetoothDevice> devices = (List<BluetoothDevice>)message.obj;
                    Log.w(TAG, "Lock state changed:" + value);
                    if (value == BluetoothDeviceGroup.ACCESS_GRANTED) {
                        transitionTo(mLocked);
                    } else {
                        Log.w(TAG, "Idle: Lock failed to " + mSetId);
                    }
                    //_CSIP*/
                    break;
                case ON_CSIP_CONNECTED:
                //starts the Lock procedure
                //Only reason why we Connect is to Lock
                //
                //Dont transition the state
                default:
                    log("Idle: not handled message:" + message.what);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    @VisibleForTesting
     class Locking extends State {
         @Override
         public void enter() {
             log( "Enter Locking(" + mSetId + "): " + messageWhatToString(
                     getCurrentMessage().what));
         }

         @Override
         public void exit() {
             log("Exit Locking(" + mSetId + "): " + messageWhatToString(
                     getCurrentMessage().what));
         }

         @Override
         public boolean processMessage(Message message) {
             log("Locking process message(" + mSetId + "): " + messageWhatToString(
                     message.what));

             switch (message.what) {

                 case BASS_GRP_START_SCAN_OFFLOAD:
                 case BASS_GRP_STOP_SCAN_OFFLOAD:
                 case BASS_GRP_ADD_BCAST_SOURCE:
                 case BASS_GRP_UPDATE_BCAST_SOURCE:
                 case BASS_GRP_SET_BCAST_CODE:
                 case BASS_GRP_REMOVE_BCAST_SOURCE:
                     //defer the meesage and move to Locked
                     deferMessage(message);
                     break;
                 case LOCK:
                     log("Already Locking to " + mSetId);
                     log("Ignore this Lock request " + mSetId);
                     break;
                 case UNLOCK:
                     Log.w(TAG, "Locking: UNLOCK deferred: " + mSetId);
                     deferMessage(message);
                     break;
                 case LOCK_STATE_CHANGED:
                     ///*_CSIP
                     int value = (int)message.arg1;
                     Log.w(TAG, "Lock state changed:" + value);
                     if (value == BluetoothDeviceGroup.ACCESS_GRANTED) {
                          List<BluetoothDevice> devices = (List<BluetoothDevice>)message.obj;
                         mMemberDevices = devices;
                         transitionTo(mLocked);
                     } else {
                         Log.w(TAG, "Locking: Unlocked to " + mSetId);
                         transitionTo(mIdle);
                     }
                     //_CSIP*/
                     break;
                 case ON_CSIP_CONNECTED:
                     //starts the Lock procedure
                     //Only reason why we Connect is to Lock
                     //
                     //Dont transition the state
                     break;
                 default:
                      log("LOCKING: not handled message:" + message.what);
                     return NOT_HANDLED;
             }
             return HANDLED;
         }
     }

    @VisibleForTesting
    class Locked extends State {
        @Override
        public void enter() {
            log( "Enter Locked(" + mSetId + "): "
                    + messageWhatToString(getCurrentMessage().what));

            removeDeferredMessages(LOCK);

        }

        @Override
        public void exit() {
            log("Exit Locked(" + mSetId + "): "
                    + messageWhatToString(getCurrentMessage().what));
        }

        @Override
        public boolean processMessage(Message message) {
            log("Locked process message(" + mSetId + "): "
                    + messageWhatToString(message.what));
            BleBroadcastSourceInfo srcInfo;
            switch (message.what) {
                case LOCK:
                    Log.w(TAG, "Locked: Lock ignored: " + mSetId);
                    break;
                case UNLOCK:
                    log("Unlocking from " + mDevice);
                    //trigger unlock procedure
                    ///*_CSIP
                    mSetCoordinator.setLockValue(mBCService.mCsipAppId, mSetId, null, BluetoothDeviceGroup.ACCESS_RELEASED);
                    transitionTo(mUnlocking);
                    //_CSIP*/

                    //transitionTo(mIdle);
                    break;
                case LOCK_STATE_CHANGED:
                    ///*_CSIP
                    int value = (int)message.arg1;
                    List<BluetoothDevice> devices = (List<BluetoothDevice>)message.obj;
                    Log.w(TAG, "Lock state changed:" + value);
                    if (value == BluetoothDeviceGroup.ACCESS_GRANTED) {
                        transitionTo(mLocked);
                    } else {
                        Log.w(TAG, "Locking: Unlocked to " + mSetId);
                        transitionTo(mIdle);
                    }
                    //_CSIP*/
                    break;
                case BASS_GRP_START_SCAN_OFFLOAD:
                    if (mBCService != null) {
                        log("START_SCAN_OFFLOAD: " + mMemberDevices);
                        mBCService.startScanOffload(mDevice, mMemberDevices);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                case BASS_GRP_STOP_SCAN_OFFLOAD:
                    if (mBCService != null) {
                        log("STOP_SCAN_OFFLOAD: " + mMemberDevices);
                        mBCService.stopScanOffload(mDevice, mMemberDevices);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                case BASS_GRP_ADD_BCAST_SOURCE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    if (mBCService != null) {
                        mBCService.addBroadcastSource(mDevice, mMemberDevices, srcInfo);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                case BASS_GRP_UPDATE_BCAST_SOURCE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    if (mBCService != null) {
                        mBCService.updateBroadcastSource(mDevice, mMemberDevices, srcInfo);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                case BASS_GRP_SET_BCAST_CODE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    if (mBCService != null) {
                        mBCService.setBroadcastCode(mDevice, mMemberDevices, srcInfo);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                case BASS_GRP_REMOVE_BCAST_SOURCE:
                    byte sourceId = (byte)message.arg1;
                    if (mBCService != null) {
                        mBCService.removeBroadcastSource(mDevice, mMemberDevices, sourceId);
                        transitionTo(mLockedProcessing);
                    } else {
                        log("no Bassclient service handle");
                    }
                    break;
                default:
                    log("Locked: not handled message:" + message.what);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    @VisibleForTesting
     class LockedProcessing extends State {
         @Override
         public void enter() {
             log( "Enter LockedProcessing(" + mSetId + "): "
                     + messageWhatToString(getCurrentMessage().what));
         }

         @Override
         public void exit() {
             log("Exit LockedProcessing(" + mSetId + "): "
                     + messageWhatToString(getCurrentMessage().what));
         }

         @Override
         public boolean processMessage(Message message) {
             log("LockedProcessing process message(" + mSetId + "): "
                     + messageWhatToString(message.what));
             BleBroadcastSourceInfo srcInfo;
             switch (message.what) {
                 case UNLOCK:
                     log("LockedProcessing: UNLOCK defer " + mDevice);
                     deferMessage(message);
                     transitionTo(mLocked);
                     break;
                 case LOCK_STATE_CHANGED:
                     int value = (int)message.arg1;
                     Log.w(TAG, "Locking state changed:" + value);
                     //Should never happen
                     break;
                 case LOCK:
                      log("LockedProcessing: LOCK ignore " + mDevice);
                     break;
                 case BASS_GRP_START_SCAN_OFFLOAD:
                 case BASS_GRP_STOP_SCAN_OFFLOAD:
                 case BASS_GRP_ADD_BCAST_SOURCE:
                 case BASS_GRP_UPDATE_BCAST_SOURCE:
                 case BASS_GRP_SET_BCAST_CODE:
                 case BASS_GRP_REMOVE_BCAST_SOURCE:
                     //defer the meesage and move to Locked
                     if (hasDeferredMessages(UNLOCK)) {
                         //If Unlock is in pending list, remove it
                         //Override the UNLOCK with this new operation
                         log("removing the unlock message, as there is another req");
                         removeDeferredMessages(UNLOCK);
                     }
                     deferMessage(message);
                     break;
                 default:
                     log("LockedProcessing: not handled message:" + message.what);
                     return NOT_HANDLED;
             }
             return HANDLED;
         }
     }


    @VisibleForTesting
    class Unlocking extends State {
        @Override
        public void enter() {
            log( "Enter Unlocking(" + mSetId + "): "
                    + messageWhatToString(getCurrentMessage().what));

            //removeDeferredMessages(LOCK);

        }

        @Override
        public void exit() {
            log("Exit Unlocking(" + mSetId + "): "
                    + messageWhatToString(getCurrentMessage().what));
        }

        @Override
        public boolean processMessage(Message message) {
            log("Locked process message(" + mSetId + "): "
                    + messageWhatToString(message.what));
            BleBroadcastSourceInfo srcInfo;
            switch (message.what) {
                case UNLOCK:
                    log("Unlocking: UNLOCK ignored from " + mDevice);
                    break;
                case LOCK_STATE_CHANGED:
                    ///*_CSIP
                    int value = (int)message.arg1;
                    Log.w(TAG, "Locking state changed:" + value);
                    if (value == BluetoothDeviceGroup.ACCESS_RELEASED) {
                         mMemberDevices = null;
                         transitionTo(mIdle);
                     } else {
                         Log.w(TAG, "UnLocking: failed to " + mSetId);
                         //keep that back in Locked?
                         transitionTo(mLocked);
                         //
                     }
                    //_CSIP*/
                    break;
                case LOCK:
                case BASS_GRP_START_SCAN_OFFLOAD:
                case BASS_GRP_STOP_SCAN_OFFLOAD:
                case BASS_GRP_ADD_BCAST_SOURCE:
                case BASS_GRP_UPDATE_BCAST_SOURCE:
                case BASS_GRP_SET_BCAST_CODE:
                case BASS_GRP_REMOVE_BCAST_SOURCE:
                    //defer the meesage and move to Locked
                    deferMessage(message);
                    break;
                default:
                    log("Locked: not handled message:" + message.what);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }


    private static String messageWhatToString(int what) {
        switch (what) {
            case LOCK:
                return "LOCK";
            case UNLOCK:
                return "UNLOCK";
            case LOCK_STATE_CHANGED:
                return "LOCK_STATE_CHANGED";
            case BASS_GRP_START_SCAN_OFFLOAD:
                return "BASS_GRP_START_SCAN_OFFLOAD";
            case BASS_GRP_STOP_SCAN_OFFLOAD:
                return "BASS_GRP_STOP_SCAN_OFFLOAD";
            case BASS_GRP_ADD_BCAST_SOURCE:
                return "BASS_GRP_ADD_BCAST_SOURCE";
            case BASS_GRP_UPDATE_BCAST_SOURCE:
                return "BASS_GRP_UPDATE_BCAST_SOURCE";
            case BASS_GRP_SET_BCAST_CODE:
                return "BASS_GRP_SET_BCAST_CODE";
            case BASS_GRP_REMOVE_BCAST_SOURCE:
                return "BASS_GRP_REMOVE_BCAST_SOURCE";
            default:
                break;
        }
        return Integer.toString(what);
    }

    @Override
    protected void log( String msg) {
        if (BassClientStateMachine.BASS_DBG) {
            super.log(msg);
        }
    }
}
