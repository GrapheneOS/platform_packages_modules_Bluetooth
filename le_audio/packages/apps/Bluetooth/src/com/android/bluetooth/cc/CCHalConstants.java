/*
 *Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2012 The Android Open Source Project
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

package com.android.bluetooth.cc;

/*
 * @hide
 */
public final class CCHalConstants {
    static final int NETWORK_STATE_NOT_AVAILABLE = 0;
    static final int NETWORK_STATE_AVAILABLE = 1;

    static final int SERVICE_TYPE_HOME = 0;
    static final int SERVICE_TYPE_ROAMING = 1;

    static final int CALL_STATE_ACTIVE = 0;
    static final int CALL_STATE_HELD = 1;
    static final int CALL_STATE_DIALING = 2;
    static final int CALL_STATE_ALERTING = 3;
    static final int CALL_STATE_INCOMING = 4;
    static final int CALL_STATE_WAITING = 5;
    static final int CALL_STATE_IDLE = 6;
    static final int CALL_STATE_DISCONNECTED = 7;

    //Call State as expected by Stack/CC
    static final int CCS_STATE_INCOMING = 0x00;
    static final int CCS_STATE_DIALING = 0x01;
    static final int CCS_STATE_ALERTING = 0x02;
    static final int CCS_STATE_ACTIVE = 0x03;
    static final int CCS_STATE_LOCAL_HELD= 0x04;
    static final int CCS_STATE_REMOTELY_HELD= 0x05;
    static final int CCS_STATE_LOCAL_REMOTE_HELD= 0x06;
    static final int CCS_STATE_DISCONNECTED = 0x07;

    static final int BTCC_OP_ACCEPT = 0;
    static final int BTCC_OP_TERMINATE = 1;
    static final int BTCC_OP_LOCAL_HLD = 2;
    static final int BTCC_OP_LOCAL_RETRIEVE = 3;
    static final int BTCC_OP_ORIGINATE = 4;
    static final int BTCC_OP_JOIN = 5;

    static final int BTCC_OP_SUCCESS = 0x00;
    static final int BTCC_OP_NOT_POSSIBLE = 0x02;

    //default call index for failures
    static final int BTCC_DEF_INDEX_FOR_FAILURES = 0;

    static int getCCsCallState(int telephonyCallState) {
        int ret = 0xFF;
        switch(telephonyCallState) {
            case CALL_STATE_ACTIVE: ret = CCS_STATE_ACTIVE; break;
            case CALL_STATE_HELD: ret = CCS_STATE_LOCAL_HELD; break;
            case CALL_STATE_DIALING: ret = CCS_STATE_DIALING; break;
            case CALL_STATE_ALERTING: ret = CCS_STATE_ALERTING; break;
            case CALL_STATE_INCOMING: ret = CCS_STATE_INCOMING; break;
            case CALL_STATE_DISCONNECTED: ret = CCS_STATE_DISCONNECTED; break;
            //this means second Incoming call is waiting
            case CALL_STATE_WAITING: ret = CCS_STATE_INCOMING; break;
            default: break;
        }
        return ret;
    }

    public static String operationToString(int what) {
        switch (what) {
            case BTCC_OP_ACCEPT :
                return "BTCC_OP_ACCEPT";
            case BTCC_OP_TERMINATE :
                return "BTCC_OP_TERMINATE";
            case BTCC_OP_LOCAL_HLD :
                return "BTCC_OP_LOCAL_HLD";
            case BTCC_OP_LOCAL_RETRIEVE :
                return "BTCC_OP_LOCAL_RETRIEVE";
            case BTCC_OP_ORIGINATE :
                return "BTCC_OP_ORIGINATE";
            case BTCC_OP_JOIN :
                return "BTCC_OP_JOIN";
            default:
                break;
        }
        return Integer.toString(what);
    }
}
