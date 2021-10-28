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

import java.util.Objects;
import java.util.Arrays;

/**
 * A blob of data representing an overall call state on the phone
 */
class CallControlState {

     int mIndex;
    /**
     * Number of active calls
     */
    int mNumActive;
    /**
     * Number of held calls
     */
    int mNumHeld;
    /**
     * Current call setup state
     */
    int mState;
    /**
     * Currently active call's phone number
     */
    String mNumber;
    /**
     * Phone number type
     */
    int mType;

    /**
     *  flags to define direction, information witheld by network or server.
     */
     int mFlags;

    /**
     * Caller display name
     */
    String mName;

    int mDirection;

    CallControlState(int numActive, int numHeld, int callState, String number, int type,
            String name) {
        mNumActive = numActive;
        mNumHeld = numHeld;
        mState = callState;
        mNumber = number;
        mType = type;
        mName = name;
    }
    CallControlState(int index, int callState, int flags) {
         mIndex  = index;
         mState = callState;
         mFlags = flags;
    }
    CallControlState(int index, int direction, int callState, String number) {
         mIndex  = index;
         mDirection = direction;
         mState = callState;
         mNumber = number;
    }

}
