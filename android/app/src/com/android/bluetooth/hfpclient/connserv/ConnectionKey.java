/*
 * Copyright (C) 2016 The Android Open Source Project
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
package com.android.bluetooth.hfpclient.connserv;

import android.bluetooth.BluetoothHeadsetClientCall;
import android.net.Uri;
import android.telecom.PhoneAccount;

/* Matching a call to internal state requires understanding of the ph number and the state of the
 * remote itself. The best way to associate a call with remote is to use the Call IDs that are
 * passed by the HFP AG role. But consider the scenario when even before a call is notified to the
 * remote and it tries to get back to us -- we execute a full cycle of Call -> Hangup. In such case
 * we have no recourse but to use phone number as the key. This class implements the matching logic
 * for phone numbers & IDs. It identifies uniquely a {@link HfpClientConnection}.
 */
class ConnectionKey {
    /* Initialize with invalid values */
    public static final int INVALID_ID = -1;

    private final int mId;
    private final Uri mPhoneNumber;

    ConnectionKey(int id, Uri phoneNumber) {
        if (id == INVALID_ID && phoneNumber == null) {
            throw new IllegalStateException("invalid id and phone number");
        }
        mId = id;
        mPhoneNumber = phoneNumber;
    }

    public static ConnectionKey getKey(BluetoothHeadsetClientCall call) {
        if (call == null) {
            throw new IllegalStateException("call may not be null");
        }

        // IDs in the call start with *1*.
        int id = call.getId() > 0 ? call.getId() : INVALID_ID;
        Uri phoneNumberUri = Uri.fromParts(PhoneAccount.SCHEME_TEL, call.getNumber(), null);
        return new ConnectionKey(id, phoneNumberUri);
    }

    public int getId() {
        return mId;
    }

    public Uri getPhoneNumber() {
        return mPhoneNumber;
    }

    @Override
    public String toString() {
        return "Key " + getId() + " Phone number " + getPhoneNumber();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ConnectionKey)) {
            return false;
        }

        ConnectionKey candidate = (ConnectionKey) o;

        /* Match based on IDs */
        if (getId() != INVALID_ID && candidate.getId() != INVALID_ID) {
            return (getId() == candidate.getId());
        }

        /* Otherwise match has to be based on phone numbers */
        return (getPhoneNumber() != null && candidate.getPhoneNumber() != null &&
                getPhoneNumber().equals(candidate.getPhoneNumber()));
    }

    @Override
    public int hashCode() {
        // Since we may do partial match based on either ID or phone numbers hence put all the items
        // in same bucket.
        return 0;
    }
}
