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
package com.android.bluetooth.pbapclient;

import com.android.vcard.VCardEntry;

import android.accounts.Account;
import android.content.ContentProviderOperation;
import android.content.Context;
import android.content.OperationApplicationException;
import android.provider.ContactsContract;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;
import android.provider.ContactsContract.Data;
import android.provider.ContactsContract.RawContacts;
import android.provider.ContactsContract.RawContactsEntity;
import android.provider.ContactsContract.Contacts.Entity;
import android.provider.ContactsContract.CommonDataKinds.Phone;
import android.provider.ContactsContract.CommonDataKinds.StructuredName;
import android.util.Log;

import com.android.vcard.VCardEntry;

import java.lang.InterruptedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class PhonebookPullRequest extends PullRequest {
    private static final int MAX_OPS = 200;
    private static final boolean DBG = true;
    private static final String TAG = "PbapPhonebookPullRequest";

    private final Account mAccount;
    private final Context mContext;
    public boolean complete = false;

    public PhonebookPullRequest(Context context, Account account) {
        mContext = context;
        mAccount = account;
        path = BluetoothPbapClient.PB_PATH;
    }

    // TODO: Apply operations together if possible.
    private void addContact(VCardEntry e)
        throws RemoteException, OperationApplicationException, InterruptedException {
        ArrayList<ContentProviderOperation> ops =
                e.constructInsertOperations(mContext.getContentResolver(), null);
        mContext.getContentResolver().applyBatch(ContactsContract.AUTHORITY, ops);
        ops.clear();
    }

    @Override
    public void onPullComplete() {
        if (mEntries == null) {
            Log.e(TAG, "onPullComplete entries is null.");
            return;
        }

        if (DBG) {
            Log.d(TAG, "onPullComplete with " + mEntries.size() + " count.");
        }
        try {
            for (VCardEntry e : mEntries) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException();
                }
                addContact(e);
            }
            Log.d(TAG, "Sync complete: add=" + mEntries.size());
        } catch (OperationApplicationException | RemoteException | NumberFormatException e) {
            Log.d(TAG, "Got exception: ", e);
        } catch (InterruptedException e) {
            Log.d(TAG, "Interrupted durring insert.");
        } finally {
            complete = true;
        }
    }
}
