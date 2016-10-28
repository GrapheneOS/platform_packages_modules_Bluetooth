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

import android.accounts.Account;
import android.accounts.AccountManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.BluetoothUuid;
import android.content.Context;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.Process;
import android.provider.CallLog;
import android.util.Log;

import com.android.bluetooth.R;

import java.io.IOException;

import javax.obex.ClientSession;
import javax.obex.HeaderSet;
import javax.obex.ResponseCodes;

/* Bluetooth/pbapclient/PbapClientConnectionHandler is responsible
 * for connecting, disconnecting and downloading contacts from the
 * PBAP PSE when commanded. It receives all direction from the
 * controlling state machine.
 */
class PbapClientConnectionHandler extends Handler {
    static final String TAG = "PBAP PCE handler";
    static final boolean DBG = true;
    static final int MSG_CONNECT = 1;
    static final int MSG_DISCONNECT = 2;
    static final int MSG_DOWNLOAD = 3;

    // The following constants are pulled from the Bluetooth Phone Book Access Profile specification
    // 1.1
    private static final byte[] PBAP_TARGET = new byte[] {
            0x79, 0x61, 0x35, (byte) 0xf0, (byte) 0xf0, (byte) 0xc5, 0x11, (byte) 0xd8, 0x09, 0x66,
            0x08, 0x00, 0x20, 0x0c, (byte) 0x9a, 0x66
    };

    public static final String PB_PATH = "telecom/pb.vcf";
    public static final String MCH_PATH = "telecom/mch.vcf";
    public static final String ICH_PATH = "telecom/ich.vcf";
    public static final String OCH_PATH = "telecom/och.vcf";
    public static final byte VCARD_TYPE_21 = 0;
    public static final byte VCARD_TYPE_30 = 1;

    private Account mAccount;
    private AccountManager mAccountManager;
    private BluetoothSocket mSocket;
    private final BluetoothAdapter mAdapter;
    private final BluetoothDevice mDevice;
    private ClientSession mObexSession;
    private Context mContext;
    private BluetoothPbapObexAuthenticator mAuth = null;
    private final PbapClientStateMachine mPbapClientStateMachine;
    private boolean mAccountCreated;

    PbapClientConnectionHandler(Looper looper, Context context, PbapClientStateMachine stateMachine,
            BluetoothDevice device) {
        super(looper);
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mDevice = device;
        mContext = context;
        mPbapClientStateMachine = stateMachine;
        mAuth = new BluetoothPbapObexAuthenticator(this);
        mAccountManager = AccountManager.get(mPbapClientStateMachine.getContext());
        mAccount = new Account(mDevice.getAddress(), mContext.getString(
                R.string.pbap_account_type));
    }

    @Override
    public void handleMessage(Message msg) {
        if (DBG) Log.d(TAG,"Handling Message = " +msg.what);
        switch(msg.what) {
            case MSG_CONNECT:
                boolean connectionSuccessful = false;

                try {
                    /* To establish a connection first open a socket, establish a OBEX Transport
                     * abstraction, establish a Bluetooth Authenticator, and finally attempt to
                     * connect via an OBEX session */
                    mSocket = mDevice.createRfcommSocketToServiceRecord(
                            BluetoothUuid.PBAP_PSE.getUuid());
                    mSocket.connect();

                    BluetoothPbapObexTransport transport;
                    transport = new BluetoothPbapObexTransport(mSocket);

                    mObexSession  = new ClientSession(transport);
                    mObexSession.setAuthenticator(mAuth);

                    HeaderSet connectionRequest = new HeaderSet();
                    connectionRequest.setHeader(HeaderSet.TARGET, PBAP_TARGET);
                    HeaderSet connectionResponse = mObexSession.connect(connectionRequest);

                    connectionSuccessful = (connectionResponse.getResponseCode() ==
                            ResponseCodes.OBEX_HTTP_OK);
                    if (DBG) Log.d(TAG,"Success = " + Boolean.toString(connectionSuccessful));
                } catch (IOException e) {
                    Log.w(TAG,"CONNECT Failure " + e.toString());
                    closeSocket();
                }

                if (connectionSuccessful) {
                    mPbapClientStateMachine.obtainMessage(
                            PbapClientStateMachine.MSG_CONNECTION_COMPLETE).sendToTarget();
                } else {
                    mPbapClientStateMachine.obtainMessage(
                            PbapClientStateMachine.MSG_CONNECTION_FAILED).sendToTarget();
                }
                break;

            case MSG_DISCONNECT:
                try {
                    if (mObexSession != null) {
                        mObexSession.disconnect(null);
                    }
                    closeSocket();
                } catch (IOException e) {
                    Log.w(TAG,"DISCONNECT Failure " + e.toString());
                }
                removeAccount(mAccount);
                mContext.getContentResolver()
                        .delete(CallLog.Calls.CONTENT_URI, null, null);
                mPbapClientStateMachine.obtainMessage(
                        PbapClientStateMachine.MSG_CONNECTION_CLOSED).sendToTarget();
                break;

            case MSG_DOWNLOAD:
                try {
                    mAccountCreated = addAccount(mAccount);
                    if (mAccountCreated == false) {
                        Log.e(TAG,"Account creation failed.");
                        return;
                    }
                    BluetoothPbapRequestPullPhoneBook request =
                            new BluetoothPbapRequestPullPhoneBook(PB_PATH, mAccount, 0,
                            VCARD_TYPE_21, 0, 0);
                    request.execute(mObexSession);
                    PhonebookPullRequest processor =
                        new PhonebookPullRequest(mPbapClientStateMachine.getContext(), mAccount);
                    processor.setResults(request.getList());
                    processor.onPullComplete();

                    downloadCallLog(MCH_PATH);
                    downloadCallLog(ICH_PATH);
                    downloadCallLog(OCH_PATH);
                } catch (IOException e) {
                    Log.w(TAG,"DOWNLOAD_CONTACTS Failure" + e.toString());
                }
                break;

            default:
                Log.w(TAG,"Received Unexpected Message");
        }
        return;
    }

    public void abort() {
        // Perform forced cleanup, it is ok if the handler throws an exception this will free the
        // handler to complete what it is doing and finish with cleanup.
        closeSocket();
        this.getLooper().getThread().interrupt();
    }

    private void closeSocket() {
        try {
            if (mSocket != null) {
                mSocket.close();
                mSocket = null;
            }
        } catch (IOException e) {
            Log.e(TAG, "Error when closing socket", e);
            mSocket = null;
        }
    }
    void downloadCallLog(String path) {
        try {
            BluetoothPbapRequestPullPhoneBook request =
                    new BluetoothPbapRequestPullPhoneBook(path,mAccount,0,VCARD_TYPE_21,0,0);
            request.execute(mObexSession);
            CallLogPullRequest processor =
                    new CallLogPullRequest(mPbapClientStateMachine.getContext(),path);
            processor.setResults(request.getList());
            processor.onPullComplete();
        } catch (IOException e) {
            Log.w(TAG,"Download call log failure");
        }
    }

    private boolean addAccount(Account account) {
        if (mAccountManager.addAccountExplicitly(account, null, null)) {
            if (DBG) {
                Log.d(TAG, "Added account " + mAccount);
            }
            return true;
        }
        return false;
    }

    private void removeAccount(Account acc) {
        if (mAccountManager.removeAccountExplicitly(acc)) {
            if (DBG) {
                Log.d(TAG, "Removed account " + acc);
            }
        } else {
            Log.e(TAG, "Failed to remove account " + mAccount);
        }
    }
}
