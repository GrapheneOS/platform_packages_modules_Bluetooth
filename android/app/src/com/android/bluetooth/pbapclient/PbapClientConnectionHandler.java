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

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.BluetoothUuid;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.Process;
import android.util.Log;

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

    private static final byte[] PBAP_TARGET = new byte[] {
            0x79, 0x61, 0x35, (byte) 0xf0, (byte) 0xf0, (byte) 0xc5, 0x11, (byte) 0xd8, 0x09, 0x66,
            0x08, 0x00, 0x20, 0x0c, (byte) 0x9a, 0x66
    };

    public static final String PB_PATH = "telecom/pb.vcf";
    public static final String MCH_PATH = "telecom/mch.vcf";
    public static final byte VCARD_TYPE_21 = 0;

    private BluetoothSocket mSocket;
    private final BluetoothAdapter mAdapter;
    private final BluetoothDevice mDevice;
    private ClientSession mObexSession;
    private BluetoothPbapObexAuthenticator mAuth = null;
    private final PbapClientStateMachine mPbapClientStateMachine;

    PbapClientConnectionHandler(Looper looper, PbapClientStateMachine stateMachine,
            BluetoothDevice device) {
        super(looper);
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mDevice = device;
        mPbapClientStateMachine = stateMachine;
        mAuth = new BluetoothPbapObexAuthenticator(this);
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
                } catch (IOException e) {
                    Log.w(TAG,"DISCONNECT Failure " + e.toString());
                }
                mPbapClientStateMachine.obtainMessage(
                        PbapClientStateMachine.MSG_CONNECTION_CLOSED).sendToTarget();
                break;

            case MSG_DOWNLOAD:
                try {
                    BluetoothPbapRequestPullPhoneBook request =
                            new BluetoothPbapRequestPullPhoneBook(PB_PATH, null, 0, VCARD_TYPE_21,
                            0, 0);
                    request.execute(mObexSession);
                    if (DBG) Log.d(TAG,"Download success? " + request.isSuccess());
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
        closeSocket();
    }

    private void closeSocket() {
        try {
            if (mSocket != null) {
                mSocket.close();
                mSocket = null;
            }
        } catch (IOException e) {
            Log.e(TAG, "Error when closing socket", e);
        }
    }
}
