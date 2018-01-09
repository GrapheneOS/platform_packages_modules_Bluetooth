/*
 * Copyright 2017 The Android Open Source Project
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

package com.android.bluetooth.pbap;

import android.annotation.NonNull;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.BluetoothObexTransport;
import com.android.bluetooth.IObexConnectionHandler;
import com.android.bluetooth.ObexRejectServer;
import com.android.bluetooth.R;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.IOException;

import javax.obex.ResponseCodes;
import javax.obex.ServerSession;

/**
 * Bluetooth PBAP StateMachine
 *              (New connection socket)
 *                 WAITING FOR AUTH
 *                        |
 *                        |    (request permission from Settings UI)
 *                        |
 *           (Accept)    / \   (Reject)
 *                      /   \
 *                     v     v
 *          CONNECTED   ----->  FINISHED
 *                (OBEX Server done)
 */
class PbapStateMachine extends StateMachine {
    private static final String TAG = "PbapStateMachine";
    private static final boolean DEBUG = true;
    private static final boolean VERBOSE = true;

    private static final String PBAP_OBEX_NOTIFICATION_CHANNEL = "pbap_obex_notification_channel";
    private static final int NOTIFICATION_ID_AUTH = -1000002;
    // TODO: set a notification channel for each sm

    static final int AUTHORIZED = 1;
    static final int REJECTED = 2;
    static final int DISCONNECT = 3;
    static final int REQUEST_PERMISSION = 4;
    static final int CREATE_NOTIFICATION = 5;
    static final int REMOVE_NOTIFICATION = 6;
    static final int AUTH_KEY_INPUT = 7;
    static final int AUTH_CANCELLED = 8;

    BluetoothPbapService mService;
    IObexConnectionHandler mIObexConnectionHandler;

    private final WaitingForAuth mWaitingForAuth = new WaitingForAuth();
    private final Finished mFinished = new Finished();
    private final Connected mConnected = new Connected();
    private BluetoothDevice mRemoteDevice;
    private Handler mServiceHandler;
    private BluetoothSocket mConnSocket;
    private BluetoothPbapObexServer mPbapServer;
    private BluetoothPbapAuthenticator mObexAuth;
    private ServerSession mServerSession;

    private PbapStateMachine(@NonNull BluetoothPbapService service, Looper looper,
            @NonNull BluetoothDevice device, @NonNull BluetoothSocket connSocket,
            IObexConnectionHandler obexConnectionHandler, Handler pbapHandler) {
        super(TAG, looper);
        mService = service;
        mIObexConnectionHandler = obexConnectionHandler;
        mRemoteDevice = device;
        mServiceHandler = pbapHandler;
        mConnSocket = connSocket;

        addState(mFinished);
        addState(mWaitingForAuth);
        addState(mConnected);
        setInitialState(mWaitingForAuth);
    }

    static PbapStateMachine make(BluetoothPbapService service, Looper looper,
            BluetoothDevice device, BluetoothSocket connSocket,
            IObexConnectionHandler obexConnectionHandler, Handler pbapHandler) {
        PbapStateMachine stateMachine = new PbapStateMachine(service, looper, device, connSocket,
                obexConnectionHandler, pbapHandler);
        stateMachine.start();
        return stateMachine;
    }

    BluetoothDevice getRemoteDevice() {
        return mRemoteDevice;
    }

    private abstract class PbapStateBase extends State {
        /**
         * Get a state value from {@link BluetoothProfile} that represents the connection state of
         * this headset state
         *
         * @return a value in {@link BluetoothProfile#STATE_DISCONNECTED},
         * {@link BluetoothProfile#STATE_CONNECTING}, {@link BluetoothProfile#STATE_CONNECTED}, or
         * {@link BluetoothProfile#STATE_DISCONNECTING}
         */
        abstract int getConnectionStateInt();
    }

    class WaitingForAuth extends PbapStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_CONNECTING;
        }

        @Override
        public void enter() {
            mService.checkOrGetPhonebookPermission(PbapStateMachine.this);
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case AUTHORIZED:
                    transitionTo(mConnected);
                    break;
                case REJECTED:
                    rejectConnection();
                    transitionTo(mFinished);
                    break;
                case DISCONNECT:
                    mServiceHandler.removeMessages(BluetoothPbapService.USER_TIMEOUT);
                    Message msg = mServiceHandler.obtainMessage(
                            BluetoothPbapService.USER_TIMEOUT);
                    msg.obj = PbapStateMachine.this;
                    msg.sendToTarget();
                    transitionTo(mFinished);
                    break;
            }
            return HANDLED;
        }

        private void rejectConnection() {
            mPbapServer = new BluetoothPbapObexServer(mServiceHandler, mService,
                    PbapStateMachine.this);
            BluetoothObexTransport transport = new BluetoothObexTransport(mConnSocket);
            ObexRejectServer server = new ObexRejectServer(ResponseCodes.OBEX_HTTP_UNAVAILABLE,
                    mConnSocket);
            try {
                mServerSession = new ServerSession(transport, server, null);
            } catch (IOException ex) {
                Log.e(TAG, "Caught exception starting OBEX reject server session"
                        + ex.toString());
            }
        }
    }

    class Finished extends PbapStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public void enter() {
            // Close OBEX server session
            if (mServerSession != null) {
                mServerSession.close();
                mServerSession = null;
            }

            // Close connection socket
            try {
                mConnSocket.close();
                mConnSocket = null;
            } catch (IOException e) {
                Log.e(TAG, "Close Connection Socket error: " + e.toString());
            }

            mServiceHandler.obtainMessage(BluetoothPbapService.MSG_STATE_MACHINE_DONE)
                    .sendToTarget();
        }

    }

    class Connected extends PbapStateBase {
        @Override
        int getConnectionStateInt() {
            return BluetoothProfile.STATE_CONNECTED;
        }

        @Override
        public void enter() {
            try {
                startObexServerSession();
            } catch (IOException ex) {
                Log.e(TAG, "Caught exception starting OBEX server session" + ex.toString());
            }
        }

        @Override
        public void exit() {
        }

        @Override
        public boolean processMessage(Message message) {
            switch (message.what) {
                case DISCONNECT:
                    stopObexServerSession();
                    break;
                case CREATE_NOTIFICATION:
                    createPbapNotification();
                    break;
                case REMOVE_NOTIFICATION:
                    Intent i = new Intent(BluetoothPbapService.USER_CONFIRM_TIMEOUT_ACTION);
                    mService.sendBroadcast(i);
                    notifyAuthCancelled();
                    removePbapNotification(NOTIFICATION_ID_AUTH);
                    break;
                case AUTH_KEY_INPUT:
                    String key = (String) message.obj;
                    notifyAuthKeyInput(key);
                    break;
                case AUTH_CANCELLED:
                    notifyAuthCancelled();
                    break;
            }
            return HANDLED;
        }

        private void startObexServerSession() throws IOException {
            if (VERBOSE) {
                Log.v(TAG, "Pbap Service startObexServerSession");
            }

            // acquire the wakeLock before start Obex transaction thread
            mServiceHandler.sendMessage(
                    mServiceHandler.obtainMessage(BluetoothPbapService.MSG_ACQUIRE_WAKE_LOCK));

            mPbapServer = new BluetoothPbapObexServer(mServiceHandler, mService,
                    PbapStateMachine.this);
            synchronized (this) {
                mObexAuth = new BluetoothPbapAuthenticator(PbapStateMachine.this);
                mObexAuth.setChallenged(false);
                mObexAuth.setCancelled(false);
            }
            BluetoothObexTransport transport = new BluetoothObexTransport(mConnSocket);
            mServerSession = new ServerSession(transport, mPbapServer, mObexAuth);
            // It's ok to just use one wake lock
            // Message MSG_ACQUIRE_WAKE_LOCK is always surrounded by RELEASE. safe.
        }

        private void stopObexServerSession() {
            if (VERBOSE) {
                Log.v(TAG, "Pbap Service stopObexServerSession");
            }
            transitionTo(mFinished);
        }

        private void createPbapNotification() {
            NotificationManager nm =
                    (NotificationManager) mService.getSystemService(Context.NOTIFICATION_SERVICE);
            NotificationChannel notificationChannel = new NotificationChannel(
                    PBAP_OBEX_NOTIFICATION_CHANNEL,
                    mService.getString(R.string.pbap_notification_group),
                    NotificationManager.IMPORTANCE_HIGH);
            nm.createNotificationChannel(notificationChannel);

            // Create an intent triggered by clicking on the status icon.
            Intent clickIntent = new Intent();
            clickIntent.setClass(mService, BluetoothPbapActivity.class);
            clickIntent.putExtra(BluetoothPbapService.EXTRA_DEVICE, mRemoteDevice);
            clickIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            clickIntent.setAction(BluetoothPbapService.AUTH_CHALL_ACTION);

            // Create an intent triggered by clicking on the
            // "Clear All Notifications" button
            Intent deleteIntent = new Intent();
            deleteIntent.setClass(mService, BluetoothPbapService.class);
            deleteIntent.setAction(BluetoothPbapService.AUTH_CANCELLED_ACTION);

            String name = mRemoteDevice.getName();

            Notification notification =
                    new Notification.Builder(mService, PBAP_OBEX_NOTIFICATION_CHANNEL)
                            .setWhen(System.currentTimeMillis())
                            .setContentTitle(mService.getString(R.string.auth_notif_title))
                            .setContentText(mService.getString(R.string.auth_notif_message, name))
                            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                            .setTicker(mService.getString(R.string.auth_notif_ticker))
                            .setColor(mService.getResources().getColor(
                                    com.android.internal.R.color.system_notification_accent_color,
                                    mService.getTheme()))
                            .setFlag(Notification.FLAG_AUTO_CANCEL, true)
                            .setFlag(Notification.FLAG_ONLY_ALERT_ONCE, true)
                            .setContentIntent(PendingIntent.getActivity(mService, 0, clickIntent,
                                    0))
                            .setDeleteIntent(PendingIntent.getBroadcast(mService, 0, deleteIntent,
                                    0))
                            .setLocalOnly(true)
                            .build();
            nm.notify(NOTIFICATION_ID_AUTH, notification);
        }

        private void removePbapNotification(int id) {
            NotificationManager nm =
                    (NotificationManager) mService.getSystemService(Context.NOTIFICATION_SERVICE);
            nm.cancel(id);
        }

        private void notifyAuthCancelled() {
            synchronized (this) {
                mObexAuth.setCancelled(true);
                mObexAuth.notify();
            }
        }

        private void notifyAuthKeyInput(final String key) {
            synchronized (this) {
                if (key != null) {
                    mObexAuth.setSessionKey(key);
                }
                mObexAuth.setChallenged(true);
                mObexAuth.notify();
            }
        }
    }

    synchronized int getConnectionState() {
        return ((PbapStateBase) getCurrentState()).getConnectionStateInt();
    }
}
