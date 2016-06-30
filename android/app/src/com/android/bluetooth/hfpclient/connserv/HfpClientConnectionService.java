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

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothHeadsetClientCall;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.ConnectionService;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.util.Log;

import com.android.bluetooth.hfpclient.HeadsetClientService;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class HfpClientConnectionService extends ConnectionService {
    private static final String TAG = "HfpClientConnService";
    private static final boolean DBG = true;

    public static final String HFP_SCHEME = "hfpc";

    private BluetoothAdapter mAdapter;
    // Currently active device.
    private BluetoothDevice mDevice;
    // Phone account associated with the above device.
    private PhoneAccount mDevicePhoneAccount;
    // BluetoothHeadset proxy.
    private BluetoothHeadsetClient mHeadsetProfile;
    private TelecomManager mTelecomManager;

    private final Map<UUID, HfpClientConnection> mConnections = new HashMap<>();
    private HfpClientConference mConference;

    private boolean mPendingAcceptCall;

    private BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (DBG) {
                Log.d(TAG, "onReceive " + intent);
            }
            String action = intent != null ? intent.getAction() : null;

            if (BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED.equals(action)) {
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                int newState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);

                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    if (DBG) {
                        Log.d(TAG, "Established connection with " + device);
                    }
                    synchronized (HfpClientConnectionService.this) {
                        if (device.equals(mDevice)) {
                            // We are already connected and this message can be safeuly ignored.
                            Log.w(TAG, "Got connected for previously connected device, ignoring.");
                        } else {
                            // Since we are connected to a new device close down the previous
                            // account and register the new one.
                            if (mDevicePhoneAccount != null) {
                                mTelecomManager.unregisterPhoneAccount(
                                    mDevicePhoneAccount.getAccountHandle());
                            }
                            // Reset the device and the phone account associated.
                            mDevice = device;
                            mDevicePhoneAccount =
                                getAccount(HfpClientConnectionService.this, device);
                            mTelecomManager.registerPhoneAccount(mDevicePhoneAccount);
                            mTelecomManager.enablePhoneAccount(
                                mDevicePhoneAccount.getAccountHandle(), true);
                            mTelecomManager.setUserSelectedOutgoingPhoneAccount(
                                mDevicePhoneAccount.getAccountHandle());
                        }
                    }

                    // Add any existing calls to the telecom stack.
                    if (mHeadsetProfile != null) {
                        List<BluetoothHeadsetClientCall> calls =
                                mHeadsetProfile.getCurrentCalls(mDevice);
                        if (DBG) {
                            Log.d(TAG, "Got calls " + calls);
                        }
                        if (calls == null) {
                            // We can get null as a return if we are not connected. Hence there may
                            // be a race in getting the broadcast and HFP Client getting
                            // disconnected before broadcast gets delivered.
                            Log.w(TAG, "Got connected but calls were null, ignoring the broadcast");
                            return;
                        }
                        for (BluetoothHeadsetClientCall call : calls) {
                            handleCall(call);
                        }
                    } else {
                        Log.e(TAG, "headset profile is null, ignoring broadcast.");
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    if (DBG) {
                        Log.d(TAG, "Disconnecting from " + device);
                    }
                    // Disconnect any inflight calls from the connection service.
                    synchronized (HfpClientConnectionService.this) {
                        if (device.equals(mDevice)) {
                            if (DBG) {
                                Log.d(TAG, "Resetting state for " + device);
                            }
                            mDevice = null;
                            disconnectAll();
                            mTelecomManager.unregisterPhoneAccount(
                                mDevicePhoneAccount.getAccountHandle());
                            mDevicePhoneAccount = null;
                        }
                    }
                }
            } else if (BluetoothHeadsetClient.ACTION_CALL_CHANGED.equals(action)) {
                // If we are not connected, then when we actually do get connected --
                // the calls should
                // be added (see ACTION_CONNECTION_STATE_CHANGED intent above).
                handleCall((BluetoothHeadsetClientCall)
                        intent.getParcelableExtra(BluetoothHeadsetClient.EXTRA_CALL));
                if (DBG) {
                    Log.d(TAG, mConnections.size() + " remaining");
                }
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        if (DBG) {
            Log.d(TAG, "onCreate");
        }
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mTelecomManager = (TelecomManager) getSystemService(Context.TELECOM_SERVICE);
        mAdapter.getProfileProxy(this, mServiceListener, BluetoothProfile.HEADSET_CLIENT);
    }

    @Override
    public void onDestroy() {
        if (DBG) {
            Log.d(TAG, "onDestroy called");
        }
        // Close the profile.
        if (mHeadsetProfile != null) {
            mAdapter.closeProfileProxy(BluetoothProfile.HEADSET_CLIENT, mHeadsetProfile);
        }

        // Unregister the broadcast receiver.
        try {
            unregisterReceiver(mBroadcastReceiver);
        } catch (IllegalArgumentException ex) {
            Log.w(TAG, "Receiver was not registered.");
        }

        // Unregister the phone account. This should ideally happen when disconnection ensues but in
        // case the service crashes we may need to force clean.
        synchronized (this) {
            mDevice = null;
            if (mDevicePhoneAccount != null) {
                mTelecomManager.unregisterPhoneAccount(mDevicePhoneAccount.getAccountHandle());
                mDevicePhoneAccount = null;
            }
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (DBG) {
            Log.d(TAG, "onStartCommand " + intent);
        }
        // In order to make sure that the service is sticky (recovers from errors when HFP
        // connection is still active) and to stop it we need a special intent since stopService
        // only recreates it.
        if (intent != null &&
            intent.getBooleanExtra(HeadsetClientService.HFP_CLIENT_STOP_TAG, false)) {
            // Stop the service.
            stopSelf();
            return 0;
        } else {
            IntentFilter filter = new IntentFilter();
            filter.addAction(BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED);
            filter.addAction(BluetoothHeadsetClient.ACTION_CALL_CHANGED);
            registerReceiver(mBroadcastReceiver, filter);
            return START_STICKY;
        }
    }

    // Find the connection specified by the key, also update the key with ID if present.
    private synchronized HfpClientConnection findConnectionKey(UUID key) {
        if (DBG) {
            Log.d(TAG, "findConnectionKey local key set " + mConnections.toString());
        }
        return mConnections.get(key);
    }

    private void handleCall(BluetoothHeadsetClientCall call) {
        if (DBG) {
            Log.d(TAG, "Got call " + call.toString(true));
        }
        HfpClientConnection connection = findConnectionKey(call.getUUID());

        if (connection != null) {
            connection.updateCall(call);
            connection.handleCallChanged();
        }

        if (connection == null) {
            // Create the connection here, trigger Telecom to bind to us.
            buildConnection(call.getDevice(), call, null);

            PhoneAccountHandle handle = getHandle();
            TelecomManager manager =
                    (TelecomManager) getSystemService(Context.TELECOM_SERVICE);

            // Depending on where this call originated make it an incoming call or outgoing
            // (represented as unknown call in telecom since). Since BluetoothHeadsetClientCall is a
            // parcelable we simply pack the entire object in there.
            Bundle b = new Bundle();
            if (call.getState() == BluetoothHeadsetClientCall.CALL_STATE_DIALING ||
                call.getState() == BluetoothHeadsetClientCall.CALL_STATE_ALERTING ||
                call.getState() == BluetoothHeadsetClientCall.CALL_STATE_ACTIVE ||
                call.getState() == BluetoothHeadsetClientCall.CALL_STATE_WAITING) {
                // This is an outgoing call. Even if it is an active call we do not have a way of
                // putting that parcelable in a seaprate field.
                b.putParcelable(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, call);
                manager.addNewUnknownCall(handle, b);
            } else if (call.getState() == BluetoothHeadsetClientCall.CALL_STATE_INCOMING) {
                // This is an incoming call.
                b.putParcelable(TelecomManager.EXTRA_INCOMING_CALL_EXTRAS, call);
                manager.addNewIncomingCall(handle, b);
            }
        } else if (call.getState() == BluetoothHeadsetClientCall.CALL_STATE_TERMINATED) {
            if (DBG) {
                Log.d(TAG, "Removing call " + call);
            }
            synchronized (this) {
                mConnections.remove(call.getUUID());
            }
        }

        updateConferenceableConnections();
    }

    // This method is called whenever there is a new incoming call (or right after BT connection).
    @Override
    public Connection onCreateIncomingConnection(
            PhoneAccountHandle connectionManagerAccount,
            ConnectionRequest request) {
        if (DBG) {
            Log.d(TAG, "onCreateIncomingConnection " + connectionManagerAccount +
                " req: " + request);
        }
        if (connectionManagerAccount != null &&
                !getHandle().equals(connectionManagerAccount)) {
            Log.w(TAG, "HfpClient does not support having a connection manager");
            return null;
        }

        // We should already have a connection by this time.
        BluetoothHeadsetClientCall call =
            request.getExtras().getParcelable(
                TelecomManager.EXTRA_INCOMING_CALL_EXTRAS);
        HfpClientConnection connection = null;

        synchronized (this) {
            connection = mConnections.get(call.getUUID());
        }

        if (connection != null) {
            connection.onAdded();
            updateConferenceableConnections();
            return connection;
        } else {
            Log.e(TAG, "Connection should exist in our db, if it doesn't we dont know how to " +
                "handle this call.");
            return null;
        }
    }

    // This method is called *only if* Dialer UI is used to place an outgoing call.
    @Override
    public Connection onCreateOutgoingConnection(
            PhoneAccountHandle connectionManagerAccount,
            ConnectionRequest request) {
        if (DBG) {
            Log.d(TAG, "onCreateOutgoingConnection " + connectionManagerAccount);
        }
        if (connectionManagerAccount != null &&
                !getHandle().equals(connectionManagerAccount)) {
            Log.w(TAG, "HfpClient does not support having a connection manager");
            return null;
        }

        HfpClientConnection connection =
                buildConnection(getDevice(request.getAccountHandle()), null, request.getAddress());
        if (connection != null) {
            connection.onAdded();
        }
        return connection;
    }

    // This method is called when:
    // 1. Outgoing call created from the AG.
    // 2. Call transfer from AG -> HF (on connection when existed call present).
    @Override
    public Connection onCreateUnknownConnection(
            PhoneAccountHandle connectionManagerAccount,
            ConnectionRequest request) {
        if (DBG) {
            Log.d(TAG, "onCreateUnknownConnection " + connectionManagerAccount);
        }
        if (connectionManagerAccount != null &&
                !getHandle().equals(connectionManagerAccount)) {
            Log.w(TAG, "HfpClient does not support having a connection manager");
            return null;
        }

        // We should already have a connection by this time.
        BluetoothHeadsetClientCall call =
            request.getExtras().getParcelable(
                TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS);
        Uri number = Uri.fromParts(PhoneAccount.SCHEME_TEL, call.getNumber(), null);

        HfpClientConnection connection = null;
        synchronized (this) {
            connection = mConnections.get(call.getUUID());
        }

        if (connection != null) {
            connection.onAdded();
            updateConferenceableConnections();
            return connection;
        } else {
            Log.e(TAG, "Connection should exist in our db, if it doesn't we dont know how to " +
                "handle this call " + call);
            return null;
        }
    }

    @Override
    public void onConference(Connection connection1, Connection connection2) {
        if (DBG) {
            Log.d(TAG, "onConference " + connection1 + " " + connection2);
        }
        if (mConference == null) {
            BluetoothDevice device = getDevice(getHandle());
            mConference = new HfpClientConference(getHandle(), device, mHeadsetProfile);
            addConference(mConference);
        }
        mConference.setActive();
        if (connection1.getConference() == null) {
            mConference.addConnection(connection1);
        }
        if (connection2.getConference() == null) {
            mConference.addConnection(connection2);
        }
    }

    // Updates any conferencable connections.
    private void updateConferenceableConnections() {
        boolean addConf = false;
        if (DBG) {
            Log.d(TAG, "Existing connections: " + mConnections + " existing conference " +
                mConference);
        }

        // If we have an existing conference call then loop through all connections and update any
        // connections that may have switched from conference -> non-conference.
        if (mConference != null) {
            for (Connection confConn : mConference.getConnections()) {
                if (!((HfpClientConnection) confConn).inConference()) {
                    if (DBG) {
                        Log.d(TAG, "Removing connection " + confConn + " from conference.");
                    }
                    mConference.removeConnection(confConn);
                }
            }
        }

        // If we have connections that are not already part of the conference then add them.
        // NOTE: addConnection takes care of duplicates (by mem addr) and the lifecycle of a
        // connection is maintained by the UUID.
        for (Connection otherConn : mConnections.values()) {
            if (((HfpClientConnection) otherConn).inConference()) {
                // If this is the first connection with conference, create the conference first.
                if (mConference == null) {
                    mConference = new HfpClientConference(getHandle(), mDevice, mHeadsetProfile);
                }
                if (mConference.addConnection(otherConn)) {
                    if (DBG) {
                        Log.d(TAG, "Adding connection " + otherConn + " to conference.");
                    }
                    addConf = true;
                }
            }
        }

        // If we have no connections in the conference we should simply end it.
        if (mConference != null && mConference.getConnections().size() == 0) {
            if (DBG) {
                Log.d(TAG, "Conference has no connection, destroying");
            }
            mConference.destroy();
            mConference = null;
        }

        // If we have a valid conference and not previously added then add it.
        if (mConference != null && addConf) {
            if (DBG) {
                Log.d(TAG, "Adding conference to stack.");
            }
            addConference(mConference);
        }
    }

    private synchronized void disconnectAll() {
        for (HfpClientConnection connection : mConnections.values()) {
            connection.onHfpDisconnected();
        }
        mConnections.clear();

        if (mConference != null) {
            mConference.destroy();
            mConference = null;
        }
    }

    private BluetoothDevice getDevice(PhoneAccountHandle handle) {
        PhoneAccount account = mTelecomManager.getPhoneAccount(handle);
        String btAddr = account.getAddress().getSchemeSpecificPart();
        return mAdapter.getRemoteDevice(btAddr);
    }

    private synchronized HfpClientConnection buildConnection(
            BluetoothDevice device, BluetoothHeadsetClientCall call, Uri number) {
        if (mHeadsetProfile == null) {
            Log.e(TAG, "Cannot create connection for call " + call + " when Profile not available");
            return null;
        }

        if (call == null && number == null) {
            Log.e(TAG, "Both call and number cannot be null.");
            return null;
        }

        if (DBG) {
            Log.d(TAG, "Creating connection on " + device + " for " + call + "/" + number);
        }
        HfpClientConnection connection = null;
        if (call != null) {
            connection = new HfpClientConnection(this, device, mHeadsetProfile, call);
        } else {
            connection = new HfpClientConnection(this, device, mHeadsetProfile, number);
        }
        if (connection.getState() != Connection.STATE_DISCONNECTED) {
            mConnections.put(connection.getUUID(), connection);
        }

        return connection;
    }

    BluetoothProfile.ServiceListener mServiceListener = new BluetoothProfile.ServiceListener() {
        @Override
        public void onServiceConnected(int profile, BluetoothProfile proxy) {
            if (DBG) {
                Log.d(TAG, "onServiceConnected");
            }
            mHeadsetProfile = (BluetoothHeadsetClient) proxy;

            List<BluetoothDevice> devices = mHeadsetProfile.getConnectedDevices();
            if (devices == null || devices.size() != 1) {
                Log.w(TAG, "No connected or more than one connected devices found." + devices);
            } else { // We have exactly one device connected.
                if (DBG) {
                    Log.d(TAG, "Creating phone account.");
                }
                synchronized (HfpClientConnectionService.this) {
                    mDevice = devices.get(0);
                    mDevicePhoneAccount = getAccount(HfpClientConnectionService.this, mDevice);
                    mTelecomManager.registerPhoneAccount(mDevicePhoneAccount);
                    mTelecomManager.enablePhoneAccount(
                        mDevicePhoneAccount.getAccountHandle(), true);
                    mTelecomManager.setUserSelectedOutgoingPhoneAccount(
                        mDevicePhoneAccount.getAccountHandle());
                }
            }

            List<BluetoothHeadsetClientCall> calls = mHeadsetProfile.getCurrentCalls(mDevice);
            if (DBG) {
                Log.d(TAG, "Got calls " + calls);
            }
            if (calls != null) {
                for (BluetoothHeadsetClientCall call : calls) {
                    handleCall(call);
                }
            }

            if (mPendingAcceptCall) {
                mHeadsetProfile.acceptCall(mDevice, BluetoothHeadsetClient.CALL_ACCEPT_NONE);
                mPendingAcceptCall = false;
            }
        }

        @Override
        public void onServiceDisconnected(int profile) {
            if (DBG) {
                Log.d(TAG, "onServiceDisconnected " + profile);
            }
            mHeadsetProfile = null;
            disconnectAll();
        }
    };

    public static boolean hasHfpClientEcc(BluetoothHeadsetClient client, BluetoothDevice device) {
        Bundle features = client.getCurrentAgEvents(device);
        return features == null ? false :
                features.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ECC, false);
    }

    public synchronized PhoneAccountHandle getHandle() {
        if (mDevicePhoneAccount == null) throw new IllegalStateException("Handle null??");
        return mDevicePhoneAccount.getAccountHandle();
    }

    public static PhoneAccount getAccount(Context context, BluetoothDevice device) {
        Uri addr = Uri.fromParts(HfpClientConnectionService.HFP_SCHEME, device.getAddress(), null);
        PhoneAccountHandle handle = new PhoneAccountHandle(
            new ComponentName(context, HfpClientConnectionService.class), device.getAddress());
        PhoneAccount account =
                new PhoneAccount.Builder(handle, "HFP")
                    .setAddress(addr)
                    .setSupportedUriSchemes(Arrays.asList(PhoneAccount.SCHEME_TEL))
                    .setCapabilities(PhoneAccount.CAPABILITY_CALL_PROVIDER)
                    .build();
        if (DBG) {
            Log.d(TAG, "phoneaccount: " + account);
        }
        return account;
    }
}
