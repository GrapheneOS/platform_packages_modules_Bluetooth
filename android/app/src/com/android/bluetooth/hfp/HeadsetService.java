/*
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

package com.android.bluetooth.hfp;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothHeadset;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.os.HandlerThread;
import android.os.Message;
import android.provider.Settings;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.ProfileService;

import java.util.ArrayList;
import java.util.List;

/**
 * Provides Bluetooth Headset and Handsfree profile, as a service in
 * the Bluetooth application.
 * @hide
 */
public class HeadsetService extends ProfileService {
    private static final boolean DBG = false;
    private static final String TAG = "HeadsetService";
    private static final String MODIFY_PHONE_STATE = android.Manifest.permission.MODIFY_PHONE_STATE;

    private HandlerThread mStateMachinesThread;
    private HeadsetStateMachine mStateMachine;
    private boolean mStarted;
    private boolean mCreated;
    private static HeadsetService sHeadsetService;

    @Override
    protected String getName() {
        return TAG;
    }

    @Override
    public synchronized IProfileServiceBinder initBinder() {
        return new BluetoothHeadsetBinder(this);
    }

    @Override
    protected synchronized void create() {
        mCreated = true;
    }

    @Override
    protected synchronized boolean start() {
        Log.i(TAG, "start()");
        mStateMachinesThread = new HandlerThread("HeadsetService.StateMachines");
        mStateMachinesThread.start();
        mStateMachine = HeadsetStateMachine.make(this, mStateMachinesThread.getLooper(),
                HeadsetNativeInterface.getInstance());
        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_BATTERY_CHANGED);
        filter.addAction(AudioManager.VOLUME_CHANGED_ACTION);
        filter.addAction(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY);
        registerReceiver(mHeadsetReceiver, filter);
        setHeadsetService(this);
        mStarted = true;
        return true;
    }

    @Override
    protected synchronized boolean stop() {
        Log.i(TAG, "stop()");
        if (!mStarted) {
            Log.w(TAG, "stop() called before start()");
            // Still return true because it is considered "stopped"
            return true;
        }
        mStarted = false;
        unregisterReceiver(mHeadsetReceiver);
        HeadsetStateMachine.destroy(mStateMachine);
        mStateMachine = null;
        mStateMachinesThread.quitSafely();
        mStateMachinesThread = null;
        setHeadsetService(null);
        return true;
    }

    @Override
    protected synchronized boolean cleanup() {
        Log.i(TAG, "cleanup");
        if (!mCreated) {
            Log.w(TAG, "cleanup() called before create()");
            // Still return true as it is considered "not created"
            return true;
        }
        mCreated = false;
        return true;
    }

    /**
     * Checks if this service object is able to accept binder calls
     * @return True if the object can accept binder calls, False otherwise
     */
    public synchronized boolean isAlive() {
        return isAvailable() && mCreated && mStarted;
    }

    // Handle messages from native (JNI) to Java
    void messageFromNative(HeadsetStackEvent stackEvent) {
        mStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT, stackEvent);
    }

    private final BroadcastReceiver mHeadsetReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(Intent.ACTION_BATTERY_CHANGED)) {
                mStateMachine.sendMessage(HeadsetStateMachine.INTENT_BATTERY_CHANGED, intent);
            } else if (action.equals(AudioManager.VOLUME_CHANGED_ACTION)) {
                int streamType = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_TYPE, -1);
                if (streamType == AudioManager.STREAM_BLUETOOTH_SCO) {
                    mStateMachine.sendMessage(HeadsetStateMachine.INTENT_SCO_VOLUME_CHANGED,
                            intent);
                }
            } else if (action.equals(BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY)) {
                int requestType = intent.getIntExtra(BluetoothDevice.EXTRA_ACCESS_REQUEST_TYPE,
                        BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS);
                if (requestType == BluetoothDevice.REQUEST_TYPE_PHONEBOOK_ACCESS) {
                    Log.v(TAG, "Received BluetoothDevice.ACTION_CONNECTION_ACCESS_REPLY");
                    mStateMachine.handleAccessPermissionResult(intent);
                }
            }
        }
    };

    /**
     * Handlers for incoming service calls
     */
    private static class BluetoothHeadsetBinder extends IBluetoothHeadset.Stub
            implements IProfileServiceBinder {
        private volatile HeadsetService mService;

        BluetoothHeadsetBinder(HeadsetService svc) {
            mService = svc;
        }

        @Override
        public boolean cleanup() {
            mService = null;
            return true;
        }

        private HeadsetService getService() {
            final HeadsetService service = mService;
            if (!Utils.checkCallerAllowManagedProfiles(service)) {
                Log.w(TAG, "Headset call not allowed for non-active user");
                return null;
            }
            if (service == null) {
                Log.w(TAG, "Service is null");
                return null;
            }
            if (!service.isAlive()) {
                Log.w(TAG, "Service is not alive");
                return null;
            }
            return service;
        }

        @Override
        public boolean connect(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.connect(device);
        }

        @Override
        public boolean disconnect(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            if (DBG) {
                Log.d(TAG, "disconnect in HeadsetService");
            }
            return service.disconnect(device);
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            HeadsetService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getConnectedDevices();
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            HeadsetService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getDevicesMatchingConnectionStates(states);
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return service.getConnectionState(device);
        }

        @Override
        public boolean setPriority(BluetoothDevice device, int priority) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.setPriority(device, priority);
        }

        @Override
        public int getPriority(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return BluetoothProfile.PRIORITY_UNDEFINED;
            }
            return service.getPriority(device);
        }

        @Override
        public boolean startVoiceRecognition(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.startVoiceRecognition(device);
        }

        @Override
        public boolean stopVoiceRecognition(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.stopVoiceRecognition(device);
        }

        @Override
        public boolean isAudioOn() {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.isAudioOn();
        }

        @Override
        public boolean isAudioConnected(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.isAudioConnected(device);
        }

        @Override
        public int getAudioState(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return BluetoothHeadset.STATE_AUDIO_DISCONNECTED;
            }
            return service.getAudioState(device);
        }

        @Override
        public boolean connectAudio() {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.connectAudio();
        }

        @Override
        public boolean disconnectAudio() {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.disconnectAudio();
        }

        @Override
        public void setAudioRouteAllowed(boolean allowed) {
            HeadsetService service = getService();
            if (service == null) {
                return;
            }
            service.setAudioRouteAllowed(allowed);
        }

        @Override
        public boolean getAudioRouteAllowed() {
            HeadsetService service = getService();
            if (service != null) {
                return service.getAudioRouteAllowed();
            }
            return false;
        }

        @Override
        public void setForceScoAudio(boolean forced) {
            HeadsetService service = getService();
            if (service == null) {
                return;
            }
            service.setForceScoAudio(forced);
        }

        @Override
        public boolean startScoUsingVirtualVoiceCall(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.startScoUsingVirtualVoiceCall(device);
        }

        @Override
        public boolean stopScoUsingVirtualVoiceCall(BluetoothDevice device) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.stopScoUsingVirtualVoiceCall(device);
        }

        @Override
        public void phoneStateChanged(int numActive, int numHeld, int callState, String number,
                int type) {
            HeadsetService service = getService();
            if (service == null) {
                return;
            }
            service.phoneStateChanged(numActive, numHeld, callState, number, type);
        }

        @Override
        public void clccResponse(int index, int direction, int status, int mode, boolean mpty,
                String number, int type) {
            HeadsetService service = getService();
            if (service == null) {
                return;
            }
            service.clccResponse(index, direction, status, mode, mpty, number, type);
        }

        @Override
        public boolean sendVendorSpecificResultCode(BluetoothDevice device, String command,
                String arg) {
            HeadsetService service = getService();
            if (service == null) {
                return false;
            }
            return service.sendVendorSpecificResultCode(device, command, arg);
        }
    }

    // API methods
    public static synchronized HeadsetService getHeadsetService() {
        if (sHeadsetService != null && sHeadsetService.isAvailable()) {
            if (DBG) {
                Log.d(TAG, "getHeadsetService(): returning " + sHeadsetService);
            }
            return sHeadsetService;
        }
        if (DBG) {
            if (sHeadsetService == null) {
                Log.d(TAG, "getHeadsetService(): service is NULL");
            } else if (!(sHeadsetService.isAvailable())) {
                Log.d(TAG, "getHeadsetService(): service is not available");
            }
        }
        return null;
    }

    private static synchronized void setHeadsetService(HeadsetService instance) {
        if (DBG) {
            Log.d(TAG, "setHeadsetService(): set to: " + instance);
        }
        sHeadsetService = instance;
    }

    public boolean connect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        Log.d(TAG, "connect: device=" + device);
        if (getPriority(device) == BluetoothProfile.PRIORITY_OFF) {
            Log.w(TAG, "connect: PRIORITY_OFF, device=" + device);
            return false;
        }
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState == BluetoothProfile.STATE_CONNECTED
                || connectionState == BluetoothProfile.STATE_CONNECTING) {
            Log.w(TAG, "connect: already connected/connecting, connectionState=" + connectionState
                    + ", device=" + device);
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.CONNECT, device);
        return true;
    }

    boolean disconnect(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        Log.d(TAG, "disconnect: device=" + device);
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED
                && connectionState != BluetoothProfile.STATE_CONNECTING) {
            Log.w(TAG, "disconnect: not connected/connecting, connectionState=" + connectionState
                    + ", device=" + device);
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT, device);
        return true;
    }

    public List<BluetoothDevice> getConnectedDevices() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getConnectedDevices();
    }

    private List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getDevicesMatchingConnectionStates(states);
    }

    public int getConnectionState(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getConnectionState(device);
    }

    public boolean setPriority(BluetoothDevice device, int priority) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        Settings.Global.putInt(getContentResolver(),
                Settings.Global.getBluetoothHeadsetPriorityKey(device.getAddress()), priority);
        if (DBG) {
            Log.d(TAG, "Saved priority " + device + " = " + priority);
        }
        return true;
    }

    public int getPriority(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        int priority = Settings.Global.getInt(getContentResolver(),
                Settings.Global.getBluetoothHeadsetPriorityKey(device.getAddress()),
                BluetoothProfile.PRIORITY_UNDEFINED);
        return priority;
    }

    boolean startVoiceRecognition(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED
                && connectionState != BluetoothProfile.STATE_CONNECTING) {
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.VOICE_RECOGNITION_START);
        return true;
    }

    boolean stopVoiceRecognition(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        // It seem that we really need to check the AudioOn state.
        // But since we allow startVoiceRecognition in STATE_CONNECTED and
        // STATE_CONNECTING state, we do these 2 in this method
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED
                && connectionState != BluetoothProfile.STATE_CONNECTING) {
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.VOICE_RECOGNITION_STOP);
        // TODO is this return correct when the voice recognition is not on?
        return true;
    }

    boolean isAudioOn() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.isAudioOn();
    }

    boolean isAudioConnected(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.isAudioConnected(device);
    }

    int getAudioState(BluetoothDevice device) {
        return mStateMachine.getAudioState(device);
    }

    public void setAudioRouteAllowed(boolean allowed) {
        mStateMachine.setAudioRouteAllowed(allowed);
    }

    public boolean getAudioRouteAllowed() {
        return mStateMachine.getAudioRouteAllowed();
    }

    public void setForceScoAudio(boolean forced) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        mStateMachine.setForceScoAudio(forced);
    }

    boolean connectAudio() {
        // TODO(BT) BLUETOOTH or BLUETOOTH_ADMIN permission
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (!mStateMachine.isConnected()) {
            Log.w(TAG, "connectAudio: profile not connected");
            return false;
        }
        if (mStateMachine.isAudioOn()) {
            Log.w(TAG, "connectAudio: audio is already ON");
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.CONNECT_AUDIO);
        return true;
    }

    boolean disconnectAudio() {
        // TODO(BT) BLUETOOTH or BLUETOOTH_ADMIN permission
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (!mStateMachine.isAudioOn()) {
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT_AUDIO);
        return true;
    }

    boolean startScoUsingVirtualVoiceCall(BluetoothDevice device) {
        /* Do not ignore request if HSM state is still Disconnected or
           Pending, it will be processed when transitioned to Connected */
        mStateMachine.sendMessage(HeadsetStateMachine.VIRTUAL_CALL_START, device);
        return true;
    }

    boolean stopScoUsingVirtualVoiceCall(BluetoothDevice device) {
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED
                && connectionState != BluetoothProfile.STATE_CONNECTING) {
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.VIRTUAL_CALL_STOP, device);
        return true;
    }

    private void phoneStateChanged(int numActive, int numHeld, int callState, String number,
            int type) {
        enforceCallingOrSelfPermission(MODIFY_PHONE_STATE, null);
        Message msg = mStateMachine.obtainMessage(HeadsetStateMachine.CALL_STATE_CHANGED);
        msg.obj = new HeadsetCallState(numActive, numHeld, callState, number, type);
        msg.arg1 = 0; // false
        mStateMachine.sendMessage(msg);
    }

    private void clccResponse(int index, int direction, int status, int mode, boolean mpty,
            String number, int type) {
        enforceCallingOrSelfPermission(MODIFY_PHONE_STATE, null);
        mStateMachine.sendMessage(HeadsetStateMachine.SEND_CCLC_RESPONSE,
                new HeadsetClccResponse(index, direction, status, mode, mpty, number, type));
    }

    private boolean sendVendorSpecificResultCode(BluetoothDevice device, String command,
            String arg) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED) {
            return false;
        }
        // Currently we support only "+ANDROID".
        if (!command.equals(BluetoothHeadset.VENDOR_RESULT_CODE_COMMAND_ANDROID)) {
            Log.w(TAG, "Disallowed unsolicited result code command: " + command);
            return false;
        }
        mStateMachine.sendMessage(HeadsetStateMachine.SEND_VENDOR_SPECIFIC_RESULT_CODE,
                new HeadsetVendorSpecificResultCode(device, command, arg));
        return true;
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        if (mStateMachine != null) {
            mStateMachine.dump(sb);
        }
    }
}
