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

package com.android.bluetooth.avrcp;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAvrcpPlayerSettings;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothAvrcpController;
import android.content.Context;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.session.PlaybackState;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Provides Bluetooth AVRCP Controller profile, as a service in the Bluetooth application.
 */
public class AvrcpControllerService extends ProfileService {
    static final String TAG = "AvrcpControllerService";
    static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
    static final boolean VDBG = Log.isLoggable(TAG, Log.VERBOSE);
    /*
     *  Play State Values from JNI
     */
    private static final byte JNI_PLAY_STATUS_STOPPED = 0x00;
    private static final byte JNI_PLAY_STATUS_PLAYING = 0x01;
    private static final byte JNI_PLAY_STATUS_PAUSED  = 0x02;
    private static final byte JNI_PLAY_STATUS_FWD_SEEK = 0x03;
    private static final byte JNI_PLAY_STATUS_REV_SEEK = 0x04;
    private static final byte JNI_PLAY_STATUS_ERROR    = -1;

    private AvrcpControllerStateMachine mAvrcpCtSm;
    private static AvrcpControllerService sAvrcpControllerService;

    private final ArrayList<BluetoothDevice> mConnectedDevices
        = new ArrayList<BluetoothDevice>();

    static {
        classInitNative();
    }

    public AvrcpControllerService() {
        initNative();
    }

    protected String getName() {
        return TAG;
    }

    protected IProfileServiceBinder initBinder() {
        return new BluetoothAvrcpControllerBinder(this);
    }

    protected boolean start() {
        HandlerThread thread = new HandlerThread("BluetoothAvrcpHandler");
        thread.start();
        Looper looper = thread.getLooper();
        mAvrcpCtSm = new AvrcpControllerStateMachine(this);
        mAvrcpCtSm.start();

        setAvrcpControllerService(this);
        return true;
    }

    protected boolean stop() {
        if (mAvrcpCtSm != null) {
            mAvrcpCtSm.doQuit();
        }
        return true;
    }

    //API Methods

    public static synchronized AvrcpControllerService getAvrcpControllerService() {
        if (sAvrcpControllerService != null && sAvrcpControllerService.isAvailable()) {
            if (DBG) {
                Log.d(TAG, "getAvrcpControllerService(): returning "
                    + sAvrcpControllerService);
            }
            return sAvrcpControllerService;
        }
        if (DBG) {
            if (sAvrcpControllerService == null) {
                Log.d(TAG, "getAvrcpControllerService(): service is NULL");
            } else if (!(sAvrcpControllerService.isAvailable())) {
                Log.d(TAG, "getAvrcpControllerService(): service is not available");
            }
        }
        return null;
    }

    private static synchronized void setAvrcpControllerService(AvrcpControllerService instance) {
        if (instance != null && instance.isAvailable()) {
            if (DBG) {
                Log.d(TAG, "setAvrcpControllerService(): set to: " + sAvrcpControllerService);
            }
            sAvrcpControllerService = instance;
        } else {
            if (DBG) {
                if (sAvrcpControllerService == null) {
                    Log.d(TAG, "setAvrcpControllerService(): service not available");
                } else if (!sAvrcpControllerService.isAvailable()) {
                    Log.d(TAG, "setAvrcpControllerService(): service is cleaning up");
                }
            }
        }
    }

    private static synchronized void clearAvrcpControllerService() {
        sAvrcpControllerService = null;
    }

    public List<BluetoothDevice> getConnectedDevices() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mConnectedDevices;
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        for (int i = 0; i < states.length; i++) {
            if (states[i] == BluetoothProfile.STATE_CONNECTED) {
                return mConnectedDevices;
            }
        }
        return new ArrayList<BluetoothDevice>();
    }

    int getConnectionState(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return (mConnectedDevices.contains(device) ? BluetoothProfile.STATE_CONNECTED :
            BluetoothProfile.STATE_DISCONNECTED);
    }

    public void sendGroupNavigationCmd(BluetoothDevice device, int keyCode, int keyState) {
        Log.v(TAG, "sendGroupNavigationCmd keyCode: " + keyCode + " keyState: " + keyState);
        if (device == null) {
            throw new NullPointerException("device == null");
        }
        if (!(mConnectedDevices.contains(device))) {
            for (BluetoothDevice cdevice : mConnectedDevices) {
                Log.e(TAG, "Device: " + cdevice);
            }
            Log.e(TAG, " Device does not match " + device);
            return;
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_SEND_GROUP_NAVIGATION_CMD, keyCode, keyState, device);
        mAvrcpCtSm.sendMessage(msg);
    }

    public void sendPassThroughCmd(BluetoothDevice device, int keyCode, int keyState) {
        Log.v(TAG, "sendPassThroughCmd keyCode: " + keyCode + " keyState: " + keyState);
        if (device == null) {
            throw new NullPointerException("device == null");
        }
        if (!mConnectedDevices.contains(device)) {
            Log.d(TAG, " Device does not match");
            return;
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        Message msg = mAvrcpCtSm
            .obtainMessage(AvrcpControllerStateMachine.MESSAGE_SEND_PASS_THROUGH_CMD,
                keyCode, keyState, device);
        mAvrcpCtSm.sendMessage(msg);

    }

    public void startAvrcpUpdates() {
        mAvrcpCtSm.obtainMessage(
            AvrcpControllerStateMachine.MESSAGE_START_METADATA_BROADCASTS).sendToTarget();
    }

    public void stopAvrcpUpdates() {
        mAvrcpCtSm.obtainMessage(
            AvrcpControllerStateMachine.MESSAGE_STOP_METADATA_BROADCASTS).sendToTarget();
    }

    public MediaMetadata getMetaData(BluetoothDevice device) {
        Log.d(TAG, "getMetaData = ");
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (mConnectedDevices.contains(device)) {
            return mAvrcpCtSm.getCurrentMetaData();
        }
        return null;
    }

    public PlaybackState getPlaybackState(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "getPlayBackState device = " + device);
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mAvrcpCtSm.getCurrentPlayBackState();
    }

    public BluetoothAvrcpPlayerSettings getPlayerSettings(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "getPlayerApplicationSetting ");
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (mConnectedDevices.contains(device)) {
            return mAvrcpCtSm.getPlayerAppSettings();
        }
        return null;
    }

    public boolean setPlayerApplicationSetting(BluetoothAvrcpPlayerSettings plAppSetting) {
        if (!mAvrcpCtSm.isConnected()) {
            return false;
        }
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        boolean isSettingSupported = mAvrcpCtSm
            .isPlayerAppSettingSupported(plAppSetting);
        if (isSettingSupported) {
            Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
                MESSAGE_SEND_SET_CURRENT_PLAYER_APPLICATION_SETTINGS, plAppSetting);
            mAvrcpCtSm.sendMessage(msg);
        }
        return isSettingSupported;
    }

    //Binder object: Must be static class or memory leak may occur
    private static class BluetoothAvrcpControllerBinder extends IBluetoothAvrcpController.Stub
        implements IProfileServiceBinder {

        private AvrcpControllerService mService;

        private AvrcpControllerService getService() {
            if (!Utils.checkCaller()) {
                Log.w(TAG, "AVRCP call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        BluetoothAvrcpControllerBinder(AvrcpControllerService svc) {
            mService = svc;
        }

        public boolean cleanup() {
            mService = null;
            return true;
        }

        public List<BluetoothDevice> getConnectedDevices() {
            AvrcpControllerService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getConnectedDevices();
        }

        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            AvrcpControllerService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getDevicesMatchingConnectionStates(states);
        }

        public int getConnectionState(BluetoothDevice device) {
            AvrcpControllerService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return service.getConnectionState(device);
        }

        public void sendPassThroughCmd(BluetoothDevice device, int keyCode, int keyState) {
            Log.v(TAG, "Binder Call: sendPassThroughCmd");
            AvrcpControllerService service = getService();
            if (service == null) {
                return;
            }
            service.sendPassThroughCmd(device, keyCode, keyState);
        }

        @Override
        public void sendGroupNavigationCmd(BluetoothDevice device, int keyCode, int keyState) {
            Log.v(TAG, "Binder Call: sendGroupNavigationCmd");
            AvrcpControllerService service = getService();
            if (service == null) {
                return;
            }
            service.sendGroupNavigationCmd(device, keyCode, keyState);
        }

        @Override
        public BluetoothAvrcpPlayerSettings getPlayerSettings(BluetoothDevice device) {
            Log.v(TAG, "Binder Call: getPlayerApplicationSetting ");
            AvrcpControllerService service = getService();
            if (service == null) {
                return null;
            }
            return service.getPlayerSettings(device);
        }

        @Override
        public MediaMetadata getMetadata(BluetoothDevice device) {
            Log.v(TAG, "Binder Call: getMetaData ");
            AvrcpControllerService service = getService();
            if (service == null) {
                return null;
            }
            return service.getMetaData(device);
        }

        @Override
        public PlaybackState getPlaybackState(BluetoothDevice device) {
            Log.v(TAG, "Binder Call: getPlaybackState");
            AvrcpControllerService service = getService();
            if (service == null) {
                return null;
            }
            return service.getPlaybackState(device);
        }

        @Override
        public boolean setPlayerApplicationSetting(BluetoothAvrcpPlayerSettings plAppSetting) {
            Log.v(TAG, "Binder Call: setPlayerApplicationSetting ");
            AvrcpControllerService service = getService();
            if (service == null) {
                return false;
            }
            return service.setPlayerApplicationSetting(plAppSetting);
        }
    }

    private void handlePassthroughRsp(int id, int keyState, byte[] address) {
        Log.d(TAG, "passthrough response received as: key: " + id + " state: " + keyState);
    }

    // Called by JNI when a device has connected or disconnected.
    private void onConnectionStateChanged(boolean connected, byte[] address) {
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        Log.d(TAG, "onConnectionStateChanged " + connected + " " + device + " size " +
            mConnectedDevices.size());
        if (device == null) {
            return;
        }
        int oldState = (mConnectedDevices.contains(device) ? BluetoothProfile.STATE_CONNECTED :
            BluetoothProfile.STATE_DISCONNECTED);
        int newState = (connected ? BluetoothProfile.STATE_CONNECTED :
            BluetoothProfile.STATE_DISCONNECTED);

        if (connected && oldState == BluetoothProfile.STATE_DISCONNECTED) {
            /* AVRCPControllerService supports single connection */
            if (mConnectedDevices.size() > 0) {
                Log.d(TAG, "A Connection already exists, returning");
                return;
            }
            mConnectedDevices.add(device);
            Message msg = mAvrcpCtSm.obtainMessage(
                AvrcpControllerStateMachine.MESSAGE_PROCESS_CONNECTION_CHANGE, newState,
                oldState, device);
            mAvrcpCtSm.sendMessage(msg);
        } else if (!connected && oldState == BluetoothProfile.STATE_CONNECTED) {
            mConnectedDevices.remove(device);
            Message msg = mAvrcpCtSm.obtainMessage(
                AvrcpControllerStateMachine.MESSAGE_PROCESS_CONNECTION_CHANGE, newState,
                oldState, device);
            mAvrcpCtSm.sendMessage(msg);
        }
    }

    // Called by JNI to notify Avrcp of features supported by the Remote device.
    private void getRcFeatures(byte[] address, int features) {
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        Message msg = mAvrcpCtSm.obtainMessage(
            AvrcpControllerStateMachine.MESSAGE_PROCESS_RC_FEATURES, features, 0, device);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI
    private void setPlayerAppSettingRsp(byte[] address, byte accepted) {
              /* Do Nothing. */
    }

    // Called by JNI when remote wants to receive absolute volume notifications.
    private void handleRegisterNotificationAbsVol(byte[] address, byte label) {
        Log.d(TAG, "handleRegisterNotificationAbsVol ");
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION, (int) label, 0);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI when remote wants to set absolute volume.
    private void handleSetAbsVolume(byte[] address, byte absVol, byte label) {
        Log.d(TAG, "handleSetAbsVolume ");
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        Message msg = mAvrcpCtSm.obtainMessage(
            AvrcpControllerStateMachine.MESSAGE_PROCESS_SET_ABS_VOL_CMD, absVol, label);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI when a track changes and local AvrcpController is registered for updates.
    private void onTrackChanged(byte[] address, byte numAttributes, int[] attributes,
        String[] attribVals) {
        Log.d(TAG, "onTrackChanged ");
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        HashMap<Integer, String> attributeMap = new HashMap<Integer, String>();
        for (int i = 0; i < numAttributes; i++) {
            attributeMap.put(attributes[i], attribVals[i]);
        }

        TrackInfo mTrack = new TrackInfo(attributeMap);
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_TRACK_CHANGED, mTrack);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI periodically based upon timer to update play position
    private void onPlayPositionChanged(byte[] address, int songLen, int currSongPosition) {
        Log.d(TAG, "onPlayPositionChanged ");
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_PLAY_POS_CHANGED, songLen, currSongPosition);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI on changes of play status
    private void onPlayStatusChanged(byte[] address, byte playStatus) {
        if (DBG) {
            Log.d(TAG, "onPlayStatusChanged " + playStatus);
        }
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        int playbackState = PlaybackState.STATE_NONE;
        switch (playStatus) {
            case JNI_PLAY_STATUS_STOPPED:
                playbackState =  PlaybackState.STATE_STOPPED;
                break;
            case JNI_PLAY_STATUS_PLAYING:
                playbackState =  PlaybackState.STATE_PLAYING;
                break;
            case JNI_PLAY_STATUS_PAUSED:
                playbackState = PlaybackState.STATE_PAUSED;
                break;
            case JNI_PLAY_STATUS_FWD_SEEK:
                playbackState = PlaybackState.STATE_FAST_FORWARDING;
                break;
            case JNI_PLAY_STATUS_REV_SEEK:
                playbackState = PlaybackState.STATE_FAST_FORWARDING;
                break;
            default:
                playbackState = PlaybackState.STATE_NONE;
        }
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_PLAY_STATUS_CHANGED, playbackState, 0);
        mAvrcpCtSm.sendMessage(msg);
    }

    // Called by JNI to report remote Player's capabilities
    private void handlePlayerAppSetting(byte[] address, byte[] playerAttribRsp, int rspLen) {
        Log.d(TAG, "handlePlayerAppSetting rspLen = " + rspLen);
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        PlayerApplicationSettings supportedSettings = PlayerApplicationSettings.
            makeSupportedSettings(playerAttribRsp);

        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_SUPPORTED_PLAYER_APP_SETTING, 0, 0, supportedSettings);
        mAvrcpCtSm.sendMessage(msg);
    }

    private void onPlayerAppSettingChanged(byte[] address, byte[] playerAttribRsp, int rspLen) {
        Log.d(TAG, "onPlayerAppSettingChanged ");
        BluetoothDevice device = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address);
        if (!mConnectedDevices.contains(device)) {
            return;
        }
        PlayerApplicationSettings desiredSettings = PlayerApplicationSettings.
            makeSettings(playerAttribRsp);
        Message msg = mAvrcpCtSm.obtainMessage(AvrcpControllerStateMachine.
            MESSAGE_PROCESS_PLAYER_APP_SETTING_CHANGED, 0, 0, desiredSettings.getAvrcpSettings());
        mAvrcpCtSm.sendMessage(msg);
    }

    private void handleGroupNavigationRsp(int id, int keyState) {
        Log.d(TAG, "group navigation response received as: key: "
            + id + " state: " + keyState);
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        mAvrcpCtSm.dump(sb);
    }

    private native static void classInitNative();

    private native void initNative();

    private native void cleanupNative();

    native static boolean sendPassThroughCommandNative(byte[] address, int keyCode, int keyState);

    native static boolean sendGroupNavigationCommandNative(byte[] address, int keyCode,
        int keyState);

    native static void setPlayerApplicationSettingValuesNative(byte[] address, byte numAttrib,
        byte[] atttibIds, byte[] attribVal);

    /* This api is used to send response to SET_ABS_VOL_CMD */
    native static void sendAbsVolRspNative(byte[] address, int absVol, int label);

    /* This api is used to inform remote for any volume level changes */
    native static void sendRegisterAbsVolRspNative(byte[] address, byte rspType, int absVol,
        int label);
}
