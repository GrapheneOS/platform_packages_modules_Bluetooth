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

import android.bluetooth.BluetoothAvrcpController;
import android.bluetooth.BluetoothAvrcpPlayerSettings;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.session.PlaybackState;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dpsink.A2dpSinkService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import java.util.ArrayList;

/**
 * Provides Bluetooth AVRCP Controller State Machine responsible for all remote control connections 
 * and interactions with a remote controlable device.
 */
class AvrcpControllerStateMachine extends StateMachine {

    // commands from Binder service
    static final int MESSAGE_SEND_PASS_THROUGH_CMD = 1;
    static final int MESSAGE_SEND_SET_CURRENT_PLAYER_APPLICATION_SETTINGS = 2;
    static final int MESSAGE_SEND_GROUP_NAVIGATION_CMD = 3;

    // commands from native layer
    static final int MESSAGE_PROCESS_SUPPORTED_PLAYER_APP_SETTING = 101;
    static final int MESSAGE_PROCESS_PLAYER_APP_SETTING_CHANGED = 102;
    static final int MESSAGE_PROCESS_SET_ABS_VOL_CMD = 103;
    static final int MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION = 104;
    static final int MESSAGE_PROCESS_TRACK_CHANGED = 105;
    static final int MESSAGE_PROCESS_PLAY_POS_CHANGED = 106;
    static final int MESSAGE_PROCESS_PLAY_STATUS_CHANGED = 107;
    static final int MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION = 108;

    // commands from A2DP sink
    static final int MESSAGE_STOP_METADATA_BROADCASTS = 201;
    static final int MESSAGE_START_METADATA_BROADCASTS = 202;

    // commands for configuring connection
    static final int MESSAGE_PROCESS_RC_FEATURES = 301;
    static final int MESSAGE_PROCESS_CONNECTION_CHANGE = 302;

    /*
     * Base value for absolute volume from JNI
     */
    private static final int ABS_VOL_BASE = 127;

    /*
     * Notification types for Avrcp protocol JNI.
     */
    private static final byte NOTIFICATION_RSP_TYPE_INTERIM = 0x00;
    private static final byte NOTIFICATION_RSP_TYPE_CHANGED = 0x01;


    private static final String TAG = "AvrcpControllerSM";
    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);
    private static final boolean VDBG = Log.isLoggable(TAG, Log.VERBOSE);

    private final Context mContext;
    private final AudioManager mAudioManager;

    private final State mDisconnected;
    private final State mConnected;

    private final Object mLock = new Object();

    // APIs exist to access these so they must be thread safe
    private Boolean mIsConnected = false;
    private RemoteDevice mRemoteDevice;

    // Only accessed from State Machine processMessage
    private boolean mAbsoluteVolumeChangeInProgress = false;
    private boolean mBroadcastMetadata = false;
    private int previousPercentageVol = -1;


    AvrcpControllerStateMachine(Context context) {
        super(TAG);
        mContext = context;

        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        IntentFilter filter = new IntentFilter(AudioManager.VOLUME_CHANGED_ACTION);
        mContext.registerReceiver(mBroadcastReceiver, filter);

        mDisconnected = new Disconnected();
        mConnected = new Connected();

        addState(mDisconnected);
        addState(mConnected);

        setInitialState(mDisconnected);
    }

    class Disconnected extends State {

        @Override
        public boolean processMessage(Message msg) {
            Log.d(TAG, " HandleMessage: " + dumpMessageString(msg.what));
            switch (msg.what) {
                case MESSAGE_PROCESS_CONNECTION_CHANGE:
                    if (msg.arg1 == BluetoothProfile.STATE_CONNECTED) {
                        transitionTo(mConnected);
                        BluetoothDevice rtDevice = (BluetoothDevice) msg.obj;
                        synchronized(mLock) {
                            mRemoteDevice = new RemoteDevice(rtDevice);
                            mIsConnected = true;
                        }
                        Intent intent = new Intent(
                            BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED);
                        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                            BluetoothProfile.STATE_DISCONNECTED);
                        intent.putExtra(BluetoothProfile.EXTRA_STATE,
                            BluetoothProfile.STATE_CONNECTED);
                        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, rtDevice);
                        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                    }
                    break;

                default:
                    Log.w(TAG,"Currently Disconnected not handling " + dumpMessageString(msg.what));
                    return false;
            }
            return true;
        }
    }

    class Connected extends State {

        @Override
        public boolean processMessage(Message msg) {
            Log.d(TAG, " HandleMessage: " + dumpMessageString(msg.what));
            A2dpSinkService a2dpSinkService = A2dpSinkService.getA2dpSinkService();
            synchronized (mLock) {
                switch (msg.what) {
                    case MESSAGE_STOP_METADATA_BROADCASTS:
                        mBroadcastMetadata = false;
                        broadcastPlayBackStateChanged(new PlaybackState.Builder().setState(
                            PlaybackState.STATE_PAUSED, mRemoteDevice.getPlayerPosition(),
                            0).build());
                        break;

                    case MESSAGE_START_METADATA_BROADCASTS:
                        mBroadcastMetadata = true;
                        broadcastPlayBackStateChanged(mRemoteDevice.getPlaybackState());
                        broadcastMetaDataChanged(
                            mRemoteDevice.getCurrentTrack().getMediaMetaData());
                        break;

                    case MESSAGE_SEND_PASS_THROUGH_CMD:
                        BluetoothDevice device = (BluetoothDevice) msg.obj;
                        AvrcpControllerService
                            .sendPassThroughCommandNative(Utils.getByteAddress(device), msg.arg1,
                                msg.arg2);
                        if (a2dpSinkService != null) {
                            Log.d(TAG, " inform AVRCP Commands to A2DP Sink ");
                            a2dpSinkService.informAvrcpPassThroughCmd(device, msg.arg1, msg.arg2);
                        }
                        break;

                    case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                        AvrcpControllerService.sendGroupNavigationCommandNative(
                            mRemoteDevice.getBluetoothAddress(), msg.arg1, msg.arg2);
                        break;

                    case MESSAGE_SEND_SET_CURRENT_PLAYER_APPLICATION_SETTINGS:
                        // The native layer interface expects 2 byte arrays.
                        BluetoothAvrcpPlayerSettings currentSettings =
                            (BluetoothAvrcpPlayerSettings) msg.obj;
                        PlayerApplicationSettings tempSettings = new PlayerApplicationSettings();
                        tempSettings.setValues(currentSettings);
                        ArrayList<Byte> settingList = tempSettings.getNativeSettings();
                        int numAttributes =  settingList.size()/2;
                        byte[] attributeIds = new byte[numAttributes];
                        byte[] attributeVals = new byte[numAttributes];
                        for (int i = 0; i < numAttributes; i++) {
                            attributeIds[i] = settingList.get(i*2);
                            attributeVals[i] = settingList.get(i*2+1);
                        }
                        AvrcpControllerService.setPlayerApplicationSettingValuesNative(
                            mRemoteDevice.getBluetoothAddress(), (byte) numAttributes, attributeIds,
                            attributeVals);
                        break;

                    case MESSAGE_PROCESS_CONNECTION_CHANGE:
                        if (msg.arg1 == BluetoothProfile.STATE_DISCONNECTED) {
                            synchronized (mLock) {
                                mIsConnected = false;
                                mRemoteDevice = null;
                            }
                            transitionTo(mDisconnected);
                            BluetoothDevice rtDevice = (BluetoothDevice) msg.obj;
                            Intent intent = new Intent(
                                BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED);
                            intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                BluetoothProfile.STATE_CONNECTED);
                            intent.putExtra(BluetoothProfile.EXTRA_STATE,
                                BluetoothProfile.STATE_DISCONNECTED);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, rtDevice);
                            mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                        }
                        break;

                    case MESSAGE_PROCESS_RC_FEATURES:
                        mRemoteDevice.setRemoteFeatures(msg.arg1);
                        break;

                    case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                        mAbsoluteVolumeChangeInProgress = true;
                        setAbsVolume(msg.arg1, msg.arg2);
                        break;

                    case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION: {
                        mRemoteDevice.setNotificationLabel(msg.arg1);
                        mRemoteDevice.setAbsVolNotificationRequested(true);
                        int percentageVol = getVolumePercentage();
                        Log.d(TAG,
                            " Sending Interim Response = " + percentageVol + " label " + msg.arg1);
                        AvrcpControllerService
                            .sendRegisterAbsVolRspNative(mRemoteDevice.getBluetoothAddress(),
                                NOTIFICATION_RSP_TYPE_INTERIM,
                                percentageVol,
                                mRemoteDevice.getNotificationLabel());
                    }
                    break;

                    case MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION: {
                        if (mAbsoluteVolumeChangeInProgress) {
                            mAbsoluteVolumeChangeInProgress = false;
                        } else {
                            if (mRemoteDevice.getAbsVolNotificationRequested()) {
                                int percentageVol = getVolumePercentage();
                                if (percentageVol != previousPercentageVol) {
                                    AvrcpControllerService.sendRegisterAbsVolRspNative(
                                        mRemoteDevice.getBluetoothAddress(),
                                        NOTIFICATION_RSP_TYPE_CHANGED,
                                        percentageVol, mRemoteDevice.getNotificationLabel());
                                    previousPercentageVol = percentageVol;
                                    mRemoteDevice.setAbsVolNotificationRequested(false);
                                }
                            }
                        }
                    }
                    break;

                    case MESSAGE_PROCESS_TRACK_CHANGED:
                        mRemoteDevice.updateCurrentTrack((TrackInfo) msg.obj);
                        if (mBroadcastMetadata) {
                            broadcastMetaDataChanged(mRemoteDevice.getCurrentTrack().
                                getMediaMetaData());
                        }
                        break;

                    case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                        mRemoteDevice.setPlayerPosition(msg.arg2);
                        if (mBroadcastMetadata) {
                            broadcastPlayBackStateChanged(getCurrentPlayBackState());
                        }
                        break;

                    case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                        int status = msg.arg1;
                        mRemoteDevice.setPlayStatus(status);
                        if (status == PlaybackState.STATE_PLAYING) {
                            a2dpSinkService.informTGStatePlaying(mRemoteDevice.mBTDevice, true);
                        } else if (status == PlaybackState.STATE_PAUSED ||
                            status == PlaybackState.STATE_STOPPED) {
                            a2dpSinkService.informTGStatePlaying(mRemoteDevice.mBTDevice, false);
                        }
                        break;

                    case MESSAGE_PROCESS_SUPPORTED_PLAYER_APP_SETTING:
                        mRemoteDevice
                            .setSupportedPlayerAppSetting((PlayerApplicationSettings) msg.obj);
                        break;

                    case MESSAGE_PROCESS_PLAYER_APP_SETTING_CHANGED:
                        mRemoteDevice
                            .updatePlayerAppSetting((BluetoothAvrcpPlayerSettings) msg.obj);
                        broadcastPlayerAppSettingChanged(
                            mRemoteDevice.getCurrentPlayerAppSetting());
                        break;

                    default:
                        return false;
                }
            }
            return true;
        }

    }

    // Interface APIs
    boolean isConnected() {
        synchronized (mLock) {
            return mIsConnected;
        }
    }

    void doQuit() {
        try {
            mContext.unregisterReceiver(mBroadcastReceiver);
        } catch (IllegalArgumentException expected) {
            // If the receiver was never registered unregister will throw an
            // IllegalArgumentException.
        }
        quit();
    }

    void dump(StringBuilder sb) {
        ProfileService.println(sb, "StateMachine: " + this.toString());
    }

    MediaMetadata getCurrentMetaData() {
        synchronized (mLock) {
            if (mRemoteDevice != null && mRemoteDevice.getCurrentTrack() != null) {
                return mRemoteDevice.getCurrentTrack().getMediaMetaData();
            }
            return null;
        }

    }

    PlaybackState getCurrentPlayBackState() {
        synchronized (mLock) {
            if (mRemoteDevice == null) {
                return new PlaybackState.Builder().setState(PlaybackState.STATE_ERROR,
                    PlaybackState.PLAYBACK_POSITION_UNKNOWN,0).build();
            }
            return mRemoteDevice.getPlaybackState();
        }
    }

    boolean isPlayerAppSettingSupported(BluetoothAvrcpPlayerSettings desiredSettings) {
        synchronized (mLock) {
            if (mRemoteDevice == null) {
                return false;
            } else {
                return mRemoteDevice.isSettingSupported(desiredSettings);
            }
        }
    }

    BluetoothAvrcpPlayerSettings getPlayerAppSettings() {
        synchronized (mLock) {
            if (mRemoteDevice == null) {
                return null;
            } else {
                return mRemoteDevice.getCurrentPlayerAppSetting();
            }
        }
    }

    // Utility Functions
    private void broadcastMetaDataChanged(MediaMetadata mMetaData) {
        Intent intent = new Intent(BluetoothAvrcpController.ACTION_TRACK_EVENT);
        intent.putExtra(BluetoothAvrcpController.EXTRA_METADATA, mMetaData);
        if (DBG) {
            Log.d(TAG, " broadcastMetaDataChanged = " +
                mMetaData.getDescription());
        }
        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void broadcastPlayBackStateChanged(PlaybackState state) {
        Intent intent = new Intent(BluetoothAvrcpController.ACTION_TRACK_EVENT);
        intent.putExtra(BluetoothAvrcpController.EXTRA_PLAYBACK, state);
        if (DBG) {
            Log.d(TAG, " broadcastPlayBackStateChanged = " + state.toString());
        }
        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void broadcastPlayerAppSettingChanged(BluetoothAvrcpPlayerSettings mPlAppSetting) {
        Intent intent = new Intent(BluetoothAvrcpController.ACTION_PLAYER_SETTING);
        intent.putExtra(BluetoothAvrcpController.EXTRA_PLAYER_SETTING, mPlAppSetting);
        if (DBG) {
            Log.d(TAG, " broadcastPlayerAppSettingChanged = " +
                displayBluetoothAvrcpSettings(mPlAppSetting));
        }
        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void setAbsVolume(int absVol, int label) {
        int maxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        int currIndex = mAudioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        // Ignore first volume command since phone may not know difference between stream volume
        // and amplifier volume.
        if (mRemoteDevice.getFirstAbsVolCmdRecvd()) {
            int newIndex = (maxVolume * absVol) / ABS_VOL_BASE;
            Log.d(TAG,
                " setAbsVolume =" + absVol + " maxVol = " + maxVolume + " cur = " + currIndex +
                    " new = " + newIndex);
            /*
             * In some cases change in percentage is not sufficient enough to warrant
             * change in index values which are in range of 0-15. For such cases
             * no action is required
             */
            if (newIndex != currIndex) {
                mAudioManager.setStreamVolume(AudioManager.STREAM_MUSIC, newIndex,
                    AudioManager.FLAG_SHOW_UI);
            }
        } else {
            mRemoteDevice.setFirstAbsVolCmdRecvd();
            absVol = (currIndex * ABS_VOL_BASE) / maxVolume;
            Log.d(TAG, " SetAbsVol recvd for first time, respond with " + absVol);
        }
        AvrcpControllerService.sendAbsVolRspNative(
            mRemoteDevice.getBluetoothAddress(), absVol, label);
    }

    private int getVolumePercentage() {
        int maxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        int currIndex = mAudioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        int percentageVol = ((currIndex * ABS_VOL_BASE) / maxVolume);
        return percentageVol;
    }

    private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(AudioManager.VOLUME_CHANGED_ACTION)) {
                int streamType = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_TYPE, -1);
                if (streamType == AudioManager.STREAM_MUSIC) {
                    sendMessage(MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION);
                }
            }
        }
    };

    public static String dumpMessageString(int message) {
        String str = "UNKNOWN";
        switch (message) {
            case MESSAGE_SEND_PASS_THROUGH_CMD:
                str = "REQ_PASS_THROUGH_CMD";
                break;
            case MESSAGE_SEND_SET_CURRENT_PLAYER_APPLICATION_SETTINGS:
                str = "REQ_SET_PLAYER_APP_SETTING";
                break;
            case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                str = "REQ_GRP_NAV_CMD";
                break;
            case MESSAGE_PROCESS_SUPPORTED_PLAYER_APP_SETTING:
                str = "CB_SUPPORTED_PLAYER_APP_SETTING";
                break;
            case MESSAGE_PROCESS_PLAYER_APP_SETTING_CHANGED:
                str = "CB_PLAYER_APP_SETTING_CHANGED";
                break;
            case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                str = "CB_SET_ABS_VOL_CMD";
                break;
            case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION:
                str = "CB_REGISTER_ABS_VOL";
                break;
            case MESSAGE_PROCESS_TRACK_CHANGED:
                str = "CB_TRACK_CHANGED";
                break;
            case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                str = "CB_PLAY_POS_CHANGED";
                break;
            case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                str = "CB_PLAY_STATUS_CHANGED";
                break;
            case MESSAGE_PROCESS_RC_FEATURES:
                str = "CB_RC_FEATURES";
                break;
            case MESSAGE_PROCESS_CONNECTION_CHANGE:
                str = "CB_CONN_CHANGED";
                break;
            default:
                str = Integer.toString(message);
                break;
        }
        return str;
    }

    public static String displayBluetoothAvrcpSettings(BluetoothAvrcpPlayerSettings mSett) {
        StringBuffer sb =  new StringBuffer();
        int supportedSetting = mSett.getSettings();
        if(VDBG) Log.d(TAG," setting: " + supportedSetting);
        if((supportedSetting & BluetoothAvrcpPlayerSettings.SETTING_EQUALIZER) != 0) {
            sb.append(" EQ : ");
            sb.append(Integer.toString(mSett.getSettingValue(BluetoothAvrcpPlayerSettings.
                                                             SETTING_EQUALIZER)));
        }
        if((supportedSetting & BluetoothAvrcpPlayerSettings.SETTING_REPEAT) != 0) {
            sb.append(" REPEAT : ");
            sb.append(Integer.toString(mSett.getSettingValue(BluetoothAvrcpPlayerSettings.
                                                             SETTING_REPEAT)));
        }
        if((supportedSetting & BluetoothAvrcpPlayerSettings.SETTING_SHUFFLE) != 0) {
            sb.append(" SHUFFLE : ");
            sb.append(Integer.toString(mSett.getSettingValue(BluetoothAvrcpPlayerSettings.
                                                             SETTING_SHUFFLE)));
        }
        if((supportedSetting & BluetoothAvrcpPlayerSettings.SETTING_SCAN) != 0) {
            sb.append(" SCAN : ");
            sb.append(Integer.toString(mSett.getSettingValue(BluetoothAvrcpPlayerSettings.
                                                             SETTING_SCAN)));
        }
        return sb.toString();
    }





}
