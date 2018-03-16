/*
 * Copyright 2018 The Android Open Source Project
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

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.os.Looper;
import android.util.Log;

import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.btservice.ProfileService;

import java.util.List;
import java.util.Objects;

/**
 * Provides Bluetooth AVRCP Target profile as a service in the Bluetooth application.
 * @hide
 */
public class AvrcpTargetService extends ProfileService {
    private static final String TAG = "NewAvrcpTargetService";
    private static final boolean DEBUG = true;

    private static final int AVRCP_MAX_VOL = 127;
    private static int sDeviceMaxVolume = 0;

    private MediaPlayerList mMediaPlayerList;
    private AudioManager mAudioManager;
    private AvrcpBroadcastReceiver mReceiver;
    private AvrcpNativeInterface mNativeInterface;

    // Only used to see if the metadata has changed from its previous value
    private MediaData mCurrentData;

    private static AvrcpTargetService sInstance = null;

    private class ListCallback implements MediaPlayerList.MediaUpdateCallback {
        @Override
        public void run(MediaData data) {
            boolean metadata = !Objects.equals(mCurrentData.metadata, data.metadata);
            boolean state = !MediaPlayerWrapper.playstateEquals(mCurrentData.state, data.state);
            boolean queue = !Objects.equals(mCurrentData.queue, data.queue);

            if (DEBUG) {
                Log.d(TAG, "onMediaUpdated: track_changed=" + metadata
                        + " state=" + state + " queue=" + queue);
            }
            mCurrentData = data;

            mNativeInterface.sendMediaUpdate(metadata, state, queue);
        }
    }

    private class AvrcpBroadcastReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED)) {
                // Update all the playback status info for each connected device
                mNativeInterface.sendMediaUpdate(false, true, false);
            }
        }
    }

    /**
     * Get the AvrcpTargetService instance. Returns null if the service hasn't been started yet.
     */
    public static AvrcpTargetService get() {
        return sInstance;
    }

    @Override
    public String getName() {
        return TAG;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return null;
    }

    @Override
    protected void setUserUnlocked(int userId) {
        Log.i(TAG, "User unlocked, initializing the service");
        init();
    }

    @Override
    protected boolean start() {
        Log.i(TAG, "Starting the AVRCP Target Service");
        sInstance = this;
        mCurrentData = new MediaData(null, null, null);
        mNativeInterface = AvrcpNativeInterface.getInterface();

        mReceiver = new AvrcpBroadcastReceiver();
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED);
        registerReceiver(mReceiver, filter);

        return true;
    }

    @Override
    protected boolean stop() {
        Log.i(TAG, "Stopping the AVRCP Target Service");

        sInstance = null;
        unregisterReceiver(mReceiver);

        // We check the interfaces first since they only get set on User Unlocked
        if (mMediaPlayerList != null) mMediaPlayerList.cleanup();
        if (mNativeInterface != null) mNativeInterface.cleanup();

        mMediaPlayerList = null;
        mNativeInterface = null;
        mAudioManager = null;
        mReceiver = null;
        return true;
    }

    private void init() {
        if (mMediaPlayerList != null) {
            Log.wtfStack(TAG, "init: The service has already been initialized");
            return;
        }

        mAudioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
        sDeviceMaxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);

        mMediaPlayerList = new MediaPlayerList();
        mMediaPlayerList.init(Looper.myLooper(), this, new ListCallback());
        mNativeInterface.init(AvrcpTargetService.this);
    }

    void deviceConnected(String bdaddr, boolean absoluteVolume) {
        Log.i(TAG, "deviceConnected: bdaddr=" + bdaddr + " absoluteVolume=" + absoluteVolume);
        mAudioManager.avrcpSupportsAbsoluteVolume(bdaddr, absoluteVolume);
    }

    void deviceDisconnected(String bdaddr) {
        // Do nothing
    }

    // TODO (apanicke): Add checks to blacklist Absolute Volume devices if they behave poorly.
    void setVolume(int avrcpVolume) {
        int deviceVolume =
                (int) Math.floor((double) avrcpVolume * sDeviceMaxVolume / AVRCP_MAX_VOL);
        if (DEBUG) {
            Log.d(TAG, "SendVolumeChanged: avrcpVolume=" + avrcpVolume
                    + " deviceVolume=" + deviceVolume
                    + " sDeviceMaxVolume=" + sDeviceMaxVolume);
        }
        mAudioManager.setStreamVolume(AudioManager.STREAM_MUSIC, deviceVolume,
                AudioManager.FLAG_SHOW_UI | AudioManager.FLAG_BLUETOOTH_ABS_VOLUME);
    }

    /**
     * Set the volume on the remote device. Does nothing if the device doesn't support absolute
     * volume.
     */
    public void sendVolumeChanged(int deviceVolume) {
        int avrcpVolume =
                (int) Math.floor((double) deviceVolume * AVRCP_MAX_VOL / sDeviceMaxVolume);
        if (avrcpVolume > 127) avrcpVolume = 127;
        if (DEBUG) {
            Log.d(TAG, "SendVolumeChanged: avrcpVolume=" + avrcpVolume
                    + " deviceVolume=" + deviceVolume
                    + " sDeviceMaxVolume=" + sDeviceMaxVolume);
        }
        mNativeInterface.sendVolumeChanged(avrcpVolume);
    }

    Metadata getCurrentSongInfo() {
        return mMediaPlayerList.getCurrentSongInfo();
    }

    PlayStatus getPlayState() {
        return PlayStatus.fromPlaybackState(mMediaPlayerList.getCurrentPlayStatus(),
                Long.parseLong(getCurrentSongInfo().duration));
    }

    String getCurrentMediaId() {
        String id = mMediaPlayerList.getCurrentMediaId();
        if (id != null) return id;

        Metadata song = getCurrentSongInfo();
        if (song != null) return song.mediaId;

        // We always want to return something, the error string just makes debugging easier
        return "error";
    }

    List<Metadata> getNowPlayingList() {
        return mMediaPlayerList.getNowPlayingList();
    }

    int getCurrentPlayerId() {
        return mMediaPlayerList.getCurrentPlayerId();
    }

    // TODO (apanicke): Have the Player List also contain info about the play state of each player
    List<PlayerInfo> getMediaPlayerList() {
        return mMediaPlayerList.getMediaPlayerList();
    }

    void getPlayerRoot(int playerId, MediaPlayerList.GetPlayerRootCallback cb) {
        mMediaPlayerList.getPlayerRoot(playerId, cb);
    }

    void getFolderItems(int playerId, String mediaId, MediaPlayerList.GetFolderItemsCallback cb) {
        mMediaPlayerList.getFolderItems(playerId, mediaId, cb);
    }

    void playItem(int playerId, boolean nowPlaying, String mediaId) {
        // NOTE: playerId isn't used if nowPlaying is true, since its assumed to be the current
        // active player
        mMediaPlayerList.playItem(playerId, nowPlaying, mediaId);
    }

    // TODO (apanicke): Handle key events here in the service. Currently it was more convenient to
    // handle them there but logically they make more sense handled here.
    void sendMediaKeyEvent(int event, int state) {
        if (DEBUG) Log.d(TAG, "getMediaKeyEvent: event=" + event + " state=" + state);
        mMediaPlayerList.sendMediaKeyEvent(event, state);
    }

    void setActiveDevice(String address) {
        Log.i(TAG, "setActiveDevice: address=" + address);
        BluetoothDevice d =
                BluetoothAdapter.getDefaultAdapter().getRemoteDevice(address.toUpperCase());
        if (d == null) {
            Log.wtfStack(TAG, "setActiveDevice: could not find device with address " + address);
        }
        A2dpService.getA2dpService().setActiveDevice(d);
    }

    /**
     * Dump debugging information to the string builder
     */
    public void dump(StringBuilder sb) {
        mMediaPlayerList.dump(sb);
    }
}
