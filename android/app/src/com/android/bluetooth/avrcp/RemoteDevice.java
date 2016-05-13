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

import android.bluetooth.BluetoothAvrcpPlayerSettings;
import android.bluetooth.BluetoothDevice;
import android.media.session.PlaybackState;

import com.android.bluetooth.Utils;

import java.util.ArrayList;
import java.nio.ByteBuffer;

/*
 * Contains information about remote device specifically the player and features enabled on it along
 * with an encapsulation of the current track and playlist information.
 */
class RemoteDevice {

    /*
     * Remote features from JNI
     */
    private static final int FEAT_NONE = 0;
    private static final int FEAT_METADATA = 1;
    private static final int FEAT_ABSOLUTE_VOLUME = 2;
    private static final int FEAT_BROWSE = 4;

    private static final int VOLUME_LABEL_UNDEFINED = -1;

    final BluetoothDevice mBTDevice;
    private int mRemoteFeatures;
    private boolean mAbsVolNotificationRequested;
    private boolean mFirstAbsVolCmdRecvd;
    private int mNotificationLabel;
    private ArrayList<TrackInfo> mPlaylist = new ArrayList<TrackInfo>();
    private TrackInfo mCurrentTrack = new TrackInfo();
    private PlayerInfo mAddressedPlayer = new PlayerInfo();

    RemoteDevice(BluetoothDevice mDevice) {
        mBTDevice = mDevice;
        mRemoteFeatures = FEAT_NONE;
        mAbsVolNotificationRequested = false;
        mNotificationLabel = VOLUME_LABEL_UNDEFINED;
        mFirstAbsVolCmdRecvd = false;
    }

    synchronized void setRemoteFeatures(int remoteFeatures) {
        mRemoteFeatures = remoteFeatures;
    }

    synchronized public boolean isBrowsingSupported() {
        return ((mRemoteFeatures & FEAT_BROWSE) != 0);
    }

    synchronized public boolean isMetaDataSupported() {
        return ((mRemoteFeatures & FEAT_METADATA) != 0);
    }

    synchronized public boolean isSubscribedToAbsoluteVolume() {
        return ((mRemoteFeatures & FEAT_ABSOLUTE_VOLUME) != 0);
    }

    synchronized public void setSupportedPlayerAppSetting(PlayerApplicationSettings featureSet) {
        mAddressedPlayer.setSupportedPlayerAppSetting(featureSet);
    }

    synchronized public void updatePlayerAppSetting(BluetoothAvrcpPlayerSettings settingsToSet) {
        mAddressedPlayer.updatePlayerAppSetting(settingsToSet);
    }

    synchronized public BluetoothAvrcpPlayerSettings getCurrentPlayerAppSetting() {
        return mAddressedPlayer.getSupportedPlayerAppSetting();
    }

    synchronized public boolean isSettingSupported(BluetoothAvrcpPlayerSettings settingsToCheck) {
        return mAddressedPlayer.isPlayerAppSettingSupported(settingsToCheck);
    }

    synchronized public void updateCurrentTrack(TrackInfo update) {
        mCurrentTrack = update;
    }

    synchronized public TrackInfo getCurrentTrack() {
        return mCurrentTrack;
    }

    synchronized public void setPlayStatus(int status) {
        mAddressedPlayer.mPlayStatus = status;
    }

    synchronized public int getPlayerStatus() {
        return mAddressedPlayer.mPlayStatus;
    }

    synchronized public void setPlayerPosition(int time) {
        mAddressedPlayer.mPlayTime = time;
    }

    synchronized public long getPlayerPosition() {
        return mAddressedPlayer.mPlayTime;
    }

    synchronized public void setAddressedPlayer(PlayerInfo mPlayer) {
        mAddressedPlayer = mPlayer;
    }

    synchronized public PlaybackState getPlaybackState() {
        return mAddressedPlayer.getPlaybackState();
    }

    synchronized public byte[] getBluetoothAddress() {
        return Utils.getByteAddress(mBTDevice);
    }

    synchronized public void setNotificationLabel(int label) {
        mNotificationLabel = label;
    }

    synchronized public int getNotificationLabel() {
        return mNotificationLabel;
    }

    synchronized public void setAbsVolNotificationRequested(boolean request) {
        mAbsVolNotificationRequested = request;
    }

    synchronized public boolean getAbsVolNotificationRequested() {
        return mAbsVolNotificationRequested;
    }

    synchronized public void setFirstAbsVolCmdRecvd() {
        mFirstAbsVolCmdRecvd = true;
    }

    synchronized public boolean getFirstAbsVolCmdRecvd() {
        return mFirstAbsVolCmdRecvd;
    }
}
