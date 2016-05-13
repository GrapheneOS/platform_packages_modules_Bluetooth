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
import android.media.session.PlaybackState;
import android.util.Log;

import java.util.ArrayList;

/*
 * Contains information about remote player
 */
class PlayerInfo {


    private static final String TAG = "PlayerInfo";
    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);

    int mPlayStatus = PlaybackState.STATE_NONE;
    long mPlayTime   = PlaybackState.PLAYBACK_POSITION_UNKNOWN;

    PlayerApplicationSettings mPlayerAppSetting =
        new PlayerApplicationSettings();

    public void setSupportedPlayerAppSetting(PlayerApplicationSettings supportedSettings) {
        mPlayerAppSetting = supportedSettings;
    }

    public void updatePlayerAppSetting(BluetoothAvrcpPlayerSettings settingValues) {
        mPlayerAppSetting.setValues(settingValues);
    }

    public BluetoothAvrcpPlayerSettings getSupportedPlayerAppSetting() {
        return mPlayerAppSetting.getAvrcpSettings();
    }

    public PlaybackState getPlaybackState() {
        long position = mPlayTime;
        float speed = 1;
        switch (mPlayStatus) {
            case PlaybackState.STATE_STOPPED:
                position = 0;
                speed = 0;
                break;
            case PlaybackState.STATE_PAUSED:
                speed = 0;
                break;
            case PlaybackState.STATE_FAST_FORWARDING:
                speed = 3;
                break;
            case PlaybackState.STATE_REWINDING:
                speed = -3;
                break;
        }
        return new PlaybackState.Builder().setState(mPlayStatus, position, speed).build();
    }

   /*
     * Checks if current setting is supported by remote.
     * input would be in form of flattened strucuture <id,val>
     */
    public boolean isPlayerAppSettingSupported(BluetoothAvrcpPlayerSettings desiredSettings) {
        return mPlayerAppSetting.supportsSettings(desiredSettings);
    }
}
