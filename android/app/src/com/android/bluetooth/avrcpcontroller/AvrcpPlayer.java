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

package com.android.bluetooth.avrcpcontroller;

import android.media.session.PlaybackState;
import android.util.Log;

import java.util.Arrays;

/*
 * Contains information about remote player
 */
class AvrcpPlayer {
    private static final String TAG = "AvrcpPlayer";
    private static final boolean DBG = false;
    private static final boolean VDBG = false;

    public static final int INVALID_ID = -1;

    public static final int FEATURE_PLAY = 40;
    public static final int FEATURE_STOP = 41;
    public static final int FEATURE_PAUSE = 42;
    public static final int FEATURE_REWIND = 44;
    public static final int FEATURE_FAST_FORWARD = 45;
    public static final int FEATURE_FORWARD = 47;
    public static final int FEATURE_PREVIOUS = 48;
    public static final int FEATURE_BROWSING = 59;

    private int mPlayStatus = PlaybackState.STATE_NONE;
    private long mPlayTime = PlaybackState.PLAYBACK_POSITION_UNKNOWN;
    private int mId;
    private String mName = "";
    private int mPlayerType;
    private byte[] mPlayerFeatures;
    private long mAvailableActions;
    private TrackInfo mCurrentTrack = new TrackInfo();

    AvrcpPlayer() {
        mId = INVALID_ID;
        //Set Default Actions in case Player data isn't available.
        mAvailableActions = PlaybackState.ACTION_PAUSE | PlaybackState.ACTION_PLAY
            | PlaybackState.ACTION_SKIP_TO_NEXT | PlaybackState.ACTION_SKIP_TO_PREVIOUS
            | PlaybackState.ACTION_STOP;
    }

    AvrcpPlayer(int id, String name, byte[] playerFeatures, int playStatus, int playerType) {
        mId = id;
        mName = name;
        mPlayStatus = playStatus;
        mPlayerType = playerType;
        mPlayerFeatures = Arrays.copyOf(playerFeatures, playerFeatures.length);
        updateAvailableActions();
    }

    public int getId() {
        return mId;
    }

    public String getName() {
        return mName;
    }

    public void setPlayTime(int playTime) {
        mPlayTime = playTime;
    }

    public long getPlayTime() {
        return mPlayTime;
    }

    public void setPlayStatus(int playStatus) {
        mPlayStatus = playStatus;
    }

    public int getPlayStatus() {
        return mPlayStatus;
    }

    public boolean supportsFeature(int featureId) {
        int byteNumber = featureId / 8;
        byte bitMask = (byte) (1 << (featureId % 8));
        return (mPlayerFeatures[byteNumber] & bitMask) == bitMask;
    }

    public PlaybackState getPlaybackState() {
        if (DBG) {
            Log.d(TAG, "getPlayBackState state " + mPlayStatus + " time " + mPlayTime);
        }

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
        return new PlaybackState.Builder().setState(mPlayStatus, position, speed)
            .setActions(mAvailableActions).setActiveQueueItemId(mCurrentTrack.mTrackNum - 1)
            .build();
    }

    public synchronized boolean updateCurrentTrack(TrackInfo update) {
        if (update != null && mCurrentTrack != null
                && update.toString().equals(mCurrentTrack.toString())) {
            if (DBG) Log.d(TAG, "Update same as original");
            return false;
        }
        if (VDBG) Log.d(TAG, "Track Changed Was:" + mCurrentTrack + "now " + update);
        mCurrentTrack = update;
        return true;
    }

    public synchronized TrackInfo getCurrentTrack() {
        return mCurrentTrack;
    }

    private void updateAvailableActions() {
        if (supportsFeature(FEATURE_PLAY)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_PLAY;
        }
        if (supportsFeature(FEATURE_STOP)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_STOP;
        }
        if (supportsFeature(FEATURE_PAUSE)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_PAUSE;
        }
        if (supportsFeature(FEATURE_REWIND)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_REWIND;
        }
        if (supportsFeature(FEATURE_FAST_FORWARD)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_FAST_FORWARD;
        }
        if (supportsFeature(FEATURE_FORWARD)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_SKIP_TO_NEXT;
        }
        if (supportsFeature(FEATURE_PREVIOUS)) {
            mAvailableActions = mAvailableActions | PlaybackState.ACTION_SKIP_TO_PREVIOUS;
        }
        if (DBG) Log.d(TAG, "Supported Actions = " + mAvailableActions);
    }
}
