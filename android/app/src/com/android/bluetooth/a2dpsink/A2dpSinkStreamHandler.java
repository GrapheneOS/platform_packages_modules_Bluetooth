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

package com.android.bluetooth.a2dpsink;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.AudioManager.OnAudioFocusChangeListener;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.avrcpcontroller.AvrcpControllerService;
import com.android.bluetooth.R;

/**
 * Bluetooth A2DP SINK Streaming Handler.
 *
 * This handler defines how the stack behaves once the A2DP connection is established and both
 * devices are ready for streaming. For simplification we assume that the connection can either
 * stream music immediately (i.e. data packets coming in or have potential to come in) or it cannot
 * stream (i.e. Idle and Open states are treated alike). See Fig 4-1 of GAVDP Spec 1.0.
 *
 * Note: There are several different audio tracks that a connected phone may like to transmit over
 * the A2DP stream including Music, Navigation, Assistant, and Notifications.  Music is the only
 * track that is almost always accompanied with an AVRCP play/pause command.  The following handler
 * is configurable at compile time through the PLAY_WITHOUT_AVRCP_COMMAND flag to allow all of these
 * audio tracks to be played trough without an explicit play command.
 *
 * Streaming is initiated by either an explicit play command from user interaction or audio coming
 * from the phone.  Streaming is terminated when either the user pauses the audio, the audio stream
 * from the phone ends, the phone disconnects, or audio focus is lost.  During playback if there is
 * a change to audio focus playback may be temporarily paused and then resumed when focus is
 * restored.
 */
final class A2dpSinkStreamHandler extends Handler {
    private static final boolean DBG = false;
    private static final String TAG = "A2dpSinkStreamHandler";

    // Configuration Variables
    private static final int DEFAULT_DUCK_PERCENT = 25;
    // Allows any audio to stream from phone without requiring AVRCP play command,
    // this lets navigation and other non music streams through.
    private static final boolean PLAY_WITHOUT_AVRCP_COMMAND = true;

    // Incoming events.
    public static final int SRC_STR_START = 0;
    public static final int SRC_STR_STOP = 1;
    public static final int ACT_PLAY = 2;
    public static final int ACT_PAUSE = 3;
    public static final int DISCONNECT = 4;
    public static final int UPGRADE_FOCUS = 5;
    public static final int AUDIO_FOCUS_CHANGE = 7;

    // Used to indicate focus lost
    private static final int STATE_FOCUS_LOST = 0;
    // Used to inform bluedroid that focus is granted
    private static final int STATE_FOCUS_GRANTED = 1;
    // Timeout in milliseconds before upgrading a transient audio focus to full focus;
    // This allows notifications and other intermittent sounds from impacting other sources.
    private static final int TRANSIENT_FOCUS_DELAY = 10000; // 10 seconds

    // Private variables.
    private A2dpSinkStateMachine mA2dpSinkSm;
    private Context mContext;
    private AudioManager mAudioManager;
    private AudioAttributes mStreamAttributes;
    // Keep track if play was requested
    private boolean playRequested = false;
    // Keep track if the remote device is providing audio
    private boolean streamAvailable = false;
    // Keep track of the relevant audio focus (None, Transient, Gain)
    private int audioFocus = AudioManager.AUDIOFOCUS_NONE;

    // Focus changes when we are currently holding focus.
    private OnAudioFocusChangeListener mAudioFocusListener = new OnAudioFocusChangeListener() {
        public void onAudioFocusChange(int focusChange) {
            if (DBG) {
                Log.d(TAG, "onAudioFocusChangeListener focuschange " + focusChange);
            }
            A2dpSinkStreamHandler.this.obtainMessage(AUDIO_FOCUS_CHANGE, focusChange)
                    .sendToTarget();
        }
    };

    public A2dpSinkStreamHandler(A2dpSinkStateMachine a2dpSinkSm, Context context) {
        mA2dpSinkSm = a2dpSinkSm;
        mContext = context;
        mAudioManager = (AudioManager) context.getSystemService(Context.AUDIO_SERVICE);
        mStreamAttributes = new AudioAttributes.Builder()
                                    .setUsage(AudioAttributes.USAGE_MEDIA)
                                    .setContentType(AudioAttributes.CONTENT_TYPE_MUSIC)
                                    .build();
    }

    @Override
    public void handleMessage(Message message) {
        if (DBG) {
            Log.d(TAG, " process message: " + message.what);
            Log.d(TAG, " audioFocus =  " + audioFocus + " playRequested = " + playRequested);
        }
        switch (message.what) {
            case SRC_STR_START:
                streamAvailable = true;
                if ((playRequested || PLAY_WITHOUT_AVRCP_COMMAND)
                        && audioFocus == AudioManager.AUDIOFOCUS_NONE) {
                    requestAudioFocus();
                }
                break;

            case SRC_STR_STOP:
                streamAvailable = false;
                if (audioFocus != AudioManager.AUDIOFOCUS_NONE) {
                    abandonAudioFocus();
                }
                break;

            case ACT_PLAY:
                playRequested = true;
                startAvrcpUpdates();
                if (streamAvailable && audioFocus == AudioManager.AUDIOFOCUS_NONE) {
                    requestAudioFocus();
                }
                break;

            case ACT_PAUSE:
                playRequested = false;
                stopAvrcpUpdates();
                break;

            case DISCONNECT:
                playRequested = false;
                sendAvrcpPause();
                stopAvrcpUpdates();
                stopFluorideStreaming();
                abandonAudioFocus();
                break;

            case UPGRADE_FOCUS:
                upgradeAudioFocus();
                break;

            case AUDIO_FOCUS_CHANGE:
                // message.obj is the newly granted audio focus.
                switch ((int) message.obj) {
                    case AudioManager.AUDIOFOCUS_GAIN_TRANSIENT:
                        setFluorideAudioTrackGain(1.0f);
                        sendMessageDelayed(obtainMessage(UPGRADE_FOCUS), TRANSIENT_FOCUS_DELAY);
                        // Begin playing audio
                        if (audioFocus == AudioManager.AUDIOFOCUS_NONE) {
                            audioFocus = (int) message.obj;
                            startAvrcpUpdates();
                            startFluorideStreaming();
                        }
                        break;

                    case AudioManager.AUDIOFOCUS_GAIN:
                        setFluorideAudioTrackGain(1.0f);
                        // Begin playing audio
                        if (audioFocus == AudioManager.AUDIOFOCUS_NONE) {
                            audioFocus = (int) message.obj;
                            startAvrcpUpdates();
                            startFluorideStreaming();
                        }
                        break;

                    case AudioManager.AUDIOFOCUS_LOSS_TRANSIENT_CAN_DUCK:
                        // Make the volume duck.
                        int duckPercent = mContext.getResources().getInteger(
                                R.integer.a2dp_sink_duck_percent);
                        if (duckPercent < 0 || duckPercent > 100) {
                            Log.e(TAG, "Invalid duck percent using default.");
                            duckPercent = DEFAULT_DUCK_PERCENT;
                        }
                        float duckRatio = (duckPercent / 100.0f);
                        if (DBG) {
                            Log.d(TAG, "Setting reduce gain on transient loss gain=" + duckRatio);
                        }
                        setFluorideAudioTrackGain(duckRatio);
                        removeMessages(UPGRADE_FOCUS);
                        break;

                    case AudioManager.AUDIOFOCUS_LOSS_TRANSIENT:
                        stopFluorideStreaming();
                        removeMessages(UPGRADE_FOCUS);
                        break;

                    case AudioManager.AUDIOFOCUS_LOSS:
                        abandonAudioFocus();
                        sendAvrcpPause();
                        stopAvrcpUpdates();
                        stopFluorideStreaming();
                        break;
                }
                break;

            default:
                Log.w(TAG, "Received unexpected event: " + message.what);
        }
    }

    /**
     * Utility functions.
     */
    private int requestAudioFocus() {
        int focusRequestStatus = mAudioManager.requestAudioFocus(mAudioFocusListener,
                mStreamAttributes, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT,
                AudioManager.AUDIOFOCUS_FLAG_DELAY_OK);
        // If the request is granted begin streaming immediately and schedule an upgrade.
        if (focusRequestStatus == AudioManager.AUDIOFOCUS_REQUEST_GRANTED) {
            startAvrcpUpdates();
            setFluorideAudioTrackGain(1.0f);
            startFluorideStreaming();
            audioFocus = AudioManager.AUDIOFOCUS_GAIN_TRANSIENT;
            sendMessageDelayed(obtainMessage(UPGRADE_FOCUS), TRANSIENT_FOCUS_DELAY);
        }
        return focusRequestStatus;
    }

    private boolean upgradeAudioFocus() {
        return (mAudioManager.requestAudioFocus(mAudioFocusListener, AudioManager.STREAM_MUSIC,
                        AudioManager.AUDIOFOCUS_GAIN)
                == AudioManager.AUDIOFOCUS_REQUEST_GRANTED);
    }

    private void abandonAudioFocus() {
        removeMessages(UPGRADE_FOCUS);
        stopAvrcpUpdates();
        stopFluorideStreaming();
        mAudioManager.abandonAudioFocus(mAudioFocusListener);
        audioFocus = AudioManager.AUDIOFOCUS_NONE;
    }

    private void startFluorideStreaming() {
        mA2dpSinkSm.informAudioFocusStateNative(STATE_FOCUS_GRANTED);
        mA2dpSinkSm.informAudioTrackGainNative(1.0f);
    }

    private void stopFluorideStreaming() {
        mA2dpSinkSm.informAudioFocusStateNative(STATE_FOCUS_LOST);
    }

    private void setFluorideAudioTrackGain(float gain) {
        mA2dpSinkSm.informAudioTrackGainNative(gain);
    }

    private void startAvrcpUpdates() {
        // Since AVRCP gets started after A2DP we may need to request it later in cycle.
        AvrcpControllerService avrcpService = AvrcpControllerService.getAvrcpControllerService();

        if (DBG) {
            Log.d(TAG, "startAvrcpUpdates");
        }
        if (avrcpService != null && avrcpService.getConnectedDevices().size() == 1) {
            avrcpService.startAvrcpUpdates();
        } else {
            Log.e(TAG, "startAvrcpUpdates failed because of connection.");
        }
    }

    private void stopAvrcpUpdates() {
        // Since AVRCP gets started after A2DP we may need to request it later in cycle.
        AvrcpControllerService avrcpService = AvrcpControllerService.getAvrcpControllerService();

        if (DBG) {
            Log.d(TAG, "stopAvrcpUpdates");
        }
        if (avrcpService != null && avrcpService.getConnectedDevices().size() == 1) {
            avrcpService.stopAvrcpUpdates();
        } else {
            Log.e(TAG, "stopAvrcpUpdates failed because of connection.");
        }
    }

    private void sendAvrcpPause() {
        // Since AVRCP gets started after A2DP we may need to request it later in cycle.
        AvrcpControllerService avrcpService = AvrcpControllerService.getAvrcpControllerService();

        if (DBG) {
            Log.d(TAG, "sendAvrcpPause");
        }
        if (avrcpService != null && avrcpService.getConnectedDevices().size() == 1) {
            if (DBG) {
                Log.d(TAG, "Pausing AVRCP.");
            }
            avrcpService.sendPassThroughCmd(avrcpService.getConnectedDevices().get(0),
                    AvrcpControllerService.PASS_THRU_CMD_ID_PAUSE,
                    AvrcpControllerService.KEY_STATE_PRESSED);
            avrcpService.sendPassThroughCmd(avrcpService.getConnectedDevices().get(0),
                    AvrcpControllerService.PASS_THRU_CMD_ID_PAUSE,
                    AvrcpControllerService.KEY_STATE_RELEASED);
        } else {
            Log.e(TAG, "Passthrough not sent, connection un-available.");
        }
    }
}
