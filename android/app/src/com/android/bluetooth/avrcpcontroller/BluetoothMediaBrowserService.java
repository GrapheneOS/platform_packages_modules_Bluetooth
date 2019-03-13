/*
 * Copyright (C) 2015 The Android Open Source Project
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

import android.bluetooth.BluetoothAvrcpController;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.MediaPlayer;
import android.media.browse.MediaBrowser;
import android.media.browse.MediaBrowser.MediaItem;
import android.media.session.MediaController;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.service.media.MediaBrowserService;
import android.util.Log;
import android.util.Pair;

import com.android.bluetooth.R;
import com.android.bluetooth.a2dpsink.A2dpSinkService;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implements the MediaBrowserService interface to AVRCP and A2DP
 *
 * This service provides a means for external applications to access A2DP and AVRCP.
 * The applications are expected to use MediaBrowser (see API) and all the music
 * browsing/playback/metadata can be controlled via MediaBrowser and MediaController.
 *
 * The current behavior of MediaSession exposed by this service is as follows:
 * 1. MediaSession is active (i.e. SystemUI and other overview UIs can see updates) when device is
 * connected and first starts playing. Before it starts playing we do not active the session.
 * 1.1 The session is active throughout the duration of connection.
 * 2. The session is de-activated when the device disconnects. It will be connected again when (1)
 * happens.
 */
public class BluetoothMediaBrowserService extends MediaBrowserService {
    private static final String TAG = "BluetoothMediaBrowserService";
    private static final boolean DBG = false;
    private static final boolean VDBG = false;

    private static final String UNKNOWN_BT_AUDIO = "__UNKNOWN_BT_AUDIO__";
    private static final float PLAYBACK_SPEED = 1.0f;

    // Message sent when A2DP device is disconnected.
    private static final int MSG_DEVICE_DISCONNECT = 0;
    // Message sent when A2DP device is connected.
    private static final int MSG_DEVICE_CONNECT = 2;
    // Message sent when we recieve a TRACK update from AVRCP profile over a connected A2DP device.
    private static final int MSG_TRACK = 4;
    // Internal message sent to trigger a AVRCP action.
    private static final int MSG_AVRCP_PASSTHRU = 5;
    // Internal message to trigger a getplaystatus command to remote.
    private static final int MSG_AVRCP_GET_PLAY_STATUS_NATIVE = 6;
    // Message sent when AVRCP browse is connected.
    private static final int MSG_DEVICE_BROWSE_CONNECT = 7;
    // Message sent when AVRCP browse is disconnected.
    private static final int MSG_DEVICE_BROWSE_DISCONNECT = 8;
    // Message sent when folder list is fetched.
    private static final int MSG_FOLDER_LIST = 9;

    // Custom actions for PTS testing.
    private static final String CUSTOM_ACTION_VOL_UP =
            "com.android.bluetooth.avrcpcontroller.CUSTOM_ACTION_VOL_UP";
    private static final String CUSTOM_ACTION_VOL_DN =
            "com.android.bluetooth.avrcpcontroller.CUSTOM_ACTION_VOL_DN";
    private static final String CUSTOM_ACTION_GET_PLAY_STATUS_NATIVE =
            "com.android.bluetooth.avrcpcontroller.CUSTOM_ACTION_GET_PLAY_STATUS_NATIVE";

    private static BluetoothMediaBrowserService sBluetoothMediaBrowserService;

    // In order to be considered as an audio source capable of receiving media key events (In the
    // eyes of MediaSessionService), we need an active MediaPlayer in addition to a MediaSession.
    // Because of this, the media player below plays an incredibly short, silent audio sample so
    // that MediaSessionService and AudioPlaybackStateMonitor will believe that we're the current
    // active player and send us media events. This is a restriction currently imposed by the media
    // framework code and could be reconsidered in the future.
    private MediaSession mSession;
    private MediaMetadata mA2dpMetadata;
    private MediaPlayer mMediaPlayer;

    private AvrcpControllerService mAvrcpCtrlSrvc;
    private boolean mBrowseConnected = false;
    private BluetoothDevice mA2dpDevice = null;
    private A2dpSinkService mA2dpSinkService = null;
    private Handler mAvrcpCommandQueue;
    private final Map<String, Result<List<MediaItem>>> mParentIdToRequestMap = new HashMap<>();
    private int mCurrentlyHeldKey = 0;

    // Browsing related structures.
    private List<MediaSession.QueueItem> mMediaQueue = new ArrayList<>();

    private static final class AvrcpCommandQueueHandler extends Handler {
        WeakReference<BluetoothMediaBrowserService> mInst;

        AvrcpCommandQueueHandler(Looper looper, BluetoothMediaBrowserService sink) {
            super(looper);
            mInst = new WeakReference<BluetoothMediaBrowserService>(sink);
        }

        @Override
        public void handleMessage(Message msg) {
            BluetoothMediaBrowserService inst = mInst.get();
            if (inst == null) {
                Log.e(TAG, "Parent class has died; aborting.");
                return;
            }

            switch (msg.what) {
                case MSG_DEVICE_CONNECT:
                    inst.msgDeviceConnect((BluetoothDevice) msg.obj);
                    break;
                case MSG_DEVICE_DISCONNECT:
                    inst.msgDeviceDisconnect((BluetoothDevice) msg.obj);
                    break;
                case MSG_TRACK:
                    Pair<PlaybackState, MediaMetadata> pair =
                            (Pair<PlaybackState, MediaMetadata>) (msg.obj);
                    inst.msgTrack(pair.first, pair.second);
                    break;
                case MSG_AVRCP_PASSTHRU:
                    inst.msgPassThru((int) msg.obj);
                    break;
                case MSG_AVRCP_GET_PLAY_STATUS_NATIVE:
                    inst.msgGetPlayStatusNative();
                    break;
                case MSG_DEVICE_BROWSE_CONNECT:
                    inst.msgDeviceBrowseConnect((BluetoothDevice) msg.obj);
                    break;
                case MSG_DEVICE_BROWSE_DISCONNECT:
                    inst.msgDeviceBrowseDisconnect((BluetoothDevice) msg.obj);
                    break;
                case MSG_FOLDER_LIST:
                    inst.msgFolderList((Intent) msg.obj);
                    break;
                default:
                    Log.e(TAG, "Message not handled " + msg);
            }
        }
    }

    /**
     * Initialize this BluetoothMediaBrowserService, creating our MediaSession, MediaPlayer and
     * MediaMetaData, and setting up mechanisms to talk with the AvrcpControllerService.
     */
    @Override
    public void onCreate() {
        if (DBG) Log.d(TAG, "onCreate");
        super.onCreate();

        // Create and configure the MediaSession
        mSession = new MediaSession(this, TAG);
        mSession.setCallback(mSessionCallbacks);
        mSession.setFlags(MediaSession.FLAG_HANDLES_MEDIA_BUTTONS
                | MediaSession.FLAG_HANDLES_TRANSPORT_CONTROLS);
        mSession.setQueueTitle(getString(R.string.bluetooth_a2dp_sink_queue_name));
        mSession.setQueue(mMediaQueue);

        // Create and setup the MediaPlayer
        initMediaPlayer();

        // Associate the held MediaSession with this browser and activate it
        setSessionToken(mSession.getSessionToken());
        mSession.setActive(true);

        // Internal handler to process events and requests
        mAvrcpCommandQueue = new AvrcpCommandQueueHandler(Looper.getMainLooper(), this);

        // Set the initial Media state (sets current playback state and media meta data)
        refreshInitialPlayingState();

        // Set up communication with the controller service
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(AvrcpControllerService.ACTION_BROWSE_CONNECTION_STATE_CHANGED);
        filter.addAction(AvrcpControllerService.ACTION_TRACK_EVENT);
        filter.addAction(AvrcpControllerService.ACTION_FOLDER_LIST);
        registerReceiver(mBtReceiver, filter);

        synchronized (this) {
            mParentIdToRequestMap.clear();
        }

        setBluetoothMediaBrowserService(this);
    }

    /**
     * Clean up this instance in the reverse order that we created it.
     */
    @Override
    public void onDestroy() {
        if (DBG) Log.d(TAG, "onDestroy");
        setBluetoothMediaBrowserService(null);
        unregisterReceiver(mBtReceiver);
        destroyMediaPlayer();
        mSession.release();
        super.onDestroy();
    }

    /**
     * Initializes the silent MediaPlayer object which aids in receiving media key focus.
     *
     * The created MediaPlayer is already prepared and will release and stop itself on error. All
     * you need to do is start() it.
     */
    private void initMediaPlayer() {
        if (DBG) Log.d(TAG, "initMediaPlayer()");

        // Parameters for create
        AudioAttributes attrs = new AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_MEDIA)
                .build();
        AudioManager am = getSystemService(AudioManager.class);

        // Create our player object. Returns a prepared player on success, null on failure
        mMediaPlayer = MediaPlayer.create(this, R.raw.silent, attrs, am.generateAudioSessionId());
        if (mMediaPlayer == null) {
            Log.e(TAG, "Failed to initialize media player. You may not get media key events");
            return;
        }

        // Set other player attributes
        mMediaPlayer.setLooping(false);
        mMediaPlayer.setOnErrorListener((mp, what, extra) -> {
            Log.e(TAG, "Silent media player error: " + what + ", " + extra);
            destroyMediaPlayer();
            return false;
        });
    }

    /**
     * Safely tears down our local MediaPlayer
     */
    private void destroyMediaPlayer() {
        if (DBG) Log.d(TAG, "destroyMediaPlayer()");
        if (mMediaPlayer == null) {
            return;
        }
        mMediaPlayer.stop();
        mMediaPlayer.release();
        mMediaPlayer = null;
    }

    /**
     * Uses the internal MediaPlayer to play a silent, short audio sample so that AudioService will
     * treat us as the active MediaSession/MediaPlayer combo and properly route us media key events.
     *
     * If the MediaPlayer failed to initialize properly, this call will fail gracefully and log the
     * failed attempt. Media keys will not be routed.
     */
    private void getMediaKeyFocus() {
        if (DBG) Log.d(TAG, "getMediaKeyFocus()");
        if (mMediaPlayer == null) {
            Log.w(TAG, "Media player is null. Can't get media key focus. Media keys may not route");
            return;
        }
        mMediaPlayer.start();
    }

    /**
     *  getBluetoothMediaBrowserService()
     *  Routine to get direct access to MediaBrowserService from within the same process.
     */
    public static synchronized BluetoothMediaBrowserService getBluetoothMediaBrowserService() {
        if (sBluetoothMediaBrowserService == null) {
            Log.w(TAG, "getBluetoothMediaBrowserService(): service is NULL");
            return null;
        }
        if (DBG) {
            Log.d(TAG, "getBluetoothMediaBrowserService(): returning "
                    + sBluetoothMediaBrowserService);
        }
        return sBluetoothMediaBrowserService;
    }

    private static synchronized void setBluetoothMediaBrowserService(
            BluetoothMediaBrowserService instance) {
        if (DBG) Log.d(TAG, "setBluetoothMediaBrowserService(): set to: " + instance);
        sBluetoothMediaBrowserService = instance;
    }

    @Override
    public BrowserRoot onGetRoot(String clientPackageName, int clientUid, Bundle rootHints) {
        if (DBG) Log.d(TAG, "onGetRoot");
        return new BrowserRoot(BrowseTree.ROOT, null);
    }

    @Override
    public synchronized void onLoadChildren(final String parentMediaId,
            final Result<List<MediaItem>> result) {
        if (mAvrcpCtrlSrvc == null) {
            Log.w(TAG, "AVRCP not yet connected.");
            result.sendResult(Collections.emptyList());
            return;
        }

        if (DBG) Log.d(TAG, "onLoadChildren parentMediaId=" + parentMediaId);
        List<MediaItem> contents = mAvrcpCtrlSrvc.getContents(mA2dpDevice, parentMediaId);
        if (contents == null) {
            mParentIdToRequestMap.put(parentMediaId, result);
            result.detach();
        } else {
            result.sendResult(contents);
        }

        return;
    }

    @Override
    public void onLoadItem(String itemId, Result<MediaBrowser.MediaItem> result) {
    }

    // Media Session Stuff.
    private MediaSession.Callback mSessionCallbacks = new MediaSession.Callback() {
        @Override
        public void onPlay() {
            if (DBG) Log.d(TAG, "onPlay");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_PLAY).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onPause() {
            if (DBG) Log.d(TAG, "onPause");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_PAUSE).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onSkipToNext() {
            if (DBG) Log.d(TAG, "onSkipToNext");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_FORWARD).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onSkipToPrevious() {
            if (DBG) Log.d(TAG, "onSkipToPrevious");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_BACKWARD).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onSkipToQueueItem(long id) {
            if (DBG) Log.d(TAG, "onSkipToQueueItem" + id);
            if (mA2dpSinkService != null) {
                mA2dpSinkService.requestAudioFocus(mA2dpDevice, true);
            }
            MediaSession.QueueItem queueItem = mMediaQueue.get((int) id);
            if (queueItem != null) {
                String mediaId = queueItem.getDescription().getMediaId();
                mAvrcpCtrlSrvc.fetchAttrAndPlayItem(mA2dpDevice, mediaId);
            }
        }

        @Override
        public void onStop() {
            if (DBG) Log.d(TAG, "onStop");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_STOP).sendToTarget();
        }

        @Override
        public void onPrepare() {
            if (DBG) Log.d(TAG, "onPrepare");
            if (mA2dpSinkService != null) {
                mA2dpSinkService.requestAudioFocus(mA2dpDevice, true);
                getMediaKeyFocus();
            }
        }

        @Override
        public void onRewind() {
            if (DBG) Log.d(TAG, "onRewind");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_REWIND).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onFastForward() {
            if (DBG) Log.d(TAG, "onFastForward");
            mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                    AvrcpControllerService.PASS_THRU_CMD_ID_FF).sendToTarget();
            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        @Override
        public void onPlayFromMediaId(String mediaId, Bundle extras) {
            synchronized (BluetoothMediaBrowserService.this) {
                // Play the item if possible.
                if (mA2dpSinkService != null) {
                    mA2dpSinkService.requestAudioFocus(mA2dpDevice, true);
                    getMediaKeyFocus();
                }
                mAvrcpCtrlSrvc.fetchAttrAndPlayItem(mA2dpDevice, mediaId);
            }

            // TRACK_EVENT should be fired eventually and the UI should be hence updated.
        }

        // Support VOL UP and VOL DOWN events for PTS testing.
        @Override
        public void onCustomAction(String action, Bundle extras) {
            if (DBG) Log.d(TAG, "onCustomAction " + action);
            if (CUSTOM_ACTION_VOL_UP.equals(action)) {
                mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                        AvrcpControllerService.PASS_THRU_CMD_ID_VOL_UP).sendToTarget();
            } else if (CUSTOM_ACTION_VOL_DN.equals(action)) {
                mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_PASSTHRU,
                        AvrcpControllerService.PASS_THRU_CMD_ID_VOL_DOWN).sendToTarget();
            } else if (CUSTOM_ACTION_GET_PLAY_STATUS_NATIVE.equals(action)) {
                mAvrcpCommandQueue.obtainMessage(MSG_AVRCP_GET_PLAY_STATUS_NATIVE).sendToTarget();
            } else {
                Log.w(TAG, "Custom action " + action + " not supported.");
            }
        }
    };

    private BroadcastReceiver mBtReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (DBG) Log.d(TAG, "onReceive intent=" + intent);
            String action = intent.getAction();
            BluetoothDevice btDev =
                    (BluetoothDevice) intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            int state = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);

            if (BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED.equals(action)) {
                if (DBG) {
                    Log.d(TAG, "handleConnectionStateChange: newState="
                            + state + " btDev=" + btDev);
                }

                // Connected state will be handled when AVRCP BluetoothProfile gets connected.
                if (state == BluetoothProfile.STATE_CONNECTED) {
                    mAvrcpCommandQueue.obtainMessage(MSG_DEVICE_CONNECT, btDev).sendToTarget();
                } else if (state == BluetoothProfile.STATE_DISCONNECTED) {
                    // Set the playback state to unconnected.
                    mAvrcpCommandQueue.obtainMessage(MSG_DEVICE_DISCONNECT, btDev).sendToTarget();
                    // If we have been pushing updates via the session then stop sending them since
                    // we are not connected anymore.
                    if (mSession.isActive()) {
                        mSession.setActive(false);
                    }
                }
            } else if (AvrcpControllerService.ACTION_BROWSE_CONNECTION_STATE_CHANGED.equals(
                    action)) {
                if (state == BluetoothProfile.STATE_CONNECTED) {
                    mAvrcpCommandQueue.obtainMessage(MSG_DEVICE_BROWSE_CONNECT, btDev)
                            .sendToTarget();
                } else if (state == BluetoothProfile.STATE_DISCONNECTED) {
                    mAvrcpCommandQueue.obtainMessage(MSG_DEVICE_BROWSE_DISCONNECT, btDev)
                            .sendToTarget();
                }
            } else if (AvrcpControllerService.ACTION_TRACK_EVENT.equals(action)) {
                PlaybackState pbb =
                        intent.getParcelableExtra(AvrcpControllerService.EXTRA_PLAYBACK);
                MediaMetadata mmd =
                        intent.getParcelableExtra(AvrcpControllerService.EXTRA_METADATA);
                mAvrcpCommandQueue.obtainMessage(MSG_TRACK,
                        new Pair<PlaybackState, MediaMetadata>(pbb, mmd)).sendToTarget();
            } else if (AvrcpControllerService.ACTION_FOLDER_LIST.equals(action)) {
                mAvrcpCommandQueue.obtainMessage(MSG_FOLDER_LIST, intent).sendToTarget();
            }
        }
    };

    private synchronized void msgDeviceConnect(BluetoothDevice device) {
        if (DBG) Log.d(TAG, "msgDeviceConnect");
        // We are connected to a new device via A2DP now.
        mA2dpDevice = device;
        mAvrcpCtrlSrvc = AvrcpControllerService.getAvrcpControllerService();
        if (mAvrcpCtrlSrvc == null) {
            Log.e(TAG, "!!!AVRCP Controller cannot be null");
            return;
        }
        refreshInitialPlayingState();
    }


    // Refresh the UI if we have a connected device and AVRCP is initialized.
    private synchronized void refreshInitialPlayingState() {
        if (mA2dpDevice == null) {
            if (DBG) Log.d(TAG, "device " + mA2dpDevice);
            return;
        }

        List<BluetoothDevice> devices = mAvrcpCtrlSrvc.getConnectedDevices();
        if (devices.size() == 0) {
            Log.w(TAG, "No devices connected yet");
            return;
        }

        if (mA2dpDevice != null && !mA2dpDevice.equals(devices.get(0))) {
            Log.w(TAG, "A2dp device : " + mA2dpDevice + " avrcp device " + devices.get(0));
            return;
        }
        mA2dpDevice = devices.get(0);
        mA2dpSinkService = A2dpSinkService.getA2dpSinkService();

        PlaybackState playbackState = mAvrcpCtrlSrvc.getPlaybackState(mA2dpDevice);
        MediaMetadata mediaMetadata = mAvrcpCtrlSrvc.getMetaData(mA2dpDevice);
        if (VDBG) {
            Log.d(TAG, "Media metadata " + mediaMetadata + " playback state " + playbackState);
        }
        mSession.setMetadata(mAvrcpCtrlSrvc.getMetaData(mA2dpDevice));
        mSession.setPlaybackState(playbackState);
    }

    private void msgDeviceDisconnect(BluetoothDevice device) {
        if (DBG) Log.d(TAG, "msgDeviceDisconnect");
        if (mA2dpDevice == null) {
            Log.w(TAG, "Already disconnected - nothing to do here.");
            return;
        } else if (!mA2dpDevice.equals(device)) {
            Log.e(TAG,
                    "Not the right device to disconnect current " + mA2dpDevice + " dc " + device);
            return;
        }

        // Unset the session.
        PlaybackState.Builder pbb = new PlaybackState.Builder();
        pbb = pbb.setState(PlaybackState.STATE_ERROR, PlaybackState.PLAYBACK_POSITION_UNKNOWN,
                PLAYBACK_SPEED)
                .setErrorMessage(getString(R.string.bluetooth_disconnected));
        mSession.setPlaybackState(pbb.build());

        // Set device to null.
        mA2dpDevice = null;
        mBrowseConnected = false;
        // update playerList.
        mMediaQueue.clear();
        mSession.setQueue(mMediaQueue);
        notifyChildrenChanged("__ROOT__");
    }

    private void msgTrack(PlaybackState pb, MediaMetadata mmd) {
        if (VDBG) Log.d(TAG, "msgTrack: playback: " + pb + " mmd: " + mmd);
        // Log the current track position/content.
        MediaController controller = mSession.getController();
        PlaybackState prevPS = controller.getPlaybackState();
        MediaMetadata prevMM = controller.getMetadata();

        if (prevPS != null) {
            Log.d(TAG, "prevPS " + prevPS);
        }

        if (prevMM != null) {
            String title = prevMM.getString(MediaMetadata.METADATA_KEY_TITLE);
            long trackLen = prevMM.getLong(MediaMetadata.METADATA_KEY_DURATION);
            if (VDBG) Log.d(TAG, "prev MM title " + title + " track len " + trackLen);
        }

        if (mmd != null) {
            if (VDBG) Log.d(TAG, "msgTrack() mmd " + mmd.getDescription());
            mSession.setMetadata(mmd);
        }

        if (pb != null) {
            if (DBG) Log.d(TAG, "msgTrack() playbackstate " + pb);
            mSession.setPlaybackState(pb);

            // If we are now playing then we should start pushing updates via MediaSession so that
            // external UI (such as SystemUI) can show the currently playing music.
            if (pb.getState() == PlaybackState.STATE_PLAYING && !mSession.isActive()) {
                mSession.setActive(true);
            }
        }
    }

    private boolean isHoldableKey(int cmd) {
        return  (cmd == AvrcpControllerService.PASS_THRU_CMD_ID_REWIND)
                || (cmd == AvrcpControllerService.PASS_THRU_CMD_ID_FF);
    }

    private synchronized void msgPassThru(int cmd) {
        if (DBG) Log.d(TAG, "msgPassThru " + cmd);
        if (mA2dpDevice == null) {
            // We should have already disconnected - ignore this message.
            Log.w(TAG, "Already disconnected ignoring.");
            return;
        }
        // Some keys should be held until the next event.
        if (mCurrentlyHeldKey != 0) {
            mAvrcpCtrlSrvc.sendPassThroughCmd(mA2dpDevice, mCurrentlyHeldKey,
                    AvrcpControllerService.KEY_STATE_RELEASED);

            if (mCurrentlyHeldKey == cmd) {
                // Return to prevent starting FF/FR operation again
                mCurrentlyHeldKey = 0;
                return;
            } else {
                // FF/FR is in progress and other operation is desired
                // so after stopping FF/FR, not returning so that command
                // can be sent for the desired operation.
                mCurrentlyHeldKey = 0;
            }
        }

        // Send the pass through.
        mAvrcpCtrlSrvc.sendPassThroughCmd(mA2dpDevice, cmd,
                AvrcpControllerService.KEY_STATE_PRESSED);

        if (isHoldableKey(cmd)) {
            // Release cmd next time a command is sent.
            mCurrentlyHeldKey = cmd;
        } else {
            mAvrcpCtrlSrvc.sendPassThroughCmd(mA2dpDevice, cmd,
                    AvrcpControllerService.KEY_STATE_RELEASED);
        }
    }

    private synchronized void msgGetPlayStatusNative() {
        if (DBG) Log.d(TAG, "msgGetPlayStatusNative");
        if (mA2dpDevice == null) {
            // We should have already disconnected - ignore this message.
            Log.w(TAG, "Already disconnected ignoring.");
            return;
        }

        // Ask for a non cached version.
        mAvrcpCtrlSrvc.getPlaybackState(mA2dpDevice, false);
    }

    private void msgDeviceBrowseConnect(BluetoothDevice device) {
        if (DBG) Log.d(TAG, "msgDeviceBrowseConnect device " + device);
        // We should already be connected to this device over A2DP.
        if (!device.equals(mA2dpDevice)) {
            Log.e(TAG, "Browse connected over different device a2dp " + mA2dpDevice + " browse "
                    + device);
            return;
        }
        mBrowseConnected = true;
        // update playerList
        notifyChildrenChanged("__ROOT__");
    }

    private void msgFolderList(Intent intent) {
        // Parse the folder list for children list and id.
        String id = intent.getStringExtra(AvrcpControllerService.EXTRA_FOLDER_ID);
        updateNowPlayingQueue();
        if (VDBG) Log.d(TAG, "Parent: " + id);
        synchronized (this) {
            // If we have a result object then we should send the result back
            // to client since it is blocking otherwise we may have gotten more items
            // from remote device, hence let client know to fetch again.
            Result<List<MediaItem>> results = mParentIdToRequestMap.remove(id);
            if (results == null) {
                Log.w(TAG, "Request no longer exists, notifying that children changed.");
                notifyChildrenChanged(id);
            } else {
                List<MediaItem> folderList = mAvrcpCtrlSrvc.getContents(mA2dpDevice, id);
                results.sendResult(folderList);
            }
        }
    }

    private void updateNowPlayingQueue() {
        List<MediaItem> songList = mAvrcpCtrlSrvc.getContents(mA2dpDevice, "NOW_PLAYING");
        Log.d(TAG, "NowPlaying" + songList.size());
        mMediaQueue.clear();
        for (MediaItem song : songList) {
            mMediaQueue.add(new MediaSession.QueueItem(song.getDescription(), mMediaQueue.size()));
        }
        mSession.setQueue(mMediaQueue);
    }

    /**
     * processInternalEvent(Intent intent)
     * Routine to provide MediaBrowserService with content updates from within the same process.
     */
    public void processInternalEvent(Intent intent) {
        String action = intent.getAction();
        if (AvrcpControllerService.ACTION_FOLDER_LIST.equals(action)) {
            mAvrcpCommandQueue.obtainMessage(MSG_FOLDER_LIST, intent).sendToTarget();
        }
    }

    private void msgDeviceBrowseDisconnect(BluetoothDevice device) {
        if (DBG) Log.d(TAG, "msgDeviceBrowseDisconnect device " + device);
        // Disconnect only if mA2dpDevice is non null
        if (!device.equals(mA2dpDevice)) {
            Log.w(TAG, "Browse disconnecting from different device a2dp " + mA2dpDevice + " browse "
                    + device);
            return;
        }
        mBrowseConnected = false;
    }

}
