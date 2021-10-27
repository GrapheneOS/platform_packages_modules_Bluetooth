/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


package com.android.bluetooth.mcp;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import com.android.bluetooth.btservice.ProfileService;
import android.bluetooth.BluetoothUuid;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemProperties;
import android.os.UserManager;
import android.util.Log;
import android.os.Message;
import android.os.Binder;
import android.os.IBinder;

import com.android.bluetooth.BluetoothMetricsProto;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.apm.ActiveDeviceManagerService;
import com.android.bluetooth.apm.ApmConst;
import com.android.bluetooth.acm.AcmService;
import com.android.bluetooth.btservice.MetricsLogger;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.internal.annotations.VisibleForTesting;
import android.media.session.PlaybackState;
import android.media.MediaDescription;
import android.media.MediaMetadata;
import com.android.bluetooth.apm.MediaControlManager;
import android.view.KeyEvent;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import android.media.session.MediaSessionManager;
import com.android.internal.util.ArrayUtils;
/**
 * Provides Bluetooth MCP profile as a service in the Bluetooth application.
 * @hide
 */
public class McpService extends ProfileService {

    private static final String TAG = "McpService";
    private static final boolean DBG = true;
    public static final int MUSIC_PLAYER_CONTROL = 28;
    private static McpService sMcpService;
    private BroadcastReceiver mBondStateChangedReceiver;

    private BluetoothDevice mActiveDevice;
    private AdapterService mAdapterService;
    private McpNativeInterface mNativeInterface;
    private static McpService sInstance = null;
    private Context mContext;
    private McsMessageHandler mHandler;
    private int mMaxConnectedAudioDevices = 1;
    private String mActiveMediaPlayerName = new String("");

    public static final String ACTION_CONNECTION_STATE_CHANGED =
                "com.android.bluetooth.mcp.action.CONNECTION_STATE_CHANGED";
    //native event
    static final int EVENT_TYPE_CONNECTION_STATE_CHANGED = 1;
    static final int EVENT_TYPE_MEDIA_CONTROL_POINT_CHANGED = 2;
    static final int EVENT_TYPE_TRACK_POSITION_CHANGED = 3;
    static final int EVENT_TYPE_PLAYING_ORDER_CHANGED = 4;
    //MCP to JNI update
    static final int MEDIA_STATE_UPDATE = 5;
    static final int MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_UPDATE = 6;
    static final int MEDIA_CONTROL_POINT_UPDATE = 7;
    static final int MEDIA_PLAYER_NAME_UPDATE = 8;
    static final int TRACK_CHANGED_UPDATE = 9;
    static final int TRACK_TITLE_UPDATE = 10;
    static final int TRACK_POSITION_UPDATE = 11;
    static final int TRACK_DURATION_UPDATE = 12;
    static final int PLAYING_ORDER_SUPPORT_UPDATE = 13;
    static final int PLAYING_ORDER_UPDATE = 14;
    static final int CONTENT_CONTROL_ID_UPDATE = 15;
    static final int ACTIVE_DEVICE_CHANGE = 16;
    static final int BOND_STATE_CHANGE = 17;
    static final int MEDIA_CONTROL_MANAGER_INIT = 18;

    static final int PLAYSTATUS_ERROR = -1;
    static final int PLAYSTATUS_STOPPED = 0;
    static final int PLAYSTATUS_PLAYING = 1;
    static final int PLAYSTATUS_PAUSED = 2;
    static final int PLAYSTATUS_SEEK = 3;


    //super set of supported player supported feature
    static final int MCP_MEDIA_CONTROL_SUP_PLAY          =     1<<0;
    static final int MCP_MEDIA_CONTROL_SUP_PAUSE         =     1<<1;
    static final int MCP_MEDIA_CONTROL_SUP_FAST_REWIND   =     1<<2;
    static final int MCP_MEDIA_CONTROL_SUP_FAST_FORWARD  =     1<<3;
    static final int MCP_MEDIA_CONTROL_SUP_STOP          =     1<<4;
    static final int MCP_MEDIA_CONTROL_SUP_PREV_TRACK    =     1<<11;
    static final int MCP_MEDIA_CONTROL_SUP_NEXT_TRACK    =     1<<12;

    //media control point opcodes
    static final int MCP_MEDIA_CONTROL_OPCODE_PLAY          =     0x01;
    static final int MCP_MEDIA_CONTROL_OPCODE_PAUSE         =     0x02;
    static final int MCP_MEDIA_CONTROL_OPCODE_FAST_REWIND   =     0x03;
    static final int MCP_MEDIA_CONTROL_OPCODE_FAST_FORWARD  =     0x04;
    static final int MCP_MEDIA_CONTROL_OPCODE_STOP          =     0x05;
    static final int MCP_MEDIA_CONTROL_OPCODE_PREV_TRACK    =     0x30;
    static final int MCP_MEDIA_CONTROL_OPCODE_NEXT_TRACK    =     0x31;

    //as there is not supported api to fetch player details
    static final int DEFAULT_MEDIA_PLAYER_SUPPORTED_FEATURE = 0x181F;
    static final int DEFAULT_PLAYER_SUPPORTED_FEATURE = 0x0001; // Single once default
    static final int DEFAULT_PLAYING_ORDER = 0x01; // Single Once default
    private int mState = -1;
    private int mCurrOpCode = -1;
    private int mSupportedControlPoint = -1;
    private int mControlPoint = -1;
    private int mSupportedPlayingOrder = -1;
    private int mPlayingOrder = -1;
    private int mCcid = -1;
    private int mTrackPosition = 0xFFFF;
    private int mTrackDuration = 0xFFFF;
    private String mPlayerName = null;
    private String mTrackTitle = null;
    private MediaControlManager mMediaControlManager;
    private MediaSessionManager mMediaSessionManager;
    /*private class MusicPlayerDetail {
        private int state;
        private int featureSupported;
        private int mSetFeature;
        private int playingOrderFeatureSupported;
        private int currentPlayingOrder;
        private int ccid;
        private int mTrackPosition;
        private int currentTrackDuration;
        private String playerName;

        public MusicPlayerDetail() {

        }
    };*/
    //HashMap<MusicPlayerDetail, String> mMusicPlayerMap = new HashMap();
    @Override
    protected IProfileServiceBinder initBinder() {
        return new McpBinder(this);
    }

    @Override
    protected void create() {
        Log.i(TAG, "create()");
    }

    @Override
    protected void cleanup() {
        Log.i(TAG, "cleanup()");
    }

    @Override
    protected boolean start() {
        Log.i(TAG, "start()");
        if (sMcpService != null) {
            Log.w(TAG, "McpService is already running");
            return true;
        }
        if (DBG) {
            Log.d(TAG, " Create McpService Instance");
        }

        mContext = this;
        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when McpService starts");
        mNativeInterface = Objects.requireNonNull(McpNativeInterface.getInstance(),
                "McpNativeInterface cannot be null when McpService starts");
        // Step 2: Get maximum number of connected audio devices
        mMaxConnectedAudioDevices = mAdapterService.getMaxConnectedAudioDevices();
        Log.i(TAG, "Max connected audio devices set to " + mMaxConnectedAudioDevices);
        //handle to synchronized tx and rx message
        if (mHandler != null) {
            mHandler = null;
        }
        HandlerThread thread = new HandlerThread("BluetoothMCSHandler");
        thread.start();
        Looper looper = thread.getLooper();
        mHandler = new McsMessageHandler(looper);
        mNativeInterface.init();
        Log.d(TAG, "mcp native init done");
        IntentFilter filter = new IntentFilter();

        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        mBondStateChangedReceiver = new BondStateChangedReceiver();
        mContext.registerReceiver(mBondStateChangedReceiver, filter);
        setMcpService(this);
        mMediaSessionManager = (MediaSessionManager) this.getSystemService(
            this.MEDIA_SESSION_SERVICE);
        //MediaControlManager.make(this);
        Message msg = mHandler.obtainMessage();
        msg.what = MEDIA_CONTROL_MANAGER_INIT;
        msg.obj = this;
        mHandler.sendMessageDelayed(msg, 100);
        return true;
    }

    @Override
    protected boolean stop() {
        Log.i(TAG, "stop()");
        if (sMcpService == null) {
           Log.w(TAG, "stop() called before start()");
           return true;
        }
        // Step 8: Mark service as stopped
        setMcpService(null);
        // Cleanup native interface
        mNativeInterface.cleanup();
        mNativeInterface = null;
        mContext.unregisterReceiver(mBondStateChangedReceiver);
        // Clear AdapterService
        mAdapterService = null;
        mMaxConnectedAudioDevices = 1;
        return true;
    }

    private static void setMcpService(McpService instance) {
        if (DBG) {
            Log.d(TAG, "setMcpService(): set to: " + instance);
        }
        sMcpService = instance;
    }
   /**
   * Get the McpService instance
   * @return McpService instance
   */

    public synchronized static  McpService getMcpService() {
        if (sMcpService == null) {
            Log.w(TAG, "getMcpService(): service is null");
            return null;
        }
        return sMcpService;
    }

    public synchronized static void clearMcpInstance () {
        Log.v(TAG, "clearing MCP instatnce");
        sInstance = null;
        Log.v(TAG, "After clearing MCP instatnce ");
    }

     public synchronized boolean MediaControlPointOpcodeUpdate(int feature) {
        Message msg = mHandler.obtainMessage();
        msg.what = MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_UPDATE;
        msg.arg1 = feature;
        mHandler.sendMessage(msg);
        return true;
    }

    public synchronized boolean MediaControlPointUpdate(int value) {
        Message msg = mHandler.obtainMessage();
        msg.what = MEDIA_CONTROL_POINT_UPDATE;
        msg.arg1 = value;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean MediaStateUpdate(int state) {
        Message msg = mHandler.obtainMessage();
        msg.what = MEDIA_STATE_UPDATE;
        msg.arg1 = state;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean MediaPlayerNameUpdate(String name) {
        Message msg = mHandler.obtainMessage();
        msg.what = MEDIA_PLAYER_NAME_UPDATE;
        msg.obj = name;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean PlayingOrderSupportedUpdate(int support) {
        Message msg = mHandler.obtainMessage();
        msg.what = PLAYING_ORDER_SUPPORT_UPDATE;
        msg.arg1 = support;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean PlayingOrderUpdate(int support) {
        Message msg = mHandler.obtainMessage();
        msg.what = PLAYING_ORDER_UPDATE;
        msg.arg1 = support;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean TrackChangedUpdate(int status) {
        Message msg = mHandler.obtainMessage();
        msg.what = TRACK_CHANGED_UPDATE;
        msg.arg1 = status;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean TrackTitleUpdate(String title) {
        Message msg = mHandler.obtainMessage();
        msg.what = TRACK_TITLE_UPDATE;
        msg.obj = title;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean TrackDurationUpdate(int duration) {
        Message msg = mHandler.obtainMessage();
        msg.what = TRACK_DURATION_UPDATE;
        msg.arg1 = duration;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean TrackPositionUpdate(int position) {
        Message msg = mHandler.obtainMessage();
        msg.what = TRACK_POSITION_UPDATE;
        msg.arg1 = position;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized boolean ContentControlID(int ccid) {
        Message msg = mHandler.obtainMessage();
        msg.what = CONTENT_CONTROL_ID_UPDATE;
        msg.arg1 = ccid;
        mHandler.sendMessage(msg);
        return true;
    }

    private synchronized int convertPlayStateToPlayStatus(PlaybackState state) {
        int playStatus = PLAYSTATUS_ERROR;
        switch (state.getState()) {
            case PlaybackState.STATE_PLAYING:
                playStatus = PLAYSTATUS_PLAYING;
                break;

            case PlaybackState.STATE_CONNECTING:
            case PlaybackState.STATE_NONE:
                playStatus = PLAYSTATUS_STOPPED;
                break;

            case PlaybackState.STATE_PAUSED:
            case PlaybackState.STATE_BUFFERING:
            case PlaybackState.STATE_STOPPED:
                playStatus = PLAYSTATUS_PAUSED;
                break;

            case PlaybackState.STATE_FAST_FORWARDING:
            case PlaybackState.STATE_SKIPPING_TO_NEXT:
            case PlaybackState.STATE_SKIPPING_TO_QUEUE_ITEM:
            case PlaybackState.STATE_REWINDING:
            case PlaybackState.STATE_SKIPPING_TO_PREVIOUS:
                playStatus = PLAYSTATUS_SEEK;
                break;

            case PlaybackState.STATE_ERROR:
                playStatus = PLAYSTATUS_ERROR;
                break;

        }
        return playStatus;
    }


    /**
     * Get the active device.
     *
     * @return the active device or null if no device is active
     */
    public synchronized BluetoothDevice getActiveDevice() {
        return mActiveDevice;
    }

    public synchronized int getControlContentID() {
        int ccid = 1;
        return ccid;
    }

    public synchronized void onConnectionStateChanged(BluetoothDevice device, int status) {
        Log.v(TAG, "onConnectionStateChanged: address=" + device.toString());
        if (status == 0)
            return;
        Message msg = mHandler.obtainMessage();
        msg.what = EVENT_TYPE_CONNECTION_STATE_CHANGED;
        msg.obj = device;
        msg.arg2 = status;
        mHandler.sendMessage(msg);
        return;
    }

    public synchronized boolean onMediaControlPointChangeReq(BluetoothDevice device, int state) {
        Message msg = mHandler.obtainMessage();
        msg.what = EVENT_TYPE_MEDIA_CONTROL_POINT_CHANGED;
        msg.obj = device;
        msg.arg1 = state;
        mHandler.sendMessage(msg);
        return true;
    }

    public synchronized boolean onTrackPositionChangeReq(int position) {
        Message msg = mHandler.obtainMessage();
        msg.what = EVENT_TYPE_TRACK_POSITION_CHANGED;
        msg.arg1 = position;
        mHandler.sendMessage(msg);
        return true;
    }

    public synchronized boolean onPlayingOrderChangeReq(int order) {
        Message msg = mHandler.obtainMessage();
        msg.what = EVENT_TYPE_PLAYING_ORDER_CHANGED;
        msg.arg1 = order;
        mHandler.sendMessage(msg);
        return true;
    }

    public synchronized boolean SetActiveDevices(BluetoothDevice device, int profile) {
        Message msg = mHandler.obtainMessage();
        msg.what = ACTIVE_DEVICE_CHANGE;
        msg.obj = device;
        msg.arg1 = 0; //<TBD> it will use to send mark two earbud address in one gp
        msg.arg2 = profile;
        mHandler.sendMessage(msg);
        return true;
    }

    public synchronized boolean OnMediaPlayerUpdate(int feature, int state,
               int playingOrderSupport, int playingOrder, String playerName) {
        Log.w(TAG, "OnMediaPlayerUpdate for player " + playerName);
        ContentControlID(getControlContentID());
        /*
        if (mMusicPlayerMap.containsKey(playerName)) {
            Log.v(TAG, "Player is already there");
        } else {
            newPlayer =  new MusicPlayerDetail();
            mMusicPlayerMap.add(newPlayer, playerName);
        }*/

        MediaPlayerNameUpdate(playerName);
        MediaStateUpdate(state);
        //added default value as there is no api for gettiting supported feature from player
        MediaControlPointOpcodeUpdate(DEFAULT_MEDIA_PLAYER_SUPPORTED_FEATURE);
        PlayingOrderSupportedUpdate(DEFAULT_PLAYER_SUPPORTED_FEATURE);
        PlayingOrderUpdate(DEFAULT_PLAYING_ORDER);
        return true;
    }

    public synchronized boolean OnMediaStateUpdate(int state) {
        Log.w(TAG, "OnMediaStateUpdate state " + state);
        MediaStateUpdate(state);
        return true;
    }

    public synchronized boolean OnTrackUpdate(int status, int duration, String title) {
        Log.w(TAG, "OnTrackUpdate title " + title + " duration " + duration);
        TrackChangedUpdate(status);
        if (status != 0) {
            TrackTitleUpdate(title);
            TrackDurationUpdate(duration);
        }
        return true;
    }

    public synchronized boolean OnTrackPositionUpdate(int position) {
        Log.w(TAG, "OnTrackPositionUpdate position " + position);
        TrackPositionUpdate(position);
        return true;
    }

    public synchronized boolean OnPlayingOrderUpdate(int order) {
        Log.w(TAG, "OnPlayingOrderUpdate order " + order);
        PlayingOrderUpdate(order);
        return true;
    }
    //As apm is not implemented callback for apm above mention function
    //implemented workaround
    public synchronized void updateMetaData(MediaMetadata data) {
        Log.w(TAG, "updateMetaData data " + data);
        if (data == null) {
            return;
        }
        //length //TBD to convert into int
        int duration = (int)data.getLong(MediaMetadata.METADATA_KEY_DURATION);
        String title = data.getString(MediaMetadata.METADATA_KEY_TITLE);
        if (title != null && !(title.equals(mTrackTitle))) {
            TrackChangedUpdate(1);
            TrackTitleUpdate(title);
        }
        if (duration != mTrackDuration)
            TrackDurationUpdate(duration);
    }

    public synchronized void updatePlaybackState(PlaybackState playbackState) {
        Log.w(TAG, "updatePlaybackState state " + playbackState);
        int state = (int)convertPlayStateToPlayStatus(playbackState);

        if (state != PLAYSTATUS_ERROR && mState != state) {
            if (state == PLAYSTATUS_STOPPED)
                state = PLAYSTATUS_PAUSED;
            MediaStateUpdate(state);
            if (mCurrOpCode != -1) {
                MediaControlPointUpdate(mCurrOpCode);
                mCurrOpCode = -1;
            }
        }
        int position = (int)playbackState.getPosition();

        if (position != mTrackPosition)
            TrackPositionUpdate(position);
        float speed = playbackState.getPlaybackSpeed(); //for playback speed
    }

    public synchronized void updatePlayerName(String packageName, boolean removed) {
        Log.w(TAG, "updatePlayerName pkg " + packageName + " removed " + removed);
        String name = null;
        boolean changed = true;
        int tCcid = 0;
        int tPlayersupport = 0;
        int tMediasupport = 0;
        if ((removed && packageName == null ) ||
            removed && packageName.equals(mPlayerName)) {
            //no active media player
            MediaStateUpdate(PLAYSTATUS_STOPPED);
            name = new String("");
        } else if (packageName != null && !packageName.equals(mPlayerName)) {
            name = packageName;
            tCcid = getControlContentID();
            tPlayersupport = DEFAULT_PLAYER_SUPPORTED_FEATURE;
            tMediasupport = DEFAULT_MEDIA_PLAYER_SUPPORTED_FEATURE;
        } else {
            Log.d(TAG, "player name is same no need to update " + packageName);
            changed = false;
        }
        if (changed) {
            Log.d(TAG, "sending player change update");
            MediaControlPointOpcodeUpdate(tMediasupport);
            PlayingOrderSupportedUpdate(tPlayersupport);
            MediaPlayerNameUpdate(name);
            ContentControlID(tCcid);
        }
    }

    private int McpPassthroughToKeyCode(int operation) {
         mCurrOpCode = operation;
         switch (operation) {
            case MCP_MEDIA_CONTROL_OPCODE_PLAY:
                return KeyEvent.KEYCODE_MEDIA_PLAY;
            case MCP_MEDIA_CONTROL_OPCODE_PAUSE:
                return KeyEvent.KEYCODE_MEDIA_PAUSE;
            case MCP_MEDIA_CONTROL_OPCODE_FAST_REWIND:
                return KeyEvent.KEYCODE_MEDIA_REWIND;
            case MCP_MEDIA_CONTROL_OPCODE_FAST_FORWARD:
                return KeyEvent.KEYCODE_MEDIA_FAST_FORWARD;
            case MCP_MEDIA_CONTROL_OPCODE_STOP:
                return KeyEvent.KEYCODE_MEDIA_STOP;
            case MCP_MEDIA_CONTROL_OPCODE_PREV_TRACK:
                return KeyEvent.KEYCODE_MEDIA_PREVIOUS;
            case MCP_MEDIA_CONTROL_OPCODE_NEXT_TRACK:
                return KeyEvent.KEYCODE_MEDIA_NEXT;

            // Fallthrough for all unknown key mappings
            default:
                mCurrOpCode = -1;
                Log.d(TAG, "unknown passthrough");
                return KeyEvent.KEYCODE_UNKNOWN;
         }
     }

    private class BondStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                                           BluetoothDevice.ERROR);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            Objects.requireNonNull(device, "ACTION_BOND_STATE_CHANGED with no EXTRA_DEVICE");
            if (sInstance != null)
                bondStateChanged(device, state);
        }
    }

    /**
     * Process a change in the bonding state for a device.
     *
     * @param device the device whose bonding state has changed
     * @param bondState the new bond state for the device. Possible values are:
     * {@link BluetoothDevice#BOND_NONE},
     * {@link BluetoothDevice#BOND_BONDING},
     * {@link BluetoothDevice#BOND_BONDED}.
     */
    @VisibleForTesting
    void bondStateChanged(BluetoothDevice device, int bondState) {
        if (DBG) {
            Log.d(TAG, "Bond state changed for device: " + device + " state: " + bondState);
        }
        // Remove state machine if the bonding for a device is removed
        if (bondState != BluetoothDevice.BOND_NONE) {
            return;
        }
        //update to lower layer
        Message msg = mHandler.obtainMessage();
        msg.what = BOND_STATE_CHANGE;
        msg.obj = device;
        msg.arg1 = bondState;
        mHandler.sendMessage(msg);
        return;
    }
    private boolean isMcpOnlyDevice(BluetoothDevice device) {
        ParcelUuid ASCS_UUID =
           ParcelUuid.fromString("0000184E-0000-1000-8000-00805F9B34FB");
        AdapterService adapterService = AdapterService.getAdapterService();
        boolean ascsSupported =
                    ArrayUtils.contains(adapterService.getRemoteUuids(device), ASCS_UUID);
        AcmService mAcmService = AcmService.getAcmService();
        if (mAcmService != null) {
            if (ascsSupported &&
                mAcmService.getConnectionState(device) == BluetoothProfile.STATE_CONNECTED) {
                return false;
            }
        }
        Log.d(TAG,"McpOnly device");
        return true;
    }
     /** Handles MCS messages. */
    private final class McsMessageHandler extends Handler {
        private McsMessageHandler(Looper looper) {
            super(looper);
        }
        @Override
         public synchronized void handleMessage(Message msg) {
           if (DBG) Log.v(TAG, "McsMessageHandler: received message=" + msg.what);

            switch (msg.what) {

                case ACTIVE_DEVICE_CHANGE:
                    if (DBG) Log.v(TAG, "ACTIVE_DEVICE_CHANGE msg: " + (BluetoothDevice)msg.obj + " msg2 : " + msg.arg1);
                    mActiveDevice = (BluetoothDevice)msg.obj;
                    mNativeInterface.setActiveDevice((BluetoothDevice)msg.obj, msg.arg1, msg.arg2);
                break;

                case BOND_STATE_CHANGE:
                    if (DBG) Log.v(TAG, "BOND_STATE_CHANGE msg: " + (BluetoothDevice)msg.obj + " msg2 : " + msg.arg1);
                    mNativeInterface.bondStateChange((BluetoothDevice)msg.obj, msg.arg2);
                break;

                case PLAYING_ORDER_SUPPORT_UPDATE:
                    if (DBG) Log.v(TAG, "PLAYING_ORDER_SUPPORT_UPDATE msg: " + msg.arg1);
                    mSupportedPlayingOrder = msg.arg1;
                    mNativeInterface.playingOrder(msg.arg1);
                break;

                case PLAYING_ORDER_UPDATE:
                    if (DBG) Log.v(TAG, "PLAYING_ORDER_UPDATE msg: " + msg.arg1);
                    mPlayingOrder = msg.arg1;
                    mNativeInterface.playingOrder(msg.arg1);
                break;

                case MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_UPDATE:
                    if (DBG) Log.v(TAG, "MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_UPDATE msg: " + msg.arg1);
                    mSupportedControlPoint = msg.arg1;
                    mNativeInterface.mediaControlPointOpcodeSupported(msg.arg1);
                break;

                case MEDIA_CONTROL_POINT_UPDATE:
                    if (DBG) Log.v(TAG, "MEDIA_CONTROL_POINT_UPDATE msg: " + msg.arg1);
                    mControlPoint = msg.arg1;
                    mNativeInterface.mediaControlPoint(msg.arg1);
                break;

                case MEDIA_PLAYER_NAME_UPDATE:
                    if (DBG) Log.v(TAG, "MEDIA_PLAYER_NAME_UPDATE msg: " + (String)msg.obj);
                    String name = (String)msg.obj;
                    mPlayerName = name;
                    if (name == null)
                        name = new String("");
                    mNativeInterface.mediaPlayerName(name);
                break;

                case MEDIA_STATE_UPDATE:
                    if (DBG) Log.v(TAG, "MEDIA_STATE_UPDATE msg: " + msg.arg1);
                    mState = msg.arg1;
                    mNativeInterface.mediaState(msg.arg1);
                break;

                case TRACK_CHANGED_UPDATE:
                    if (DBG) Log.v(TAG, "TRACK_CHANGED_UPDATE msg: " + msg.arg1);
                    mNativeInterface.trackChanged(msg.arg1);
                break;

                case TRACK_DURATION_UPDATE:
                    if (DBG) Log.v(TAG, "TRACK_DURATION_UPDATE msg: " + msg.arg1);
                    mTrackDuration = msg.arg1;
                    mNativeInterface.trackDuration(msg.arg1);
                break;

                case TRACK_POSITION_UPDATE:
                    if (DBG) Log.v(TAG, "TRACK_POSITION_UPDATE msg: " + msg.arg1);
                    mTrackPosition = msg.arg1;
                    mNativeInterface.trackPosition(msg.arg1);
                break;

                case TRACK_TITLE_UPDATE:
                    if (DBG) Log.v(TAG, "TRACK_TITLE_UPDATE msg: " + (String)msg.obj);
                    String title =  (String)msg.obj;
                    mTrackTitle = title;
                    mNativeInterface.trackTitle(title);
                break;


                case CONTENT_CONTROL_ID_UPDATE:
                    if (DBG) Log.v(TAG, "CONTENT_CONTROL_ID_UPDATE msg: " + msg.arg1);
                    mCcid = msg.arg1;
                    mNativeInterface.contentControlId(mCcid);
                break;

                case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                    if (DBG) Log.v(TAG, "EVENT_TYPE_CONNECTION_STATE_CHANGED msg: " + msg.arg1);
                    //update to APM
                break;

                case EVENT_TYPE_MEDIA_CONTROL_POINT_CHANGED:
                    if (DBG) Log.v(TAG, "EVENT_TYPE_MEDIA_CONTROL_POINT_CHANGED msg: " + msg.arg1);
                    BluetoothDevice mMcpDevice = (BluetoothDevice)msg.obj;
                    int code = McpPassthroughToKeyCode(msg.arg1);

                    if (code != KeyEvent.KEYCODE_UNKNOWN) {
                        Log.w(TAG, "Valid passthrough, dispatch to media player");
                    }
                    if (code == KeyEvent.KEYCODE_MEDIA_PLAY &&
                        !Objects.equals(mMcpDevice, mActiveDevice) && !isMcpOnlyDevice(mMcpDevice)) {
                        ActiveDeviceManagerService mActiveDeviceManager = ActiveDeviceManagerService.get();
                        if (mActiveDeviceManager != null) {
                            mActiveDeviceManager.setActiveDevice(mMcpDevice, ApmConst.AudioFeatures.MEDIA_AUDIO, false, true);
                        }
                    }

                    // WAR- For FF/Rewind UC
                    if (code == KeyEvent.KEYCODE_MEDIA_FAST_FORWARD ||
                            code == KeyEvent.KEYCODE_MEDIA_REWIND) {
                        if (mState != PLAYSTATUS_SEEK) {
                            mState = PLAYSTATUS_SEEK;
                            MediaStateUpdate(mState);
                            MediaControlPointUpdate(mCurrOpCode);
                            mCurrOpCode = -1;
                            Log.w(TAG, "Update Playstate as seeking for FF/Rewind opcode");
                        }
                    } else {
                        if (mState == PLAYSTATUS_SEEK) { // To-Do
                        }
                    }

                    KeyEvent event = new KeyEvent(KeyEvent.ACTION_DOWN, code);
                    mMediaSessionManager.dispatchMediaKeyEvent(event, false);
                    event = new KeyEvent(KeyEvent.ACTION_UP, code);
                    mMediaSessionManager.dispatchMediaKeyEvent(event, false);
                break;

                case EVENT_TYPE_PLAYING_ORDER_CHANGED:
                    if (DBG) Log.v(TAG, "EVENT_TYPE_PLAYING_ORDER_CHANGED msg: " + msg.arg1);
                    //update to APM
                break;

                case EVENT_TYPE_TRACK_POSITION_CHANGED:
                    if (DBG) Log.v(TAG, "EVENT_TYPE_TRACK_POSITION_CHANGED msg: " + msg.arg1);
                    //update to APM
                break;

                case MEDIA_CONTROL_MANAGER_INIT:
                    if (DBG) Log.v(TAG, "MEDIA_CONTROL_MANAGER_INIT");
                    Context context = (Context)msg.obj;
                    MediaControlManager.make(context);
                break;

                default:
                    Log.e(TAG, "unknown message! msg.what=" + msg.what);
                break;
            }
            Log.v(TAG, "Exit handleMessage");
        }
    }

    /**
     * Binder object: must be a static class or memory leak may occur.
     */

    static class McpBinder extends Binder implements IProfileServiceBinder {
        private McpService mService;

        private McpService getService() {
            if (!Utils.checkCallerIsSystemOrActiveUser(TAG)) {
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        McpBinder(McpService svc) {
            mService = svc;
        }

        @Override
         public synchronized void cleanup() {
            mService = null;
        }
    }
}


