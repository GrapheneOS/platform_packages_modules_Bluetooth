/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package com.android.bluetooth.le_audio;

import android.annotation.NonNull;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import com.android.bluetooth.audio_util.MediaData;
import com.android.bluetooth.audio_util.MediaPlayerList;
import com.android.bluetooth.audio_util.MediaPlayerWrapper;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.mcp.McpServiceManager;
import com.android.bluetooth.mcp.McpServiceMediaControlRequest;
import com.android.bluetooth.mcp.McpServiceSearchRequest;
import com.android.bluetooth.mcp.PlaybackState;
import com.android.bluetooth.mcp.PlayerStateField;
import com.android.bluetooth.mcp.PlayingOrder;
import com.android.bluetooth.mcp.ServiceCallbacks;
import com.android.bluetooth.mcp.ServiceFeature;
import com.android.bluetooth.mcp.ServiceStatus;
import com.android.bluetooth.mcp.SupportedPlayingOrder;
import com.android.internal.annotations.VisibleForTesting;
import java.lang.Math;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/*
 * Generic Media Control Profile hooks into the currently active media player using the MediaSession
 * and MediaController wrapper helpers. It registers a single GMCS instance and connects the two
 * pieces together. It exposes current media player state through the registered MCS GATT service
 * instance and reacts on bluetooth peer device commands with calls to the proper media player's
 * controller. GMCS should be able to control any media player which works nicely with the
 * Android's Media Session framework.
 *
 * Implemented according to Media Control Service v1.0 specification.
 */
public class MediaControlProfile {
    private static final String TAG = "MediaControlProfile";
    private static final boolean DBG = true;
    private final Context mContext;

    // Media players data
    private MediaPlayerList mMediaPlayerList;
    private MediaData mCurrentData;

    private McpServiceManager mMcpServiceManager;
    // MCP service instance
    private McpService mGMcsService;

    // MCP Service requests for stete fields needed to fill the characteristic values
    private List<PlayerStateField> mPendingStateRequest;

    private MediaPlayerWrapper mLastActivePlayer = null;

    public class ListCallback implements MediaPlayerList.MediaUpdateCallback {
        @Override
        public void run(MediaData data) {
            boolean metadata = !Objects.equals(mCurrentData.metadata, data.metadata);
            boolean state = !MediaPlayerWrapper.playstateEquals(mCurrentData.state, data.state);
            boolean queue = !Objects.equals(mCurrentData.queue, data.queue);

            if (DBG)
                Log.d(TAG,
                        "onMediaUpdated: track_changed=" + metadata + " state=" + state
                                + " queue=" + queue);
            mCurrentData = data;

            mContext.getMainThreadHandler().post(() -> {
                onCurrentPlayerStateUpdated(state, metadata);
                if (queue)
                    onCurrentPlayerQueueUpdated();
                processPendingPlayerStateRequest();
            });
        }

        @Override
        public void run(boolean availablePlayers, boolean addressedPlayers, boolean uids) {
            if (DBG)
                Log.d(TAG,
                        "onFolderUpdated: available_players= " + availablePlayers
                                + " addressedPlayers=" + addressedPlayers + " uids=" + uids);
        }
    }

    @VisibleForTesting
    long getCurrentTrackDuration() {
        if (mCurrentData != null) {
            if (mCurrentData.metadata != null)
                return Long.valueOf(mCurrentData.metadata.duration);
        }
        return McpService.TRACK_DURATION_UNAVAILABLE;
    }

    private void onCurrentPlayerQueueUpdated() {
        if (DBG)
            Log.d(TAG,
                    "onCurrentPlayerQueueUpdated: "
                            + "not implemented");

        /* TODO: Implement once we have the Object Transfer Service */
        if (mCurrentData.queue == null)
            return;
    }

    @VisibleForTesting
    void onCurrentPlayerStateUpdated(boolean state_changed, boolean metadata_changed) {
        Map<PlayerStateField, Object> state_map = new HashMap<>();

        if (mMediaPlayerList.getActivePlayer() != mLastActivePlayer)
            state_map.put(PlayerStateField.PLAYER_NAME, getCurrentPlayerName());

        if (state_changed) {
            if (mCurrentData.state != null) {
                if (DBG)
                    Log.d(TAG, "onCurrentPlayerStateUpdated state.");
                PlaybackState playback_state = playerState2McsState(mCurrentData.state.getState());
                state_map.put(PlayerStateField.PLAYBACK_STATE, playback_state);
                state_map.put(PlayerStateField.OPCODES_SUPPORTED,
                        playerActions2McsSupportedOpcodes(mCurrentData.state.getActions()));

                if (playback_state != PlaybackState.INACTIVE) {
                    state_map.put(
                            PlayerStateField.SEEKING_SPEED, mCurrentData.state.getPlaybackSpeed());
                    state_map.put(
                            PlayerStateField.PLAYBACK_SPEED, mCurrentData.state.getPlaybackSpeed());
                    state_map.put(PlayerStateField.TRACK_POSITION,
                            getDriftCorrectedTrackPosition(mCurrentData.state));
                }
            } else {
                // Just update the state and the service should set it's characteristics as required
                state_map.put(PlayerStateField.PLAYBACK_STATE, PlaybackState.INACTIVE);
            }
        }

        if (metadata_changed) {
            if (mCurrentData.metadata != null) {
                if (DBG)
                    Log.d(TAG,
                            "onCurrentPlayerStateUpdated metadata: title= "
                                    + mCurrentData.metadata.title
                                    + " duration= " + mCurrentData.metadata.duration);

                state_map.put(PlayerStateField.TRACK_DURATION,
                        Long.valueOf(mCurrentData.metadata.duration));
                state_map.put(PlayerStateField.TRACK_TITLE, mCurrentData.metadata.title);

                // Update the position if track has changed
                if (mCurrentData.state != null) {
                    state_map.put(PlayerStateField.TRACK_POSITION,
                            getDriftCorrectedTrackPosition(mCurrentData.state));
                }
            } else {
                state_map.put(PlayerStateField.TRACK_DURATION,
                        Long.valueOf(McpService.TRACK_DURATION_UNAVAILABLE));
                state_map.put(PlayerStateField.TRACK_TITLE, "");
            }
        }

        // If any of these were previously requested, just clean-up the requests
        removePendingStateRequests(state_map.keySet());

        mGMcsService.updatePlayerState(state_map);
    }

    private void removePendingStateRequests(Set<PlayerStateField> fields) {
        if (mPendingStateRequest == null)
            return;

        for (PlayerStateField field : fields) {
            mPendingStateRequest.remove(field);
        }
        if (mPendingStateRequest.isEmpty())
            mPendingStateRequest = null;
    }

    public MediaControlProfile(@NonNull Context context, @NonNull MediaPlayerList mediaPlayerList,
            @NonNull McpServiceManager McpServiceManager) {
        Log.v(TAG, "Creating Generic Media Control Service");

        mContext = context;

        mMediaPlayerList = mediaPlayerList;
        mMcpServiceManager = McpServiceManager;
    }

    private final ServiceCallbacks mMcsCallbacks = new ServiceCallbacks() {
        @Override
        public void onServiceInstanceRegistered(ServiceStatus status, McpService service) {
            if (DBG)
                Log.d(TAG, "onServiceInstanceRegistered: status= " + status);
            mGMcsService = service;
        }

        @Override
        public void onServiceInstanceUnregistered(ServiceStatus status) {
            if (DBG)
                Log.d(TAG, "GMCS onServiceInstanceUnregistered: status= " + status);
            mGMcsService = null;
        }

        @Override
        public void onMediaControlRequest(McpServiceMediaControlRequest request) {
            handleMediaControlRequest(request);
        }

        @Override
        public void onSearchRequest(McpServiceSearchRequest request) {
            handleSearchRequest(request);
        }

        @Override
        public void onSetObjectIdRequest(int obj_field, long object_id) {
            handleSetObjectIdRequest(obj_field, object_id);
        }

        @Override
        public void onTrackPositionSetRequest(long position) {
            handleTrackPositionSetRequest(position);
        }

        @Override
        public void onPlaybackSpeedSetRequest(float speed) {
            handlePlaybackSpeedSetRequest(speed);
        }

        @Override
        public void onPlayingOrderSetRequest(int order) {
            handlePlayingOrderSetRequest(order);
        }

        @Override
        public void onCurrentTrackObjectIdSet(long object_id) {
            // TODO: Implement once we have Object Transfer Service
        }

        @Override
        public void onNextTrackObjectIdSet(long object_id) {
            // TODO: Implement once we have Object Transfer Service
        }

        @Override
        public void onCurrentGroupObjectIdSet(long object_id) {
            // TODO: Implement once we have Object Transfer Service
        }

        @Override
        public void onCurrentTrackMetadataRequest() {
            handleCurrentTrackMetadataRequest();
        }

        @Override
        public void onPlayerStateRequest(PlayerStateField[] state_fields) {
            mPendingStateRequest = Stream.of(state_fields).collect(Collectors.toList());
            processPendingPlayerStateRequest();
        }

        @Override
        public long onGetFeatureFlags() {
            return SUPPORTED_FEATURES;
        }

        @Override
        public long onGetCurrentTrackPosition() {
            if (DBG)
                Log.d(TAG, "getCurrentTrackPosition");
            return getLatestTrackPosition();
        }
    };

    private long TrackPositionRelativeToAbsolute(long position) {
        /* MCS v1.0; Sec. 3.7.1
         * "If the value is zero or greater, then the current playing position shall be set to
         * the offset from the start of the track. If the value is less than zero, then the
         * current playing position shall be set to the offset from the end of the track and
         * the value of the Track Position characteristic shall be set to the offset from the start
         * of the track to the new playing position.
         * If the value written does not correspond to a valid track position, the server shall
         * set the Track Position characteristic to a valid value."
         */

        // Limit the possible position to valid track positions
        long track_duration = getCurrentTrackDuration();
        if (position < 0)
            return Math.max(0, position + track_duration);
        return Math.min(track_duration, position);
    }

    private void handleTrackPositionSetRequest(long position) {
        if (DBG)
            Log.d(TAG, "GMCS onTrackPositionSetRequest");

        if (mMediaPlayerList.getActivePlayer() == null)
            return;
        if ((mCurrentData.state.getActions() & android.media.session.PlaybackState.ACTION_SEEK_TO)
                != 0) {
            mMediaPlayerList.getActivePlayer().seekTo(TrackPositionRelativeToAbsolute(position));
        } else {
            // player does not support seek to command, notify last known track position only
            Map<PlayerStateField, Object> state_map = new HashMap<>();
            state_map.put(PlayerStateField.TRACK_POSITION, getLatestTrackPosition());

            mGMcsService.updatePlayerState(state_map);
        }
    }

    private void handleCurrentTrackMetadataRequest() {
        if (DBG)
            Log.d(TAG, "GMCS onCurrentTrackMetadataRequest");
        // FIXME: Seems to be not used right now
    }

    private void handlePlayingOrderSetRequest(int order) {
        if (DBG)
            Log.d(TAG, "GMCS onPlayingOrderSetRequest");
        // Notice: MediaPlayerWrapper does not support play order control.
        // Ignore the request for now.
    }

    private void handlePlaybackSpeedSetRequest(float speed) {
        if (DBG)
            Log.d(TAG, "GMCS onPlaybackSpeedSetRequest");
        if (mMediaPlayerList.getActivePlayer() == null)
            return;
        mMediaPlayerList.getActivePlayer().setPlaybackSpeed(speed);
    }

    private void handleSetObjectIdRequest(int obj_field, long object_id) {
        if (DBG)
            Log.d(TAG, "GMCS onSetObjectIdRequest");
        // TODO: Implement once we have the Object Transfer Service
    }

    private void handleSearchRequest(McpServiceSearchRequest request) {
        if (DBG)
            Log.d(TAG, "GMCS onSearchRequest");
        // TODO: Implement once we have the Object Transfer Service
    }

    @VisibleForTesting
    void handleMediaControlRequest(McpServiceMediaControlRequest request) {
        if (DBG)
            Log.d(TAG, "GMCS onMediaControlRequest: posted task");

        McpServiceMediaControlRequest.Results status =
                McpServiceMediaControlRequest.Results.COMMAND_CANNOT_BE_COMPLETED;
        if (mMediaPlayerList.getActivePlayer() != null) {
            switch (request.getOpcode()) {
                case McpServiceMediaControlRequest.Opcodes.PLAY:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_PLAY)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().playCurrent();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.PAUSE:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_PAUSE)
                            != 0) {
                        // Notice: Pause may function as Pause/Play toggle switch when triggered on
                        // a Media Player which is already in Paused state.
                        if (mCurrentData.state.getState()
                                != android.media.session.PlaybackState.STATE_PAUSED)
                            mMediaPlayerList.getActivePlayer().pauseCurrent();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.STOP:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_STOP)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().seekTo(0);
                        mMediaPlayerList.getActivePlayer().stopCurrent();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.PREVIOUS_TRACK:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_SKIP_TO_PREVIOUS)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().skipToPrevious();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.NEXT_TRACK:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_SKIP_TO_NEXT)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().skipToNext();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.FAST_REWIND:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_REWIND)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().rewind();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.FAST_FORWARD:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_FAST_FORWARD)
                            != 0) {
                        mMediaPlayerList.getActivePlayer().fastForward();
                        status = McpServiceMediaControlRequest.Results.SUCCESS;
                    }
                    break;
                case McpServiceMediaControlRequest.Opcodes.MOVE_RELATIVE:
                    if ((mCurrentData.state.getActions()
                                & android.media.session.PlaybackState.ACTION_SEEK_TO)
                            != 0) {
                        long requested_offset_ms = request.getIntArg();
                        long current_pos_ms = getLatestTrackPosition();
                        long track_duration_ms = getCurrentTrackDuration();

                        if (track_duration_ms != McpService.TRACK_DURATION_UNAVAILABLE) {
                            current_pos_ms = current_pos_ms + requested_offset_ms;
                            if (current_pos_ms < 0)
                                current_pos_ms = 0;
                            else if (current_pos_ms > track_duration_ms)
                                current_pos_ms = track_duration_ms;

                            mMediaPlayerList.getActivePlayer().seekTo(current_pos_ms);
                            status = McpServiceMediaControlRequest.Results.SUCCESS;
                        }
                    }
                    break;
            }

            // These seem to be not supported:
            // McpServiceMediaControlRequest.Opcodes.PREVIOUS_SEGMENT:
            // McpServiceMediaControlRequest.Opcodes.NEXT_SEGMENT:
            // McpServiceMediaControlRequest.Opcodes.FIRST_SEGMENT:
            // McpServiceMediaControlRequest.Opcodes.LAST_SEGMENT:
            // McpServiceMediaControlRequest.Opcodes.GOTO_SEGMENT:
            // McpServiceMediaControlRequest.Opcodes.FIRST_TRACK:
            // McpServiceMediaControlRequest.Opcodes.LAST_TRACK:
            // McpServiceMediaControlRequest.Opcodes.GOTO_TRACK:
            // McpServiceMediaControlRequest.Opcodes.PREVIOUS_GROUP:
            // McpServiceMediaControlRequest.Opcodes.NEXT_GROUP:
            // McpServiceMediaControlRequest.Opcodes.FIRST_GROUP:
            // McpServiceMediaControlRequest.Opcodes.LAST_GROUP:
            // McpServiceMediaControlRequest.Opcodes.GOTO_GROUP:
        }
        if (mGMcsService != null) {
            mGMcsService.setMediaControlRequestResult(request, status);
        }
    }

    private synchronized long getLatestTrackPosition() {
        if (mMediaPlayerList.getActivePlayer() != null) {
            android.media.session.PlaybackState state =
                    mMediaPlayerList.getActivePlayer().getPlaybackState();
            if (state != null)
                return getDriftCorrectedTrackPosition(state);
        }
        return McpService.TRACK_POSITION_UNAVAILABLE;
    }

    private long getDriftCorrectedTrackPosition(android.media.session.PlaybackState state) {
        long position = state.getPosition();
        if (playerState2McsState(state.getState()) == PlaybackState.PLAYING)
            position = position + SystemClock.elapsedRealtime() - state.getLastPositionUpdateTime();

        // Limit the possible position to valid track positions
        if (position < 0)
            return 0;

        long duration = getCurrentTrackDuration();
        if (duration == McpService.TRACK_DURATION_UNAVAILABLE)
            return position;

        return Math.min(duration, position);
    }

    @VisibleForTesting
    static int playerActions2McsSupportedOpcodes(long supported_player_actions) {
        int opcodes_supported = 0;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_STOP) != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.STOP;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_PAUSE) != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.PAUSE;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_PLAY) != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.PLAY;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_REWIND) != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_SKIP_TO_PREVIOUS)
                != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_SKIP_TO_NEXT)
                != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_FAST_FORWARD)
                != 0)
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD;

        if ((supported_player_actions & android.media.session.PlaybackState.ACTION_SEEK_TO) != 0) {
            opcodes_supported |= McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE;
        }

        // It seems we can't we handle any of these:
        // android.media.session.PlaybackState.ACTION_SET_RATING
        // android.media.session.PlaybackState.ACTION_PLAY_PAUSE
        // android.media.session.PlaybackState.ACTION_PLAY_FROM_MEDIA_ID
        // android.media.session.PlaybackState.ACTION_PLAY_FROM_SEARCH
        // android.media.session.PlaybackState.ACTION_SKIP_TO_QUEUE_ITEM
        // android.media.session.PlaybackState.ACTION_PLAY_FROM_URI
        // android.media.session.PlaybackState.ACTION_PREPARE
        // android.media.session.PlaybackState.ACTION_PREPARE_FROM_MEDIA_ID
        // android.media.session.PlaybackState.ACTION_PREPARE_FROM_SEARCH
        // android.media.session.PlaybackState.ACTION_PREPARE_FROM_URI

        if (DBG)
            Log.d(TAG, "updateSupportedOpcodes setting supported opcodes to: " + opcodes_supported);
        return opcodes_supported;
    }

    private void processPendingPlayerStateRequest() {
        if (DBG)
            Log.d(TAG, "GMCS processPendingPlayerStateRequest");

        Map<PlayerStateField, Object> handled_request_map = new HashMap<>();

        if (mPendingStateRequest == null)
            return;

        // Notice: If we are unable to provide the requested field it will stay queued until we are
        //         able to provide it.
        for (PlayerStateField settings_field : mPendingStateRequest) {
            switch (settings_field) {
                case PLAYBACK_STATE:
                    if (mCurrentData.state != null) {
                        handled_request_map.put(settings_field,
                                playerState2McsState(mCurrentData.state.getState()));
                    }
                    break;
                case TRACK_DURATION:
                    handled_request_map.put(settings_field, getCurrentTrackDuration());
                    break;
                case PLAYBACK_SPEED:
                    if (mCurrentData.state != null) {
                        handled_request_map.put(
                                settings_field, mCurrentData.state.getPlaybackSpeed());
                    }
                    break;
                case SEEKING_SPEED:
                    float seeking_speed = 1.0f;
                    if (mCurrentData.state != null) {
                        if ((mCurrentData.state.getState()
                                    == android.media.session.PlaybackState.STATE_FAST_FORWARDING)
                                || (mCurrentData.state.getState()
                                        == android.media.session.PlaybackState.STATE_REWINDING)) {
                            seeking_speed = mCurrentData.state.getPlaybackSpeed();
                        }
                    }

                    handled_request_map.put(settings_field, seeking_speed);
                    break;
                case PLAYING_ORDER:
                    handled_request_map.put(settings_field, getCurrentPlayerPlayingOrder());
                    break;
                case TRACK_POSITION:
                    if (mCurrentData.state != null) {
                        handled_request_map.put(
                                settings_field, getDriftCorrectedTrackPosition(mCurrentData.state));
                    }
                    break;
                case PLAYER_NAME:
                    String player_name = getCurrentPlayerName();
                    if (player_name != null)
                        handled_request_map.put(settings_field, player_name);
                    break;
                case ICON_URL:
                    // Not implemented
                    break;
                case ICON_OBJ_ID:
                    // TODO: Implement once we have Object Transfer Service
                    break;
                case PLAYING_ORDER_SUPPORTED:
                    Integer playing_order = getSupportedPlayingOrder();
                    if (playing_order != null) {
                        handled_request_map.put(settings_field, playing_order.intValue());
                    }
                    break;
                case OPCODES_SUPPORTED:
                    if (mCurrentData.state != null) {
                        handled_request_map.put(settings_field,
                                playerActions2McsSupportedOpcodes(mCurrentData.state.getActions()));
                    }
                    break;
            }
        }

        if (!handled_request_map.isEmpty()) {
            removePendingStateRequests(handled_request_map.keySet());
            mGMcsService.updatePlayerState(handled_request_map);
        }

        if (DBG) {
            if (mPendingStateRequest != null) {
                if (!mPendingStateRequest.isEmpty()) {
                    Log.w(TAG, "MCS service state fields left unhandled: ");
                    for (PlayerStateField item : mPendingStateRequest) {
                        Log.w(TAG, "   > " + item);
                    }
                }
            }
        }
    }

    @VisibleForTesting
    PlayingOrder getCurrentPlayerPlayingOrder() {
        MediaPlayerWrapper mp = mMediaPlayerList.getActivePlayer();
        if (mp == null)
            return PlayingOrder.IN_ORDER_ONCE;

        // Notice: We don't support all the possible MCP playing orders
        if (mp.isShuffleSet()) {
            if (mp.isRepeatSet())
                return PlayingOrder.SHUFFLE_REPEAT;
            else
                return PlayingOrder.SHUFFLE_ONCE;
        } else {
            if (mp.isRepeatSet())
                return PlayingOrder.IN_ORDER_REPEAT;
            else
                return PlayingOrder.IN_ORDER_ONCE;
        }
    }

    @VisibleForTesting
    Integer getSupportedPlayingOrder() {
        MediaPlayerWrapper mp = mMediaPlayerList.getActivePlayer();
        if (mp == null)
            return null;

        // Notice: We don't support all the possible MCP playing orders
        int playing_order = SupportedPlayingOrder.IN_ORDER_ONCE;
        if (mp.isRepeatSupported())
            playing_order |= SupportedPlayingOrder.IN_ORDER_REPEAT;

        if (mp.isShuffleSupported()) {
            if (mp.isRepeatSupported())
                playing_order |= SupportedPlayingOrder.SHUFFLE_REPEAT;
            else
                playing_order |= SupportedPlayingOrder.SHUFFLE_ONCE;
        }
        return playing_order;
    }

    private String getCurrentPlayerName() {
        MediaPlayerWrapper player = mMediaPlayerList.getActivePlayer();
        if (player == null)
            return null;

        String player_name = player.getPackageName();
        try {
            PackageManager pm = mContext.getApplicationContext().getPackageManager();
            ApplicationInfo info = pm.getApplicationInfo(player.getPackageName(), 0);
            player_name = info.loadLabel(pm).toString();
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        return player_name;
    }

    public void init() {
        mCurrentData = new MediaData(null, null, null);

        mMediaPlayerList.init(new ListCallback());
        mMcpServiceManager.registerServiceInstance(mContext.getPackageName(), mMcsCallbacks);
    }

    public void cleanup() {
        if (mMediaPlayerList != null) {
            mMediaPlayerList.cleanup();
        }

        if (mMcpServiceManager != null) {
            mMcpServiceManager.unregisterServiceInstance(mContext.getPackageName());
        }
    }

    public void onLeAudioDeviceConnected(BluetoothDevice device) {
        // Authorize MCP access from devices with enabled Le Audio profile
        if (mMcpServiceManager != null) {
            mMcpServiceManager.setDeviceAuthorization(device, BluetoothDevice.ACCESS_ALLOWED);
        }
    }

    public void onLeAudioDeviceDisconnected(BluetoothDevice device) {
        // Unauthorize MCP access from devices with disabled Le Audio profile
        if (mMcpServiceManager != null) {
            mMcpServiceManager.setDeviceAuthorization(device, BluetoothDevice.ACCESS_UNKNOWN);
        }
    }

    @VisibleForTesting
    static PlaybackState playerState2McsState(int player_state) {
        PlaybackState playback_state = sPlayerState2McsStateMap.get(player_state);

        if (playback_state == null)
            playback_state = PlaybackState.INACTIVE;

        return playback_state;
    }

    private static final HashMap<Integer, PlaybackState> sPlayerState2McsStateMap =
            new HashMap<Integer, PlaybackState>() {
                {
                    put(android.media.session.PlaybackState.STATE_PLAYING, PlaybackState.PLAYING);
                    put(android.media.session.PlaybackState.STATE_NONE, PlaybackState.INACTIVE);
                    put(android.media.session.PlaybackState.STATE_STOPPED, PlaybackState.PAUSED);
                    put(android.media.session.PlaybackState.STATE_PAUSED, PlaybackState.PAUSED);
                    put(android.media.session.PlaybackState.STATE_PLAYING, PlaybackState.PLAYING);
                    put(android.media.session.PlaybackState.STATE_FAST_FORWARDING,
                            PlaybackState.SEEKING);
                    put(android.media.session.PlaybackState.STATE_REWINDING, PlaybackState.SEEKING);
                    put(android.media.session.PlaybackState.STATE_BUFFERING, PlaybackState.PAUSED);
                    put(android.media.session.PlaybackState.STATE_ERROR, PlaybackState.INACTIVE);
                    put(android.media.session.PlaybackState.STATE_CONNECTING,
                            PlaybackState.INACTIVE);
                    put(android.media.session.PlaybackState.STATE_SKIPPING_TO_PREVIOUS,
                            PlaybackState.PAUSED);
                    put(android.media.session.PlaybackState.STATE_SKIPPING_TO_NEXT,
                            PlaybackState.PAUSED);
                    put(android.media.session.PlaybackState.STATE_SKIPPING_TO_QUEUE_ITEM,
                            PlaybackState.PAUSED);
                }
            };

    private static final long SUPPORTED_FEATURES = ServiceFeature.PLAYER_NAME
            | ServiceFeature.PLAYER_NAME_NOTIFY
            // It seems that can't provide player icon URIs that easily
            // BluetoothMcs.ServiceFeature.PLAYER_ICON_URL |
            | ServiceFeature.TRACK_CHANGED | ServiceFeature.TRACK_TITLE
            | ServiceFeature.TRACK_TITLE_NOTIFY | ServiceFeature.TRACK_DURATION
            | ServiceFeature.TRACK_DURATION_NOTIFY | ServiceFeature.TRACK_POSITION
            | ServiceFeature.TRACK_POSITION_NOTIFY | ServiceFeature.PLAYBACK_SPEED
            | ServiceFeature.PLAYBACK_SPEED_NOTIFY | ServiceFeature.SEEKING_SPEED
            | ServiceFeature.SEEKING_SPEED_NOTIFY | ServiceFeature.PLAYING_ORDER
            | ServiceFeature.PLAYING_ORDER_NOTIFY | ServiceFeature.PLAYING_ORDER_SUPPORTED
            | ServiceFeature.MEDIA_STATE | ServiceFeature.MEDIA_CONTROL_POINT
            | ServiceFeature.MEDIA_CONTROL_POINT_OPCODES_SUPPORTED
            | ServiceFeature.MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_NOTIFY
            | ServiceFeature.CONTENT_CONTROL_ID;
}
