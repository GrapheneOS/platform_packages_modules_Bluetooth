
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

import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.media.session.PlaybackState;
import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.audio_util.MediaData;
import com.android.bluetooth.audio_util.MediaPlayerList;
import com.android.bluetooth.audio_util.MediaPlayerWrapper;
import com.android.bluetooth.audio_util.Metadata;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.mcp.McpServiceManager;
import com.android.bluetooth.mcp.McpServiceMediaControlRequest;
import com.android.bluetooth.mcp.PlayerStateField;
import com.android.bluetooth.mcp.PlayingOrder;
import com.android.bluetooth.mcp.ServiceCallbacks;
import com.android.bluetooth.mcp.ServiceStatus;
import com.android.bluetooth.mcp.SupportedPlayingOrder;
import java.lang.Math;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class MediaControlProfileTest {
    private BluetoothAdapter mAdapter;
    private MediaControlProfile mMediaControlProfile;
    private List<Integer> mPendingStateRequest;

    private String packageName = "TestPackage";

    private String name = "TestPlayer";
    private CharSequence charSequence = "TestPlayer";
    private ServiceCallbacks mMcpServiceCallbacks;

    @Mock private AdapterService mAdapterService;
    @Mock private Context mMockContext;
    @Mock private MediaData mMockMediaData;
    @Mock private MediaPlayerList mMockMediaPlayerList;
    @Mock private Metadata mMockMetadata;
    @Mock private MediaPlayerWrapper mMockMediaPlayerWrapper;
    @Mock private PackageManager mMockPackageManager;
    @Mock private ApplicationInfo mMockApplicationInfo;
    @Mock private McpService mMockGMcsService;
    @Mock private McpServiceManager mMockMcpServiceManager;

    @Captor private ArgumentCaptor<HashMap> stateMapCaptor;
    @Captor private ArgumentCaptor<Long> positionCaptor;
    @Captor private ArgumentCaptor<MediaControlProfile.ListCallback> listCallbackCaptor;
    @Captor private ArgumentCaptor<ServiceCallbacks> McpServiceCallbacksCaptor;

    @Before
    public void setUp() throws Exception {
        MediaControlProfile.ListCallback listCallback;
        MockitoAnnotations.initMocks(this);

        TestUtils.setAdapterService(mAdapterService);
        mAdapter = BluetoothAdapter.getDefaultAdapter();

        mMockMediaData.metadata = mMockMetadata;

        mMockMediaData.state = null;
        mMockMetadata.duration = Long.toString(0);
        mMockMetadata.title = null;
        doReturn(mMockMediaPlayerWrapper).when(mMockMediaPlayerList).getActivePlayer();
        doReturn(mMockContext).when(mMockContext).getApplicationContext();
        doReturn(mMockPackageManager).when(mMockContext).getPackageManager();
        doReturn(getInstrumentation().getTargetContext().getMainThreadHandler())
                .when(mMockContext)
                .getMainThreadHandler();
        doReturn(packageName).when(mMockContext).getPackageName();
        doReturn(name).when(mMockMediaPlayerWrapper).getPackageName();
        doReturn(charSequence).when(mMockApplicationInfo).loadLabel(any(PackageManager.class));
        try {
            doReturn(mMockApplicationInfo)
                    .when(mMockPackageManager)
                    .getApplicationInfo(anyString(), anyInt());
        } catch (PackageManager.NameNotFoundException e) {
            Assert.fail();
        }

        mPendingStateRequest = new ArrayList<>();
        mMediaControlProfile =
                new MediaControlProfile(mMockContext, mMockMediaPlayerList, mMockMcpServiceManager);

        mMediaControlProfile.init();
        verify(mMockMcpServiceManager)
                .registerServiceInstance(eq(packageName), McpServiceCallbacksCaptor.capture());
        mMcpServiceCallbacks = McpServiceCallbacksCaptor.getValue();
        mMcpServiceCallbacks.onServiceInstanceRegistered(ServiceStatus.OK, mMockGMcsService);

        verify(mMockMediaPlayerList).init(listCallbackCaptor.capture());
        listCallback = listCallbackCaptor.getValue();
        listCallback.run(mMockMediaData);
        // Give some time to verify if post function finishes on update player state method call
        // XXX: Is there a possibility to get rid of this timetout ?
        verify(mMockGMcsService, timeout(100).times(1)).updatePlayerState(any(HashMap.class));
    }

    @After
    public void tearDown() throws Exception {
        mMediaControlProfile.cleanup();
        mMediaControlProfile = null;

        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void testGetCurrentTrackDuration() {
        long duration = 10;

        // Some duration
        mMockMetadata.duration = Long.toString(duration);
        Assert.assertEquals(duration, mMediaControlProfile.getCurrentTrackDuration());

        // No metadata equals no track duration
        mMockMediaData.metadata = null;
        Assert.assertEquals(McpService.TRACK_DURATION_UNAVAILABLE,
                mMediaControlProfile.getCurrentTrackDuration());
    }

    @Test
    public void testPlayerState2McsState() {
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_PLAYING),
                com.android.bluetooth.mcp.PlaybackState.PLAYING);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_NONE),
                com.android.bluetooth.mcp.PlaybackState.INACTIVE);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_STOPPED),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_PAUSED),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_PLAYING),
                com.android.bluetooth.mcp.PlaybackState.PLAYING);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_FAST_FORWARDING),
                com.android.bluetooth.mcp.PlaybackState.SEEKING);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_REWINDING),
                com.android.bluetooth.mcp.PlaybackState.SEEKING);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_BUFFERING),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(PlaybackState.STATE_ERROR),
                com.android.bluetooth.mcp.PlaybackState.INACTIVE);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_CONNECTING),
                com.android.bluetooth.mcp.PlaybackState.INACTIVE);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_SKIPPING_TO_PREVIOUS),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
        Assert.assertEquals(
                mMediaControlProfile.playerState2McsState(PlaybackState.STATE_SKIPPING_TO_NEXT),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
        Assert.assertEquals(mMediaControlProfile.playerState2McsState(
                                    PlaybackState.STATE_SKIPPING_TO_QUEUE_ITEM),
                com.android.bluetooth.mcp.PlaybackState.PAUSED);
    }

    @Test
    public void testGetLatestTrackPosition() {
        int state = PlaybackState.STATE_PLAYING;
        long position = 10;
        float playback_speed = 1.5f;
        long update_time = 77;

        Assert.assertEquals(mMcpServiceCallbacks.onGetCurrentTrackPosition(),
                McpService.TRACK_POSITION_UNAVAILABLE);

        PlaybackState.Builder bob = new PlaybackState.Builder(mMockMediaData.state);
        bob.setState(state, position, playback_speed);
        mMockMediaData.state = bob.build();
        doReturn(mMockMediaData.state).when(mMockMediaPlayerWrapper).getPlaybackState();

        Assert.assertNotEquals(mMcpServiceCallbacks.onGetCurrentTrackPosition(),
                McpService.TRACK_POSITION_UNAVAILABLE);
    }

    @Test
    public void testOnCurrentPlayerStateUpdate() {
        HashMap stateMap;
        int state = PlaybackState.STATE_PLAYING;
        long position = 10;
        float playback_speed = 1.5f;
        long update_time = 77;
        long duration = 10;
        String title = "TestTrackTitle";

        mMockMetadata.duration = Long.toString(duration);
        mMockMetadata.title = title;

        PlaybackState.Builder bob = new PlaybackState.Builder(mMockMediaData.state);
        bob.setState(state, position, playback_speed, update_time);
        mMockMediaData.state = bob.build();

        mMediaControlProfile.onCurrentPlayerStateUpdated(true, true);
        // First time called from ListCallback. Give some time to verify if post function
        // finishes on update player state method call
        // XXX: Is there a possibility to get rid of this timetout ?
        verify(mMockGMcsService, timeout(100).times(2)).updatePlayerState(stateMapCaptor.capture());
        stateMap = stateMapCaptor.getValue();

        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYER_NAME));

        // state changed
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYBACK_STATE));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.OPCODES_SUPPORTED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.SEEKING_SPEED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYBACK_SPEED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.TRACK_POSITION));

        // metadata changed
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.TRACK_DURATION));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.TRACK_TITLE));
    }

    private void testHandleTrackPositionSetRequest(long position, long duration, int times) {
        mMcpServiceCallbacks.onTrackPositionSetRequest(position);
        verify(mMockMediaPlayerWrapper, timeout(100).times(times)).seekTo(positionCaptor.capture());

        // position cannot be negative and bigger than track duration
        if (position < 0)
            Assert.assertEquals(positionCaptor.getValue().longValue(), 0);
        else if (position > duration) {
            Assert.assertEquals(positionCaptor.getValue().longValue(), duration);
        } else {
            Assert.assertEquals(positionCaptor.getValue().longValue(), position);
        }
    }

    @Test
    public void testHandleTrackPositionsSetRequest() {
        long duration = 50;
        long actions = PlaybackState.ACTION_SEEK_TO;
        int times = 1;

        mMockMetadata.duration = Long.toString(duration);

        PlaybackState.Builder bob = new PlaybackState.Builder(mMockMediaData.state);
        bob.setActions(actions);
        mMockMediaData.state = bob.build();

        testHandleTrackPositionSetRequest(-duration, duration, times++);
        testHandleTrackPositionSetRequest(duration + duration, duration, times++);
        testHandleTrackPositionSetRequest(Math.round(duration / 2), duration, times++);

        actions = 0;
        bob.setActions(actions);
        mMockMediaData.state = bob.build();

        mMcpServiceCallbacks.onTrackPositionSetRequest(duration);
        // First time called from ListCallback. Give some time to verify if post function
        // finishes on update player state method call
        // XXX: Is there a possibility to get rid of this timetout ?
        verify(mMockGMcsService, timeout(100).times(2)).updatePlayerState(any(HashMap.class));
    }

    @Test
    public void testHandlePlaybackSpeedSetRequest() {
        float speed = 1.5f;
        int times = 1;

        mMcpServiceCallbacks.onPlaybackSpeedSetRequest(speed);
        verify(mMockMediaPlayerWrapper, timeout(100).times(times)).setPlaybackSpeed(anyFloat());

        // Playback speed wouldn't be set if no active player
        doReturn(null).when(mMockMediaPlayerList).getActivePlayer();
        mMcpServiceCallbacks.onPlaybackSpeedSetRequest(speed);
        verify(mMockMediaPlayerWrapper, timeout(100).times(times)).setPlaybackSpeed(anyFloat());
    }

    @Test
    public void testHandleMediaControlRequest() {
        long actions = PlaybackState.ACTION_PLAY | PlaybackState.ACTION_PAUSE
                | PlaybackState.ACTION_STOP | PlaybackState.ACTION_SKIP_TO_PREVIOUS
                | PlaybackState.ACTION_SKIP_TO_NEXT | PlaybackState.ACTION_REWIND
                | PlaybackState.ACTION_FAST_FORWARD | PlaybackState.ACTION_SEEK_TO;
        long duration = 10;

        PlaybackState.Builder bob = new PlaybackState.Builder(mMockMediaData.state);
        bob.setActions(actions);
        mMockMediaData.state = bob.build();

        McpServiceMediaControlRequest request =
                new McpServiceMediaControlRequest(McpServiceMediaControlRequest.Opcodes.PLAY, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).playCurrent();
        request = new McpServiceMediaControlRequest(McpServiceMediaControlRequest.Opcodes.PAUSE, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).pauseCurrent();
        request = new McpServiceMediaControlRequest(McpServiceMediaControlRequest.Opcodes.STOP, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).seekTo(0);
        verify(mMockMediaPlayerWrapper).stopCurrent();
        request = new McpServiceMediaControlRequest(
                McpServiceMediaControlRequest.Opcodes.PREVIOUS_TRACK, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).skipToPrevious();
        request = new McpServiceMediaControlRequest(
                McpServiceMediaControlRequest.Opcodes.NEXT_TRACK, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).skipToNext();
        request = new McpServiceMediaControlRequest(
                McpServiceMediaControlRequest.Opcodes.FAST_REWIND, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).rewind();
        request = new McpServiceMediaControlRequest(
                McpServiceMediaControlRequest.Opcodes.FAST_FORWARD, 0);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).fastForward();

        mMockMetadata.duration = Long.toString(duration);
        Assert.assertEquals(duration, mMediaControlProfile.getCurrentTrackDuration());
        request = new McpServiceMediaControlRequest(
                McpServiceMediaControlRequest.Opcodes.MOVE_RELATIVE, 100);
        mMcpServiceCallbacks.onMediaControlRequest(request);
        verify(mMockMediaPlayerWrapper, timeout(100)).seekTo(duration);
    }

    @Test
    public void testPlayerActions2McsSupportedOpcodes() {
        long actions = PlaybackState.ACTION_PLAY | PlaybackState.ACTION_PAUSE
                | PlaybackState.ACTION_STOP | PlaybackState.ACTION_SKIP_TO_PREVIOUS
                | PlaybackState.ACTION_SKIP_TO_NEXT | PlaybackState.ACTION_REWIND
                | PlaybackState.ACTION_FAST_FORWARD | PlaybackState.ACTION_SEEK_TO;
        int opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.STOP
                | McpServiceMediaControlRequest.SupportedOpcodes.PAUSE
                | McpServiceMediaControlRequest.SupportedOpcodes.PLAY
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD
                | McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE;

        Assert.assertEquals(
                mMediaControlProfile.playerActions2McsSupportedOpcodes(actions), opcodes_supported);
    }

    @Test
    public void testProcessPendingPlayerStateRequest() {
        HashMap stateMap;
        int state = PlaybackState.STATE_PLAYING;
        long position = 10;
        float playback_speed = 1.5f;

        PlaybackState.Builder bob = new PlaybackState.Builder(mMockMediaData.state);
        bob.setState(state, position, playback_speed);
        mMockMediaData.state = bob.build();
        doReturn(mMockMediaData.state).when(mMockMediaPlayerWrapper).getPlaybackState();

        PlayerStateField[] state_fields = new PlayerStateField[] {PlayerStateField.PLAYBACK_STATE,
                PlayerStateField.TRACK_DURATION, PlayerStateField.PLAYBACK_SPEED,
                PlayerStateField.SEEKING_SPEED, PlayerStateField.PLAYING_ORDER,
                PlayerStateField.TRACK_POSITION, PlayerStateField.PLAYER_NAME,
                PlayerStateField.PLAYING_ORDER_SUPPORTED, PlayerStateField.OPCODES_SUPPORTED};

        mMcpServiceCallbacks.onPlayerStateRequest(state_fields);
        // First time called from ListCallback. Give some time to verify if post function
        // finishes on update player state method call
        // XXX: Is there a possibility to get rid of this timetout ?
        verify(mMockGMcsService, timeout(100).times(2)).updatePlayerState(stateMapCaptor.capture());
        stateMap = stateMapCaptor.getValue();

        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYBACK_STATE));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.TRACK_DURATION));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYBACK_SPEED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.SEEKING_SPEED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYING_ORDER));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.TRACK_POSITION));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYER_NAME));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.PLAYING_ORDER_SUPPORTED));
        Assert.assertTrue(stateMap.containsKey(PlayerStateField.OPCODES_SUPPORTED));
    }

    private void testGetCurrentPlayerPlayingOrder(
            PlayingOrder expected_value, boolean is_shuffle_set, boolean is_repeat_set) {
        doReturn(is_shuffle_set).when(mMockMediaPlayerWrapper).isShuffleSet();
        doReturn(is_repeat_set).when(mMockMediaPlayerWrapper).isRepeatSet();
        Assert.assertEquals(expected_value, mMediaControlProfile.getCurrentPlayerPlayingOrder());
    }

    @Test
    public void testGetCurrentPlayerPlayingOrders() {
        testGetCurrentPlayerPlayingOrder(PlayingOrder.SHUFFLE_REPEAT, true, true);
        testGetCurrentPlayerPlayingOrder(PlayingOrder.SHUFFLE_ONCE, true, false);
        testGetCurrentPlayerPlayingOrder(PlayingOrder.IN_ORDER_REPEAT, false, true);
        testGetCurrentPlayerPlayingOrder(PlayingOrder.IN_ORDER_ONCE, false, false);
    }

    private void testGetSupportedPlayingOrder(boolean is_shuffle_set, boolean is_repeat_set) {
        int expected_value = SupportedPlayingOrder.IN_ORDER_ONCE;

        if (is_repeat_set)
            expected_value |= SupportedPlayingOrder.IN_ORDER_REPEAT;
        if (is_shuffle_set) {
            if (is_repeat_set)
                expected_value |= SupportedPlayingOrder.SHUFFLE_REPEAT;
            else
                expected_value |= SupportedPlayingOrder.SHUFFLE_ONCE;
        }

        doReturn(is_shuffle_set).when(mMockMediaPlayerWrapper).isShuffleSupported();
        doReturn(is_repeat_set).when(mMockMediaPlayerWrapper).isRepeatSupported();
        Assert.assertEquals(
                expected_value, mMediaControlProfile.getSupportedPlayingOrder().intValue());
    }

    @Test
    public void testGetSupportedPlayingOrders() {
        testGetSupportedPlayingOrder(true, true);
        testGetSupportedPlayingOrder(true, false);
        testGetSupportedPlayingOrder(false, true);
        testGetSupportedPlayingOrder(false, false);
    }

    @Test
    public void testAuthorizeLeAudioDevice() {
        BluetoothDevice device = TestUtils.getTestDevice(mAdapter, 0);
        mMediaControlProfile.onLeAudioDeviceConnected(device);
        verify(mMockMcpServiceManager)
                .setDeviceAuthorization(eq(device), eq(BluetoothDevice.ACCESS_ALLOWED));

        mMediaControlProfile.onLeAudioDeviceDisconnected(device);
        verify(mMockMcpServiceManager)
                .setDeviceAuthorization(eq(device), eq(BluetoothDevice.ACCESS_UNKNOWN));
    }
}
