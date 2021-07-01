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

package com.android.bluetooth.mcp;

import static org.mockito.Mockito.*;

import android.bluetooth.*;
import android.content.Context;
import android.os.Looper;
import android.util.MathUtils;
import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class McpServiceTest {
    private BluetoothAdapter mAdapter;
    private BluetoothDevice mCurrentDevice;

    private static final UUID UUID_GMCS = UUID.fromString("00001849-0000-1000-8000-00805f9b34fb");
    private static final UUID UUID_MCS = UUID.fromString("00001848-0000-1000-8000-00805f9b34fb");
    private static final UUID UUID_CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");
    public static final int TEST_CCID = 1;

    private McpServiceGatt mMcpService;

    @Mock private AdapterService mAdapterService;
    @Mock private Context mMockContext;
    @Mock private McpServiceGatt.BluetoothGattServerProxy mMockGattServer;
    @Mock private McpServiceManager mMockMcpServiceManager;
    @Mock private ServiceCallbacks mMockMcsCallbacks;

    @Captor private ArgumentCaptor<BluetoothGattService> mGattServiceCaptor;

    @Before
    public void setUp() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }

        MockitoAnnotations.initMocks(this);

        TestUtils.setAdapterService(mAdapterService);
        mAdapter = BluetoothAdapter.getDefaultAdapter();

        doReturn(true).when(mMockGattServer).addService(any(BluetoothGattService.class));

        mMcpService = new McpServiceGatt(mMockMcpServiceManager, mMockMcsCallbacks, TEST_CCID);
        mMcpService.setBluetoothGattServerForTesting(mMockGattServer);
        mMcpService.setServiceManagerForTesting(mMockMcpServiceManager);
        doReturn(BluetoothDevice.ACCESS_ALLOWED)
                .when(mMockMcpServiceManager)
                .getDeviceAuthorization(any(BluetoothDevice.class));
    }

    @After
    public void tearDown() throws Exception {
        mMcpService = null;
        TestUtils.clearAdapterService(mAdapterService);
    }

    private void prepareConnectedDevice() {
        if (mCurrentDevice == null)
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, 0);
    }

    private void prepareConnectedDevicesCccVal(
            BluetoothGattCharacteristic characteristic, byte[] value) {
        prepareConnectedDevice();
        List<BluetoothDevice> devices = new ArrayList<BluetoothDevice>();
        devices.add(mCurrentDevice);
        doReturn(devices).when(mMockGattServer).getConnectedDevices();
        mMcpService.setCcc(mCurrentDevice, characteristic.getUuid(), 0, value);
    }

    @Test
    public void testInit() {
        long mMandatoryFeatures = ServiceFeature.ALL_MANDATORY_SERVICE_FEATURES;

        doReturn(mMandatoryFeatures).when(mMockMcsCallbacks).onGetFeatureFlags();
        Assert.assertTrue(mMcpService.init(UUID_GMCS));
        Assert.assertEquals(mMcpService.getContentControlId(), TEST_CCID);

        doReturn(true).when(mMockGattServer).removeService(any(BluetoothGattService.class));
        mMcpService.destroy();
        verify(mMockMcsCallbacks).onServiceInstanceUnregistered(eq(ServiceStatus.OK));
    }

    @Test
    public void testFailingInit() {
        long mMandatoryFeatures = 0;

        doReturn(mMandatoryFeatures).when(mMockMcsCallbacks).onGetFeatureFlags();
        Assert.assertFalse(mMcpService.init(UUID_GMCS));
    }

    private BluetoothGattService initAllFeaturesGattService() {
        long features = ServiceFeature.ALL_MANDATORY_SERVICE_FEATURES
                | ServiceFeature.PLAYER_ICON_OBJ_ID | ServiceFeature.PLAYER_ICON_URL
                | ServiceFeature.PLAYBACK_SPEED | ServiceFeature.SEEKING_SPEED
                | ServiceFeature.CURRENT_TRACK_SEGMENT_OBJ_ID | ServiceFeature.CURRENT_TRACK_OBJ_ID
                | ServiceFeature.NEXT_TRACK_OBJ_ID | ServiceFeature.CURRENT_GROUP_OBJ_ID
                | ServiceFeature.PARENT_GROUP_OBJ_ID | ServiceFeature.PLAYING_ORDER
                | ServiceFeature.PLAYING_ORDER_SUPPORTED | ServiceFeature.MEDIA_CONTROL_POINT
                | ServiceFeature.MEDIA_CONTROL_POINT_OPCODES_SUPPORTED
                | ServiceFeature.SEARCH_RESULT_OBJ_ID | ServiceFeature.SEARCH_CONTROL_POINT |
                // Notifications
                ServiceFeature.PLAYER_NAME_NOTIFY | ServiceFeature.TRACK_TITLE_NOTIFY
                | ServiceFeature.TRACK_DURATION_NOTIFY | ServiceFeature.TRACK_POSITION_NOTIFY
                | ServiceFeature.PLAYBACK_SPEED_NOTIFY | ServiceFeature.SEEKING_SPEED_NOTIFY
                | ServiceFeature.CURRENT_TRACK_OBJ_ID_NOTIFY
                | ServiceFeature.NEXT_TRACK_OBJ_ID_NOTIFY
                | ServiceFeature.CURRENT_GROUP_OBJ_ID_NOTIFY
                | ServiceFeature.PARENT_GROUP_OBJ_ID_NOTIFY | ServiceFeature.PLAYING_ORDER_NOTIFY
                | ServiceFeature.MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_NOTIFY;

        doReturn(features).when(mMockMcsCallbacks).onGetFeatureFlags();
        Assert.assertTrue(mMcpService.init(UUID_GMCS));

        verify(mMockGattServer).addService(mGattServiceCaptor.capture());

        // Capture GATT Service definition for verification
        BluetoothGattService service = mGattServiceCaptor.getValue();
        Assert.assertNotNull(service);

        // Call back the low level GATT callback and expect proper higher level callback to be
        // called
        mMcpService.mServerCallback.onServiceAdded(BluetoothGatt.GATT_SUCCESS, service);
        verify(mMockMcsCallbacks)
                .onServiceInstanceRegistered(any(ServiceStatus.class), any(McpService.class));

        return service;
    }

    @Test
    public void testGattServerFullInitialState() {
        BluetoothGattService service = initAllFeaturesGattService();

        // Check initial state of all mandatory characteristics
        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_PLAYER_NAME);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals("", characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_TITLE);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals("", characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_DURATION);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(0xFFFFFFFF,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(0xFFFFFFFF,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_MEDIA_STATE);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(PlaybackState.INACTIVE.getValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT8, 0).intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CONTENT_CONTROL_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_READ);
        Assert.assertEquals(TEST_CCID,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT8, 0).intValue());

        // Check initial state of all optional characteristics
        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYER_ICON_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_READ);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYER_ICON_URL);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_READ);
        Assert.assertEquals("", characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_CHANGED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_NOTIFY);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(0,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT8, 0).intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEEKING_SPEED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(0,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT8, 0).intValue());

        characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_CURRENT_TRACK_SEGMENT_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_READ);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_TRACK_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_NEXT_TRACK_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_GROUP_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PARENT_GROUP_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(PlayingOrder.SINGLE_ONCE.getValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT8, 0).intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER_SUPPORTED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                characteristic.getProperties(), BluetoothGattCharacteristic.PROPERTY_READ);
        Assert.assertEquals(SupportedPlayingOrder.SINGLE_ONCE,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT16, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_MEDIA_CONTROL_POINT);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_NOTIFY
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE);

        characteristic = service.getCharacteristic(
                McpServiceGatt.UUID_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertEquals(McpServiceMediaControlRequest.SupportedOpcodes.NONE,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEARCH_RESULT_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_READ
                        | BluetoothGattCharacteristic.PROPERTY_NOTIFY);
        Assert.assertTrue(characteristic.getValue().length == 0);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEARCH_CONTROL_POINT);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(characteristic.getProperties(),
                BluetoothGattCharacteristic.PROPERTY_NOTIFY
                        | BluetoothGattCharacteristic.PROPERTY_WRITE
                        | BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE);
    }

    @Test
    public void testUpdatePlayerState() {
        BluetoothGattService service = initAllFeaturesGattService();
        Map<PlayerStateField, Object> state_map = new HashMap<>();
        float playback_speed = 0.5f;
        PlayingOrder playing_order = PlayingOrder.IN_ORDER_REPEAT;
        long track_position = 100;
        String player_name = "TestPlayerName";
        String icon_url = "www.testiconurl.com";
        Long icon_obj_id = 7l;
        Integer playing_order_supported = SupportedPlayingOrder.IN_ORDER_REPEAT
                | SupportedPlayingOrder.SINGLE_ONCE | SupportedPlayingOrder.SINGLE_REPEAT
                | SupportedPlayingOrder.IN_ORDER_ONCE | SupportedPlayingOrder.IN_ORDER_REPEAT
                | SupportedPlayingOrder.OLDEST_ONCE | SupportedPlayingOrder.OLDEST_REPEAT
                | SupportedPlayingOrder.NEWEST_ONCE | SupportedPlayingOrder.NEWEST_REPEAT
                | SupportedPlayingOrder.SHUFFLE_ONCE | SupportedPlayingOrder.SHUFFLE_REPEAT;
        Integer opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.NONE
                | McpServiceMediaControlRequest.SupportedOpcodes.PLAY
                | McpServiceMediaControlRequest.SupportedOpcodes.PAUSE
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD
                | McpServiceMediaControlRequest.SupportedOpcodes.STOP
                | McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_GROUP;
        String track_title = "Test Song";
        long track_duration = 1000;
        PlaybackState playback_state = PlaybackState.SEEKING;
        float seeking_speed = 2.0f;

        state_map.put(PlayerStateField.PLAYBACK_SPEED, playback_speed);
        state_map.put(PlayerStateField.PLAYING_ORDER, playing_order);
        state_map.put(PlayerStateField.TRACK_POSITION, track_position);
        state_map.put(PlayerStateField.PLAYER_NAME, player_name);
        state_map.put(PlayerStateField.ICON_URL, icon_url);
        state_map.put(PlayerStateField.ICON_OBJ_ID, icon_obj_id);
        state_map.put(PlayerStateField.PLAYING_ORDER_SUPPORTED, playing_order_supported);
        state_map.put(PlayerStateField.OPCODES_SUPPORTED, opcodes_supported);
        state_map.put(PlayerStateField.TRACK_TITLE, track_title);
        state_map.put(PlayerStateField.TRACK_DURATION, track_duration);
        state_map.put(PlayerStateField.PLAYBACK_STATE, playback_state);
        state_map.put(PlayerStateField.SEEKING_SPEED, seeking_speed);
        mMcpService.updatePlayerState(state_map);

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                playback_speed, mMcpService.getPlaybackSpeedChar().floatValue(), 0.001f);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(playing_order.getValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT8, 0).intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);
        Assert.assertNotNull(characteristic);
        // Set value as ms, kept in characteristic as 0.01s
        Assert.assertEquals(track_position / 10,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYER_NAME);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(player_name, characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYER_ICON_URL);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(icon_url, characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYER_ICON_OBJ_ID);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(
                icon_obj_id.longValue(), mMcpService.byteArray2ObjId(characteristic.getValue()));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER_SUPPORTED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(playing_order_supported.intValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT16, 0)
                        .intValue());

        characteristic = service.getCharacteristic(
                McpServiceGatt.UUID_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(opcodes_supported.intValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_TITLE);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(track_title, characteristic.getStringValue(0));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_DURATION);
        Assert.assertNotNull(characteristic);
        // Set value as ms, kept in characteristic as 0.01s
        Assert.assertEquals(track_duration / 10,
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_SINT32, 0)
                        .intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_MEDIA_STATE);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(playback_state.getValue(),
                characteristic.getIntValue(BluetoothGattCharacteristic.FORMAT_UINT8, 0).intValue());

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEEKING_SPEED);
        Assert.assertNotNull(characteristic);
        Assert.assertEquals(seeking_speed, mMcpService.getSeekingSpeedChar().floatValue(), 0.001f);
    }

    private void verifyWriteObjIdsValid(
            BluetoothGattCharacteristic characteristic, long value, int id) {
        mMcpService.mServerCallback.onCharacteristicWriteRequest(mCurrentDevice, 1, characteristic,
                false, true, 0, mMcpService.objId2ByteArray(value));

        verify(mMockMcsCallbacks).onSetObjectIdRequest(eq(id), eq(value));

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1), eq(BluetoothGatt.GATT_SUCCESS), eq(0),
                        eq(mMcpService.objId2ByteArray(value)));
    }

    @Test
    public void testWriteCallbacksValid() {
        BluetoothGattService service = initAllFeaturesGattService();
        int track_position = 100;
        byte playback_speed = 64;
        long current_track_obj_id = 7;
        long next_track_obj_id = 77;
        long current_group_obj_id = 777;
        PlayingOrder playing_order = PlayingOrder.IN_ORDER_REPEAT;
        Integer playing_order_supported = SupportedPlayingOrder.IN_ORDER_REPEAT;

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);

        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) track_position);

        prepareConnectedDevice();
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockMcsCallbacks).onTrackPositionSetRequest(eq(track_position * 10l));

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1), eq(BluetoothGatt.GATT_SUCCESS), eq(0),
                        eq(bb.array()));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);

        bb = ByteBuffer.allocate(Byte.BYTES);
        bb.put(playback_speed);

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockMcsCallbacks)
                .onPlaybackSpeedSetRequest(eq(MathUtils.pow(2, playback_speed / 64)));

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1), eq(BluetoothGatt.GATT_SUCCESS), eq(0),
                        eq(bb.array()));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_TRACK_OBJ_ID);
        verifyWriteObjIdsValid(
                characteristic, current_track_obj_id, ObjectIds.CURRENT_TRACK_OBJ_ID);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_NEXT_TRACK_OBJ_ID);
        verifyWriteObjIdsValid(characteristic, next_track_obj_id, ObjectIds.NEXT_TRACK_OBJ_ID);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_GROUP_OBJ_ID);
        verifyWriteObjIdsValid(
                characteristic, current_group_obj_id, ObjectIds.CURRENT_GROUP_OBJ_ID);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER_SUPPORTED);
        characteristic.setValue(
                playing_order_supported, BluetoothGattCharacteristic.FORMAT_UINT16, 0);
        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        bb = ByteBuffer.allocate(Byte.BYTES);
        bb.put((byte) playing_order.getValue());

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockMcsCallbacks).onPlayingOrderSetRequest(eq(playing_order.getValue()));

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1), eq(BluetoothGatt.GATT_SUCCESS), eq(0),
                        eq(bb.array()));
    }

    private void verifyWriteObjIdsInvalid(
            BluetoothGattCharacteristic characteristic, int id, byte diff_byte) {
        byte[] value = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, diff_byte};
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, value);

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH), eq(0), eq(value));
    }

    @Test
    public void testWriteCallbacksInvalid() {
        BluetoothGattService service = initAllFeaturesGattService();
        int track_position = 100;
        byte playback_speed = 64;
        PlayingOrder playing_order = PlayingOrder.IN_ORDER_REPEAT;
        byte diff_byte = 0x00;

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);

        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES + 1).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) track_position);
        bb.put((byte) 0);

        prepareConnectedDevice();
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH), eq(0), eq(bb.array()));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);

        bb = ByteBuffer.allocate(Byte.BYTES + 1);
        bb.put(playback_speed);
        bb.put((byte) 0);

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH), eq(0), eq(bb.array()));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_TRACK_OBJ_ID);
        verifyWriteObjIdsInvalid(characteristic, ObjectIds.CURRENT_TRACK_OBJ_ID, diff_byte++);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_NEXT_TRACK_OBJ_ID);
        verifyWriteObjIdsInvalid(characteristic, ObjectIds.NEXT_TRACK_OBJ_ID, diff_byte++);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_GROUP_OBJ_ID);
        verifyWriteObjIdsInvalid(characteristic, ObjectIds.CURRENT_GROUP_OBJ_ID, diff_byte++);

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        bb = ByteBuffer.allocate(Byte.BYTES + 1);
        bb.put((byte) playing_order.getValue());
        bb.put((byte) 0);

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH), eq(0), eq(bb.array()));
    }

    private void testNotify(boolean register_for_notification) {
        BluetoothGattService service = initAllFeaturesGattService();
        String player_name = "TestPlayerName";
        String track_title = "Test Song";
        long track_duration = 1000;
        long track_position = 100;
        float playback_speed = 0.5f;
        float seeking_speed = 2.0f;
        Long obj_id = 7l;
        PlayingOrder playing_order = PlayingOrder.IN_ORDER_REPEAT;
        int playing_order_supported = SupportedPlayingOrder.IN_ORDER_REPEAT;
        int playback_state = PlaybackState.SEEKING.getValue();
        Integer opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.NONE
                | McpServiceMediaControlRequest.SupportedOpcodes.PLAY
                | McpServiceMediaControlRequest.SupportedOpcodes.PAUSE
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD
                | McpServiceMediaControlRequest.SupportedOpcodes.STOP
                | McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_GROUP;
        byte[] ccc_val = register_for_notification
                ? BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.clone()
                : BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE.clone();
        int times_cnt = register_for_notification ? 1 : 0;
        int media_control_request_opcode = McpServiceMediaControlRequest.Opcodes.MOVE_RELATIVE;

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_PLAYER_NAME);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updatePlayerNameChar(player_name, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_TITLE);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateTrackTitleChar(track_title, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_DURATION);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateTrackDurationChar(track_duration, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_MEDIA_STATE);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateMediaStateChar(playback_state);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateTrackPositionChar(track_position, false);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updatePlaybackSpeedChar(playback_speed, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEEKING_SPEED);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateSeekingSpeedChar(seeking_speed, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_TRACK_OBJ_ID);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateObjectID(ObjectIds.CURRENT_TRACK_OBJ_ID, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_NEXT_TRACK_OBJ_ID);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateObjectID(ObjectIds.NEXT_TRACK_OBJ_ID, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_CURRENT_GROUP_OBJ_ID);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateObjectID(ObjectIds.CURRENT_GROUP_OBJ_ID, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PARENT_GROUP_OBJ_ID);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateObjectID(ObjectIds.PARENT_GROUP_OBJ_ID, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updatePlayingOrderSupportedChar(playing_order_supported);
        mMcpService.updatePlayingOrderChar(playing_order, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_MEDIA_CONTROL_POINT);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.setMediaControlRequestResult(
                new McpServiceMediaControlRequest(media_control_request_opcode, 0),
                McpServiceMediaControlRequest.Results.SUCCESS);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(
                McpServiceGatt.UUID_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateSupportedOpcodesChar(opcodes_supported, true);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEARCH_RESULT_OBJ_ID);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.updateObjectID(ObjectIds.SEARCH_RESULT_OBJ_ID, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        characteristic = service.getCharacteristic(McpServiceGatt.UUID_SEARCH_CONTROL_POINT);
        prepareConnectedDevicesCccVal(characteristic, ccc_val);
        mMcpService.setSearchRequestResult(null, McpServiceSearchRequest.Results.SUCCESS, obj_id);
        verify(mMockGattServer, times(times_cnt))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));
    }

    @Test
    public void testNotifyRegistered() {
        testNotify(true);
    }

    @Test
    public void testNotifyNotRegistered() {
        testNotify(false);
    }

    private void verifyMediaControlPointRequest(BluetoothGattService service, int opcode,
            Integer value, int expected_gatt_result, int invocation_count) {
        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_MEDIA_CONTROL_POINT);
        ByteBuffer bb;

        if (expected_gatt_result == BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH) {
            bb = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
        } else {
            bb = ByteBuffer.allocate(value != null ? (Integer.BYTES + Byte.BYTES) : Byte.BYTES)
                         .order(ByteOrder.LITTLE_ENDIAN);
        }
        bb.put((byte) opcode);
        if (value != null)
            bb.putInt(value);

        Assert.assertEquals(
                expected_gatt_result, mMcpService.handleMediaControlPointRequest(bb.array()));

        if (expected_gatt_result == BluetoothGatt.GATT_SUCCESS) {
            // Verify if callback comes to profile
            verify(mMockMcsCallbacks, times(invocation_count++))
                    .onMediaControlRequest(any(McpServiceMediaControlRequest.class));
        }
    }

    private void verifyMediaControlPointRequests(int expected_gatt_result) {
        BluetoothGattService service = initAllFeaturesGattService();
        int invocation_count = 1;
        Integer opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.PLAY
                | McpServiceMediaControlRequest.SupportedOpcodes.PAUSE
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD
                | McpServiceMediaControlRequest.SupportedOpcodes.STOP
                | McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_GROUP;

        BluetoothGattCharacteristic characteristic = service.getCharacteristic(
                McpServiceGatt.UUID_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED);
        prepareConnectedDevicesCccVal(
                characteristic, BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE.clone());
        mMcpService.updateSupportedOpcodesChar(opcodes_supported, true);
        verify(mMockGattServer, times(0))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.PLAY, null,
                expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.PAUSE, null,
                expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.FAST_REWIND,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.FAST_FORWARD,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.STOP, null,
                expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.MOVE_RELATIVE,
                100, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service,
                McpServiceMediaControlRequest.Opcodes.PREVIOUS_SEGMENT, null, expected_gatt_result,
                invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.NEXT_SEGMENT,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.FIRST_SEGMENT,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.LAST_SEGMENT,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.GOTO_SEGMENT,
                10, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service,
                McpServiceMediaControlRequest.Opcodes.PREVIOUS_TRACK, null, expected_gatt_result,
                invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.NEXT_TRACK,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.FIRST_TRACK,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.LAST_TRACK,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.GOTO_TRACK, 7,
                expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service,
                McpServiceMediaControlRequest.Opcodes.PREVIOUS_GROUP, null, expected_gatt_result,
                invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.NEXT_GROUP,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.FIRST_GROUP,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.LAST_GROUP,
                null, expected_gatt_result, invocation_count++);
        verifyMediaControlPointRequest(service, McpServiceMediaControlRequest.Opcodes.GOTO_GROUP,
                10, expected_gatt_result, invocation_count++);
    }

    @Test
    public void testMediaControlPointRequestValid() {
        verifyMediaControlPointRequests(BluetoothGatt.GATT_SUCCESS);
    }

    @Test
    public void testMediaControlPointRequestInvalidLength() {
        verifyMediaControlPointRequests(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH);
    }

    @Test
    public void testMediaControlPointRequestInvalid() {
        Integer opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.NONE;

        Assert.assertFalse(
                mMcpService.isOpcodeSupported(McpServiceMediaControlRequest.Opcodes.PLAY));
    }

    @Test
    public void testPlaybackSpeedWrite() {
        BluetoothGattService service = initAllFeaturesGattService();
        byte playback_speed = -64;

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_PLAYBACK_SPEED);
        prepareConnectedDevicesCccVal(
                characteristic, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.clone());

        ByteBuffer bb = ByteBuffer.allocate(Byte.BYTES);
        bb.put(playback_speed);

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockMcsCallbacks)
                .onPlaybackSpeedSetRequest(eq(MathUtils.pow(2, playback_speed / 64)));

        // Fake characteristic write - this is done by player status update
        characteristic.setValue(playback_speed, BluetoothGattCharacteristic.FORMAT_SINT8, 0);

        // Second set of the same value - does not bother player only sends notification
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockGattServer, times(1))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));
    }

    @Test
    public void testUpdateSupportedOpcodesChar() {
        BluetoothGattService service = initAllFeaturesGattService();
        Integer opcodes_supported = McpServiceMediaControlRequest.SupportedOpcodes.PLAY
                | McpServiceMediaControlRequest.SupportedOpcodes.PAUSE
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_REWIND
                | McpServiceMediaControlRequest.SupportedOpcodes.FAST_FORWARD
                | McpServiceMediaControlRequest.SupportedOpcodes.STOP
                | McpServiceMediaControlRequest.SupportedOpcodes.MOVE_RELATIVE
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_SEGMENT
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_TRACK
                | McpServiceMediaControlRequest.SupportedOpcodes.PREVIOUS_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.NEXT_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.FIRST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.LAST_GROUP
                | McpServiceMediaControlRequest.SupportedOpcodes.GOTO_GROUP;

        BluetoothGattCharacteristic characteristic = service.getCharacteristic(
                McpServiceGatt.UUID_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED);
        prepareConnectedDevicesCccVal(
                characteristic, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.clone());

        mMcpService.updateSupportedOpcodesChar(opcodes_supported, true);
        verify(mMockGattServer, times(1))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        // Verify if there will be no new notification triggered when nothing changes
        mMcpService.updateSupportedOpcodesChar(opcodes_supported, true);
        verify(mMockGattServer, times(1))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));

        opcodes_supported = 0;
        mMcpService.updateSupportedOpcodesChar(opcodes_supported, true);
        verify(mMockGattServer, times(2))
                .notifyCharacteristicChanged(eq(mCurrentDevice), eq(characteristic), eq(false));
    }

    @Test
    public void testPlayingOrderSupportedChar() {
        BluetoothGattService service = initAllFeaturesGattService();
        int playing_order_supported =
                SupportedPlayingOrder.IN_ORDER_REPEAT | SupportedPlayingOrder.NEWEST_ONCE;
        PlayingOrder playing_order = PlayingOrder.IN_ORDER_REPEAT;
        ByteBuffer bb = ByteBuffer.allocate(Byte.BYTES);

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_PLAYING_ORDER);
        prepareConnectedDevicesCccVal(
                characteristic, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE.clone());

        mMcpService.updatePlayingOrderSupportedChar(playing_order_supported);

        bb.put((byte) playing_order.getValue());
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());
        verify(mMockMcsCallbacks, times(1)).onPlayingOrderSetRequest(anyInt());

        // Not supported playing order should be ignored
        playing_order = PlayingOrder.SHUFFLE_ONCE;
        bb.put(0, (byte) playing_order.getValue());
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());
        verify(mMockMcsCallbacks, times(1)).onPlayingOrderSetRequest(anyInt());

        playing_order = PlayingOrder.NEWEST_ONCE;
        bb.put(0, (byte) playing_order.getValue());
        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());
        verify(mMockMcsCallbacks, times(2)).onPlayingOrderSetRequest(anyInt());
    }

    @Test
    public void testCharacteristicReadUnauthorized() {
        BluetoothGattService service = initAllFeaturesGattService();

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);

        prepareConnectedDevice();
        doReturn(BluetoothDevice.ACCESS_REJECTED)
                .when(mMockMcpServiceManager)
                .getDeviceAuthorization(any(BluetoothDevice.class));

        mMcpService.mServerCallback.onCharacteristicReadRequest(
                mCurrentDevice, 1, 0, characteristic);

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INSUFFICIENT_AUTHORIZATION), eq(0), any());
    }

    @Test
    public void testCharacteristicWriteUnauthorized() {
        BluetoothGattService service = initAllFeaturesGattService();
        int track_position = 100;

        BluetoothGattCharacteristic characteristic =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION);

        ByteBuffer bb = ByteBuffer.allocate(Integer.BYTES + 1).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) track_position);
        bb.put((byte) 0);

        prepareConnectedDevice();
        doReturn(BluetoothDevice.ACCESS_REJECTED)
                .when(mMockMcpServiceManager)
                .getDeviceAuthorization(any(BluetoothDevice.class));

        mMcpService.mServerCallback.onCharacteristicWriteRequest(
                mCurrentDevice, 1, characteristic, false, true, 0, bb.array());

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INSUFFICIENT_AUTHORIZATION), eq(0), any());
    }

    @Test
    public void testDescriptorReadUnauthorized() {
        BluetoothGattService service = initAllFeaturesGattService();

        BluetoothGattDescriptor descriptor =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION)
                        .getDescriptor(UUID_CCCD);
        Assert.assertNotNull(descriptor);

        prepareConnectedDevice();
        doReturn(BluetoothDevice.ACCESS_REJECTED)
                .when(mMockMcpServiceManager)
                .getDeviceAuthorization(any(BluetoothDevice.class));

        mMcpService.mServerCallback.onDescriptorReadRequest(mCurrentDevice, 1, 0, descriptor);

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INSUFFICIENT_AUTHORIZATION), eq(0), any());
    }

    @Test
    public void testDescriptorWriteUnauthorized() {
        BluetoothGattService service = initAllFeaturesGattService();

        BluetoothGattDescriptor descriptor =
                service.getCharacteristic(McpServiceGatt.UUID_TRACK_POSITION)
                        .getDescriptor(UUID_CCCD);
        Assert.assertNotNull(descriptor);

        prepareConnectedDevice();
        doReturn(BluetoothDevice.ACCESS_REJECTED)
                .when(mMockMcpServiceManager)
                .getDeviceAuthorization(any(BluetoothDevice.class));

        ByteBuffer bb = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);
        bb.put((byte) 0);
        bb.put((byte) 1);

        mMcpService.mServerCallback.onDescriptorWriteRequest(
                mCurrentDevice, 1, descriptor, false, true, 0, bb.array());

        verify(mMockGattServer)
                .sendResponse(eq(mCurrentDevice), eq(1),
                        eq(BluetoothGatt.GATT_INSUFFICIENT_AUTHORIZATION), eq(0), any());
    }
}
