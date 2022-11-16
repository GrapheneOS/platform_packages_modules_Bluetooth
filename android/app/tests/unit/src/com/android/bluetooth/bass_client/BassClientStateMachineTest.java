/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.bluetooth.bass_client;

import static android.bluetooth.BluetoothGatt.GATT_SUCCESS;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothProfile;
import android.content.Intent;
import android.os.Bundle;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.telecom.Log;

import androidx.test.filters.MediumTest;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import static com.google.common.truth.Truth.assertThat;

import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.UUID;

@MediumTest
@RunWith(JUnit4.class)
public class BassClientStateMachineTest {
    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

    private static final int CONNECTION_TIMEOUT_MS = 1_000;
    private static final int TIMEOUT_MS = 2_000;
    private static final int WAIT_MS = 1_200;
    private BluetoothAdapter mAdapter;
    private HandlerThread mHandlerThread;
    private StubBassClientStateMachine mBassClientStateMachine;
    private BluetoothDevice mTestDevice;
    @Mock
    private AdapterService mAdapterService;
    @Mock
    private BassClientService mBassClientService;

    @Before
    public void setUp() throws Exception {
        TestUtils.setAdapterService(mAdapterService);

        mAdapter = BluetoothAdapter.getDefaultAdapter();

        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        // Set up thread and looper
        mHandlerThread = new HandlerThread("BassClientStateMachineTestHandlerThread");
        mHandlerThread.start();
        mBassClientStateMachine = new StubBassClientStateMachine(mTestDevice,
                mBassClientService, mHandlerThread.getLooper(), CONNECTION_TIMEOUT_MS);
        mBassClientStateMachine.start();
    }

    @After
    public void tearDown() throws Exception {
        mBassClientStateMachine.doQuit();
        mHandlerThread.quit();
        TestUtils.clearAdapterService(mAdapterService);
    }

    /**
     * Test that default state is disconnected
     */
    @Test
    public void testDefaultDisconnectedState() {
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                mBassClientStateMachine.getConnectionState());
    }

    /**
     * Allow/disallow connection to any device.
     *
     * @param allow if true, connection is allowed
     */
    private void allowConnection(boolean allow) {
        when(mBassClientService.okToConnect(any(BluetoothDevice.class))).thenReturn(allow);
    }

    private void allowConnectGatt(boolean allow) {
        mBassClientStateMachine.mShouldAllowGatt = allow;
    }

    /**
     * Test that an incoming connection with policy forbidding connection is rejected
     */
    @Test
    public void testOkToConnectFails() {
        allowConnection(false);
        allowConnectGatt(true);

        // Inject an event for when incoming connection is requested
        mBassClientStateMachine.sendMessage(BassClientStateMachine.CONNECT);

        // Verify that no connection state broadcast is executed
        verify(mBassClientService, after(WAIT_MS).never()).sendBroadcast(any(Intent.class),
                anyString());

        // Check that we are in Disconnected state
        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Disconnected.class));
    }

    @Test
    public void testFailToConnectGatt() {
        allowConnection(true);
        allowConnectGatt(false);

        // Inject an event for when incoming connection is requested
        mBassClientStateMachine.sendMessage(BassClientStateMachine.CONNECT);

        // Verify that no connection state broadcast is executed
        verify(mBassClientService, after(WAIT_MS).never()).sendBroadcast(any(Intent.class),
                anyString());

        // Check that we are in Disconnected state
        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Disconnected.class));
        assertNull(mBassClientStateMachine.mBluetoothGatt);
    }

    @Test
    public void testSuccessfullyConnected() {
        allowConnection(true);
        allowConnectGatt(true);

        // Inject an event for when incoming connection is requested
        mBassClientStateMachine.sendMessage(BassClientStateMachine.CONNECT);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mBassClientService, timeout(TIMEOUT_MS).times(1)).sendBroadcast(
                intentArgument1.capture(), anyString(), any(Bundle.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Connecting.class));

        assertNotNull(mBassClientStateMachine.mGattCallback);
        mBassClientStateMachine.notifyConnectionStateChanged(
                GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED);

        // Verify that the expected number of broadcasts are executed:
        // - two calls to broadcastConnectionState(): Disconnected -> Connecting -> Connected
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mBassClientService, timeout(TIMEOUT_MS).times(2)).sendBroadcast(
                intentArgument2.capture(), anyString(), any(Bundle.class));

        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Connected.class));
    }

    @Test
    public void testConnectGattTimeout() {
        allowConnection(true);
        allowConnectGatt(true);

        // Inject an event for when incoming connection is requested
        mBassClientStateMachine.sendMessage(BassClientStateMachine.CONNECT);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mBassClientService, timeout(TIMEOUT_MS).times(1)).sendBroadcast(
                intentArgument1.capture(), anyString(), any(Bundle.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Connecting.class));

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mBassClientService, timeout(TIMEOUT_MS).times(
                2)).sendBroadcast(intentArgument2.capture(), anyString(), any(Bundle.class));
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        Assert.assertThat(mBassClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(BassClientStateMachine.Disconnected.class));
    }

    @Test
    public void testStatesChangesWithMessages() {
        allowConnection(true);
        allowConnectGatt(true);

        assertThat(mBassClientStateMachine.getCurrentState())
                .isInstanceOf(BassClientStateMachine.Disconnected.class);

        // disconnected -> connecting ---timeout---> disconnected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT),
                BassClientStateMachine.Connecting.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT_TIMEOUT),
                BassClientStateMachine.Disconnected.class);

        // disconnected -> connecting ---DISCONNECT---> disconnected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT),
                BassClientStateMachine.Connecting.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.DISCONNECT),
                BassClientStateMachine.Disconnected.class);

        // disconnected -> connecting ---CONNECTION_STATE_CHANGED(connected)---> connected -->
        // disconnected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT),
                BassClientStateMachine.Connecting.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.CONNECTION_STATE_CHANGED,
                        Integer.valueOf(BluetoothProfile.STATE_CONNECTED)),
                BassClientStateMachine.Connected.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.CONNECTION_STATE_CHANGED,
                        Integer.valueOf(BluetoothProfile.STATE_DISCONNECTED)),
                BassClientStateMachine.Disconnected.class);

        // disconnected -> connecting ---CONNECTION_STATE_CHANGED(non-connected) --> disconnected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT),
                BassClientStateMachine.Connecting.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.CONNECTION_STATE_CHANGED,
                        Integer.valueOf(BluetoothProfile.STATE_DISCONNECTED)),
                BassClientStateMachine.Disconnected.class);

        // change default state to connected for the next tests
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.CONNECT),
                BassClientStateMachine.Connecting.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.CONNECTION_STATE_CHANGED,
                        Integer.valueOf(BluetoothProfile.STATE_CONNECTED)),
                BassClientStateMachine.Connected.class);

        // connected ----READ_BASS_CHARACTERISTICS---> connectedProcessing --GATT_TXN_PROCESSED
        // --> connected


        // Make bluetoothGatt non-null so state will transit
        mBassClientStateMachine.mBluetoothGatt = Mockito.mock(
                BassClientStateMachine.BluetoothGattTestableWrapper.class);
        mBassClientStateMachine.mBroadcastScanControlPoint = new BluetoothGattCharacteristic(
                BassConstants.BASS_BCAST_AUDIO_SCAN_CTRL_POINT,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ);

        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.READ_BASS_CHARACTERISTICS,
                        new BluetoothGattCharacteristic(UUID.randomUUID(),
                                BluetoothGattCharacteristic.PROPERTY_READ,
                                BluetoothGattCharacteristic.PERMISSION_READ)),
                BassClientStateMachine.ConnectedProcessing.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.GATT_TXN_PROCESSED),
                BassClientStateMachine.Connected.class);

        // connected ----READ_BASS_CHARACTERISTICS---> connectedProcessing --GATT_TXN_TIMEOUT -->
        // connected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(
                        BassClientStateMachine.READ_BASS_CHARACTERISTICS,
                        new BluetoothGattCharacteristic(UUID.randomUUID(),
                                BluetoothGattCharacteristic.PROPERTY_READ,
                                BluetoothGattCharacteristic.PERMISSION_READ)),
                BassClientStateMachine.ConnectedProcessing.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.GATT_TXN_TIMEOUT),
                BassClientStateMachine.Connected.class);

        // connected ----START_SCAN_OFFLOAD---> connectedProcessing --GATT_TXN_PROCESSED-->
        // connected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.START_SCAN_OFFLOAD),
                BassClientStateMachine.ConnectedProcessing.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.GATT_TXN_PROCESSED),
                BassClientStateMachine.Connected.class);

        // connected ----STOP_SCAN_OFFLOAD---> connectedProcessing --GATT_TXN_PROCESSED--> connected
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.STOP_SCAN_OFFLOAD),
                BassClientStateMachine.ConnectedProcessing.class);
        sendMessageAndVerifyTransition(
                mBassClientStateMachine.obtainMessage(BassClientStateMachine.GATT_TXN_PROCESSED),
                BassClientStateMachine.Connected.class);
    }

    private <T> void sendMessageAndVerifyTransition(Message msg, Class<T> type) {
        Mockito.clearInvocations(mBassClientService);
        mBassClientStateMachine.sendMessage(msg);
        // Verify that one connection state broadcast is executed
        verify(mBassClientService, timeout(TIMEOUT_MS)
                .times(1))
                .sendBroadcast(any(Intent.class), anyString(), any());
        Assert.assertThat(mBassClientStateMachine.getCurrentState(), IsInstanceOf.instanceOf(type));
    }


    // It simulates GATT connection for testing.
    public static class StubBassClientStateMachine extends BassClientStateMachine {
        boolean mShouldAllowGatt = true;

        StubBassClientStateMachine(BluetoothDevice device, BassClientService service, Looper looper,
                int connectTimeout) {
            super(device, service, looper, connectTimeout);
        }

        @Override
        public boolean connectGatt(Boolean autoConnect) {
            mGattCallback = new GattCallback();
            return mShouldAllowGatt;
        }

        public void notifyConnectionStateChanged(int status, int newState) {
            if (mGattCallback != null) {
                BluetoothGatt gatt = null;
                if (mBluetoothGatt != null) {
                    gatt = mBluetoothGatt.mWrappedBluetoothGatt;
                }
                mGattCallback.onConnectionStateChange(gatt, status, newState);
            }
        }
    }
}
