/*
 * Copyright 2017 The Android Open Source Project
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

package com.android.bluetooth.hfp;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.media.AudioManager;
import android.os.HandlerThread;
import android.os.UserHandle;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Tests for {@link HeadsetStateMachine}
 */
@MediumTest
@RunWith(AndroidJUnit4.class)
public class HeadsetStateMachineTest {
    private static final int CONNECT_TIMEOUT_TEST_MILLIS = 1000;
    private static final int CONNECT_TIMEOUT_TEST_WAIT_MILLIS = CONNECT_TIMEOUT_TEST_MILLIS * 3 / 2;
    private static final int ASYNC_CALL_TIMEOUT_MILLIS = 250;
    private Context mTargetContext;
    private BluetoothAdapter mAdapter;
    private HandlerThread mHandlerThread;
    private HeadsetStateMachine mHeadsetStateMachine;
    private BluetoothDevice mTestDevice;
    private ArgumentCaptor<Intent> mIntentArgument = ArgumentCaptor.forClass(Intent.class);

    @Mock private AdapterService mAdapterService;
    @Mock private HeadsetService mHeadsetService;
    @Mock private HeadsetSystemInterface mSystemInterface;
    @Mock private AudioManager mAudioManager;
    @Mock private HeadsetPhoneState mPhoneState;
    private HeadsetNativeInterface mNativeInterface;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when HeadsetService is not enabled",
                mTargetContext.getResources().getBoolean(R.bool.profile_supported_hs_hfp));
        // Setup mocks and test assets
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);
        // Stub system interface
        when(mSystemInterface.getHeadsetPhoneState()).thenReturn(mPhoneState);
        when(mSystemInterface.getAudioManager()).thenReturn(mAudioManager);
        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");
        // Spy on native interface
        mNativeInterface = spy(HeadsetNativeInterface.getInstance());
        doNothing().when(mNativeInterface).init(anyInt(), anyBoolean());
        doReturn(true).when(mNativeInterface).connectHfp(mTestDevice);
        doReturn(true).when(mNativeInterface).disconnectHfp(mTestDevice);
        doReturn(true).when(mNativeInterface).connectAudio(mTestDevice);
        doReturn(true).when(mNativeInterface).disconnectAudio(mTestDevice);
        // Stub headset service
        doReturn(BluetoothDevice.BOND_BONDED).when(mAdapterService)
                .getBondState(any(BluetoothDevice.class));
        when(mHeadsetService.bindService(any(Intent.class), any(ServiceConnection.class), anyInt()))
                .thenReturn(true);
        when(mHeadsetService.getResources()).thenReturn(
                InstrumentationRegistry.getTargetContext().getResources());
        when(mHeadsetService.getPackageManager()).thenReturn(
                InstrumentationRegistry.getContext().getPackageManager());
        when(mHeadsetService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);
        when(mHeadsetService.getForceScoAudio()).thenReturn(true);
        when(mHeadsetService.okToAcceptConnection(any(BluetoothDevice.class))).thenReturn(true);
        // Setup thread and looper
        mHandlerThread = new HandlerThread("HeadsetStateMachineTestHandlerThread");
        mHandlerThread.start();
        // Modify CONNECT timeout to a smaller value for test only
        HeadsetStateMachine.sConnectTimeoutMs = CONNECT_TIMEOUT_TEST_MILLIS;
        mHeadsetStateMachine = HeadsetObjectsFactory.getInstance()
                .makeStateMachine(mTestDevice, mHandlerThread.getLooper(), mHeadsetService,
                        mAdapterService, mNativeInterface, mSystemInterface);
    }

    @After
    public void tearDown() throws Exception {
        if (!mTargetContext.getResources().getBoolean(R.bool.profile_supported_hs_hfp)) {
            return;
        }
        HeadsetObjectsFactory.getInstance().destroyStateMachine(mHeadsetStateMachine);
        mHandlerThread.quit();
        TestUtils.clearAdapterService(mAdapterService);
    }

    /**
     * Test that default state is Disconnected
     */
    @Test
    public void testDefaultDisconnectedState() {
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                mHeadsetStateMachine.getConnectionState());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test that state is Connected after calling setUpConnectedState()
     */
    @Test
    public void testSetupConnectedState() {
        setUpConnectedState();
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetStateMachine.getConnectionState());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from Disconnected to Connecting state via CONNECT message
     */
    @Test
    public void testStateTransition_DisconnectedToConnecting_Connect() {
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.CONNECT, mTestDevice);
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));
    }

    /**
     * Test state transition from Disconnected to Connecting state via StackEvent.CONNECTED message
     */
    @Test
    public void testStateTransition_DisconnectedToConnecting_StackConnected() {
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));
    }

    /**
     * Test state transition from Disconnected to Connecting state via StackEvent.CONNECTING message
     */
    @Test
    public void testStateTransition_DisconnectedToConnecting_StackConnecting() {
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTING, mTestDevice));
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));
    }

    /**
     * Test state transition from Connecting to Disconnected state via StackEvent.DISCONNECTED
     * message
     */
    @Test
    public void testStateTransition_ConnectingToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpConnectingState();
        // Indicate disconnecting to test state machine, which should do nothing
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING, mTestDevice));
        // Should do nothing new
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), any(UserHandle.class), anyString());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));

        // Indicate connection failed to test state machine
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));

        numBroadcastsSent++;
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from Connecting to Disconnected state via CONNECT_TIMEOUT message
     */
    @Test
    public void testStateTransition_ConnectingToDisconnected_Timeout() {
        int numBroadcastsSent = setUpConnectingState();
        // Let the connection timeout
        numBroadcastsSent++;
        verify(mHeadsetService, timeout(CONNECT_TIMEOUT_TEST_WAIT_MILLIS).times(
                numBroadcastsSent)).sendBroadcastAsUser(mIntentArgument.capture(),
                eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from Connecting to Connected state via StackEvent.SLC_CONNECTED message
     */
    @Test
    public void testStateTransition_ConnectingToConnected_StackSlcConnected() {
        int numBroadcastsSent = setUpConnectingState();
        // Indicate connecting to test state machine
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTING, mTestDevice));
        // Should do nothing
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), any(UserHandle.class), anyString());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));

        // Indicate RFCOMM connection is successful to test state machine
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTED, mTestDevice));
        // Should do nothing
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), any(UserHandle.class), anyString());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));

        // Indicate SLC connection is successful to test state machine
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from Disconnecting to Disconnected state via StackEvent.DISCONNECTED
     * message
     */
    @Test
    public void testStateTransition_DisconnectingToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpDisconnectingState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_DISCONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from Disconnecting to Disconnected state via CONNECT_TIMEOUT
     * message
     */
    @Test
    public void testStateTransition_DisconnectingToDisconnected_Timeout() {
        int numBroadcastsSent = setUpDisconnectingState();
        // Let the connection timeout
        numBroadcastsSent++;
        verify(mHeadsetService, timeout(CONNECT_TIMEOUT_TEST_WAIT_MILLIS).times(
                numBroadcastsSent)).sendBroadcastAsUser(mIntentArgument.capture(),
                eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_DISCONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from Disconnecting to Connected state via StackEvent.SLC_CONNECTED
     * message
     */
    @Test
    public void testStateTransition_DisconnectingToConnected_StackSlcCconnected() {
        int numBroadcastsSent = setUpDisconnectingState();
        // Send StackEvent.SLC_CONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_DISCONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from Connected to Disconnecting state via DISCONNECT message
     */
    @Test
    public void testStateTransition_ConnectedToDisconnecting_Disconnect() {
        int numBroadcastsSent = setUpConnectedState();
        // Send DISCONNECT message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT, mTestDevice);
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
    }

    /**
     * Test state transition from Connected to Disconnecting state via StackEvent.DISCONNECTING
     * message
     */
    @Test
    public void testStateTransition_ConnectedToDisconnecting_StackDisconnecting() {
        int numBroadcastsSent = setUpConnectedState();
        // Send StackEvent.DISCONNECTING message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
    }

    /**
     * Test state transition from Connected to Disconnected state via StackEvent.DISCONNECTED
     * message
     */
    @Test
    public void testStateTransition_ConnectedToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpConnectedState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from Connected to AudioConnecting state via CONNECT_AUDIO message
     */
    @Test
    public void testStateTransition_ConnectedToAudioConnecting_ConnectAudio() {
        int numBroadcastsSent = setUpConnectedState();
        // Send CONNECT_AUDIO message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.CONNECT_AUDIO, mTestDevice);
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTING,
                BluetoothHeadset.STATE_AUDIO_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioConnecting.class));
    }

    /**
     * Test state transition from Connected to AudioConnecting state via
     * StackEvent.AUDIO_CONNECTING message
     */
    @Test
    public void testStateTransition_ConnectedToAudioConnecting_StackAudioConnecting() {
        int numBroadcastsSent = setUpConnectedState();
        // Send StackEvent.AUDIO_CONNECTING message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_CONNECTING, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTING,
                BluetoothHeadset.STATE_AUDIO_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioConnecting.class));
    }

    /**
     * Test state transition from Connected to AudioOn state via StackEvent.AUDIO_CONNECTED message
     */
    @Test
    public void testStateTransition_ConnectedToAudioOn_StackAudioConnected() {
        int numBroadcastsSent = setUpConnectedState();
        // Send StackEvent.AUDIO_CONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTED,
                BluetoothHeadset.STATE_AUDIO_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioOn.class));
    }

    /**
     * Test state transition from AudioConnecting to Connected state via CONNECT_TIMEOUT message
     */
    @Test
    public void testStateTransition_AudioConnectingToConnected_Timeout() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Wait for connection to timeout
        numBroadcastsSent++;
        verify(mHeadsetService, timeout(CONNECT_TIMEOUT_TEST_WAIT_MILLIS).times(
                numBroadcastsSent)).sendBroadcastAsUser(mIntentArgument.capture(),
                eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from AudioConnecting to Connected state via
     * StackEvent.AUDIO_DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioConnectingToConnected_StackAudioDisconnected() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Send StackEvent.AUDIO_DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from AudioConnecting to Disconnected state via
     * StackEvent.DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioConnectingToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from AudioConnecting to Disconnecting state via
     * StackEvent.DISCONNECTING message
     */
    @Test
    public void testStateTransition_AudioConnectingToDisconnecting_StackDisconnecting() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
    }

    /**
     * Test state transition from AudioConnecting to AudioOn state via
     * StackEvent.AUDIO_CONNECTED message
     */
    @Test
    public void testStateTransition_AudioConnectingToAudioOn_StackAudioConnected() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Send StackEvent.AUDIO_DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioOn.class));
    }

    /**
     * Test state transition from AudioOn to AudioDisconnecting state via
     * StackEvent.AUDIO_DISCONNECTING message
     */
    @Test
    public void testStateTransition_AudioOnToAudioDisconnecting_StackAudioDisconnecting() {
        int numBroadcastsSent = setUpAudioOnState();
        // Send StackEvent.AUDIO_DISCONNECTING message
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_DISCONNECTING, mTestDevice));
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioDisconnecting.class));
    }

    /**
     * Test state transition from AudioOn to AudioDisconnecting state via
     * DISCONNECT_AUDIO message
     */
    @Test
    public void testStateTransition_AudioOnToAudioDisconnecting_DisconnectAudio() {
        int numBroadcastsSent = setUpAudioOnState();
        // Send DISCONNECT_AUDIO message
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT_AUDIO, mTestDevice);
        // Should not sent any broadcast due to lack of AUDIO_DISCONNECTING intent value
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioDisconnecting.class));
    }

    /**
     * Test state transition from AudioOn to AudioDisconnecting state via
     * Stack.AUDIO_DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioOnToConnected_StackAudioDisconnected() {
        int numBroadcastsSent = setUpAudioOnState();
        // Send DISCONNECT_AUDIO message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from AudioOn to Disconnected state via
     * Stack.DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioOnToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpAudioOnState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Test state transition from AudioOn to Disconnecting state via
     * Stack.DISCONNECTING message
     */
    @Test
    public void testStateTransition_AudioOnToDisconnecting_StackDisconnecting() {
        int numBroadcastsSent = setUpAudioOnState();
        // Send StackEvent.DISCONNECTING message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
    }

    /**
     * Test state transition from AudioDisconnecting to Connected state via
     * CONNECT_TIMEOUT message
     */
    @Test
    public void testStateTransition_AudioDisconnectingToConnected_Timeout() {
        int numBroadcastsSent = setUpAudioDisconnectingState();
        // Wait for connection to timeout
        numBroadcastsSent++;
        verify(mHeadsetService, timeout(CONNECT_TIMEOUT_TEST_WAIT_MILLIS).times(
                numBroadcastsSent)).sendBroadcastAsUser(mIntentArgument.capture(),
                eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from AudioDisconnecting to Connected state via
     * Stack.AUDIO_DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioDisconnectingToConnected_StackAudioDisconnected() {
        int numBroadcastsSent = setUpAudioDisconnectingState();
        // Send Stack.AUDIO_DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
    }

    /**
     * Test state transition from AudioDisconnecting to AudioOn state via
     * Stack.AUDIO_CONNECTED message
     */
    @Test
    public void testStateTransition_AudioDisconnectingToAudioOn_StackAudioConnected() {
        int numBroadcastsSent = setUpAudioDisconnectingState();
        // Send Stack.AUDIO_CONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioOn.class));
    }

    /**
     * Test state transition from AudioDisconnecting to Disconnecting state via
     * Stack.DISCONNECTING message
     */
    @Test
    public void testStateTransition_AudioDisconnectingToDisconnecting_StackDisconnecting() {
        int numBroadcastsSent = setUpAudioDisconnectingState();
        // Send StackEvent.DISCONNECTING message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTING, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
    }

    /**
     * Test state transition from AudioDisconnecting to Disconnecting state via
     * Stack.DISCONNECTED message
     */
    @Test
    public void testStateTransition_AudioDisconnectingToDisconnected_StackDisconnected() {
        int numBroadcastsSent = setUpAudioDisconnectingState();
        // Send StackEvent.DISCONNECTED message
        numBroadcastsSent += 2;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 2));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTED,
                mIntentArgument.getAllValues().get(mIntentArgument.getAllValues().size() - 1));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnected.class));
    }

    /**
     * Setup Connecting State
     * @return number of times mHeadsetService.sendBroadcastAsUser() has been invoked
     */
    private int setUpConnectingState() {
        // Put test state machine in connecting state
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.CONNECT, mTestDevice);
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));
        return 1;
    }

    /**
     * Setup Connected State
     * @return number of times mHeadsetService.sendBroadcastAsUser() has been invoked
     */
    private int setUpConnectedState() {
        // Put test state machine into connected state
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connecting.class));
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mTestDevice));
        verify(mHeadsetService, timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(2)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Connected.class));
        return 2;
    }

    private int setUpAudioConnectingState() {
        int numBroadcastsSent = setUpConnectedState();
        // Send CONNECT_AUDIO
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.CONNECT_AUDIO, mTestDevice);
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTING,
                BluetoothHeadset.STATE_AUDIO_DISCONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioConnecting.class));
        return numBroadcastsSent;
    }

    private int setUpAudioOnState() {
        int numBroadcastsSent = setUpAudioConnectingState();
        // Send StackEvent.AUDIO_DISCONNECTED message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.STACK_EVENT,
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_AUDIO_STATE_CHANGED,
                        HeadsetHalConstants.AUDIO_STATE_CONNECTED, mTestDevice));
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyAudioStateBroadcast(mTestDevice, BluetoothHeadset.STATE_AUDIO_CONNECTED,
                BluetoothHeadset.STATE_AUDIO_CONNECTING, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioOn.class));
        return numBroadcastsSent;
    }

    private int setUpAudioDisconnectingState() {
        int numBroadcastsSent = setUpAudioOnState();
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT_AUDIO, mTestDevice);
        // No new broadcast due to lack of AUDIO_DISCONNECTING intent variable
        verify(mHeadsetService,
                after(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                any(Intent.class), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.AudioDisconnecting.class));
        return numBroadcastsSent;
    }

    private int setUpDisconnectingState() {
        int numBroadcastsSent = setUpConnectedState();
        // Send DISCONNECT message
        numBroadcastsSent++;
        mHeadsetStateMachine.sendMessage(HeadsetStateMachine.DISCONNECT, mTestDevice);
        verify(mHeadsetService,
                timeout(ASYNC_CALL_TIMEOUT_MILLIS).times(numBroadcastsSent)).sendBroadcastAsUser(
                mIntentArgument.capture(), eq(UserHandle.ALL), eq(HeadsetService.BLUETOOTH_PERM));
        verifyConnectionStateBroadcast(mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                BluetoothProfile.STATE_CONNECTED, mIntentArgument.getValue());
        Assert.assertThat(mHeadsetStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetStateMachine.Disconnecting.class));
        return numBroadcastsSent;
    }


    private static void verifyAudioStateBroadcast(BluetoothDevice device, int toState,
            int fromState, Intent intent) {
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHeadset.ACTION_AUDIO_STATE_CHANGED, intent.getAction());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(toState, intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        Assert.assertEquals(fromState,
                intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1));
    }

    private static void verifyConnectionStateBroadcast(BluetoothDevice device, int toState,
            int fromState, Intent intent) {
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED, intent.getAction());
        Assert.assertEquals(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND, intent.getFlags());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(toState, intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        Assert.assertEquals(fromState,
                intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1));
    }
}
