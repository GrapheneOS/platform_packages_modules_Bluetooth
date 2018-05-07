/*
 * Copyright 2018 The Android Open Source Project
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

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import android.app.Activity;
import android.app.Instrumentation;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothHeadset;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.net.Uri;
import android.os.ParcelUuid;
import android.os.RemoteException;
import android.support.test.InstrumentationRegistry;
import android.support.test.espresso.intent.Intents;
import android.support.test.espresso.intent.matcher.IntentMatchers;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.telecom.PhoneAccount;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A set of integration test that involves both {@link HeadsetService} and
 * {@link HeadsetStateMachine}
 */
@MediumTest
@RunWith(AndroidJUnit4.class)
public class HeadsetServiceAndStateMachineTest {
    private static final int ASYNC_CALL_TIMEOUT_MILLIS = 250;
    private static final int MAX_HEADSET_CONNECTIONS = 5;
    private static final ParcelUuid[] FAKE_HEADSET_UUID = {BluetoothUuid.Handsfree};
    private static final String TEST_PHONE_NUMBER = "1234567890";

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    private Context mTargetContext;
    private HeadsetService mHeadsetService;
    private IBluetoothHeadset.Stub mHeadsetServiceBinder;
    private BluetoothAdapter mAdapter;
    private HeadsetNativeInterface mNativeInterface;
    private BluetoothDevice mCurrentDevice;
    private ArgumentCaptor<HeadsetStateMachine> mStateMachineArgument =
            ArgumentCaptor.forClass(HeadsetStateMachine.class);
    private ArrayList<BluetoothDevice> mBondedDevices = new ArrayList<>();
    private final BlockingQueue<Intent> mConnectionStateChangedQueue = new LinkedBlockingQueue<>();
    private final BlockingQueue<Intent> mActiveDeviceChangedQueue = new LinkedBlockingQueue<>();
    private HeadsetIntentReceiver mHeadsetIntentReceiver;

    private class HeadsetIntentReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) {
                Assert.fail("Action is null for intent " + intent);
                return;
            }
            switch (action) {
                case BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED:
                    try {
                        mConnectionStateChangedQueue.put(intent);
                    } catch (InterruptedException e) {
                        Assert.fail("Cannot add Intent to the Connection State Changed queue: "
                                + e.getMessage());
                    }
                    break;
                case BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED:
                    try {
                        mActiveDeviceChangedQueue.put(intent);
                    } catch (InterruptedException e) {
                        Assert.fail("Cannot add Intent to the Active Device Changed queue: "
                                + e.getMessage());
                    }
                    break;
                default:
                    Assert.fail("Unknown action " + action);
            }

        }
    }

    @Spy private HeadsetObjectsFactory mObjectsFactory = HeadsetObjectsFactory.getInstance();
    @Mock private AdapterService mAdapterService;
    @Mock private HeadsetSystemInterface mSystemInterface;
    @Mock private AudioManager mAudioManager;
    @Mock private HeadsetPhoneState mPhoneState;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when HeadsetService is not enabled",
                mTargetContext.getResources().getBoolean(R.bool.profile_supported_hs_hfp));
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);
        doReturn(true).when(mAdapterService).isEnabled();
        doReturn(MAX_HEADSET_CONNECTIONS).when(mAdapterService).getMaxConnectedAudioDevices();
        doReturn(new ParcelUuid[]{BluetoothUuid.Handsfree}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        // We cannot mock HeadsetObjectsFactory.getInstance() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the HeadsetObjectsFactory.sInstance field.
        Method method = HeadsetObjectsFactory.class.getDeclaredMethod("setInstanceForTesting",
                HeadsetObjectsFactory.class);
        method.setAccessible(true);
        method.invoke(null, mObjectsFactory);
        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Mock methods in AdapterService
        doReturn(FAKE_HEADSET_UUID).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        doReturn(BluetoothDevice.BOND_BONDED).when(mAdapterService)
                .getBondState(any(BluetoothDevice.class));
        doAnswer(invocation -> mBondedDevices.toArray(new BluetoothDevice[]{})).when(
                mAdapterService).getBondedDevices();
        // Mock system interface
        doNothing().when(mSystemInterface).init();
        doNothing().when(mSystemInterface).stop();
        when(mSystemInterface.getHeadsetPhoneState()).thenReturn(mPhoneState);
        when(mSystemInterface.getAudioManager()).thenReturn(mAudioManager);
        // Mock methods in HeadsetNativeInterface
        mNativeInterface = spy(HeadsetNativeInterface.getInstance());
        doNothing().when(mNativeInterface).init(anyInt(), anyBoolean());
        doNothing().when(mNativeInterface).cleanup();
        doReturn(true).when(mNativeInterface).connectHfp(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHfp(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).connectAudio(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectAudio(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).setActiveDevice(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).sendBsir(any(BluetoothDevice.class), anyBoolean());
        // Use real state machines here
        doCallRealMethod().when(mObjectsFactory)
                .makeStateMachine(any(), any(), any(), any(), any(), any());
        // Mock methods in HeadsetObjectsFactory
        doReturn(mSystemInterface).when(mObjectsFactory).makeSystemInterface(any());
        doReturn(mNativeInterface).when(mObjectsFactory).getNativeInterface();
        Intents.init();
        TestUtils.startService(mServiceRule, HeadsetService.class);
        mHeadsetService = HeadsetService.getHeadsetService();
        Assert.assertNotNull(mHeadsetService);
        verify(mObjectsFactory).makeSystemInterface(mHeadsetService);
        verify(mObjectsFactory).getNativeInterface();
        mHeadsetServiceBinder = (IBluetoothHeadset.Stub) mHeadsetService.initBinder();
        Assert.assertNotNull(mHeadsetServiceBinder);

        // Set up the Connection State Changed receiver
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED);
        mHeadsetIntentReceiver = new HeadsetIntentReceiver();
        mTargetContext.registerReceiver(mHeadsetIntentReceiver, filter);
    }

    @After
    public void tearDown() throws Exception {
        if (!mTargetContext.getResources().getBoolean(R.bool.profile_supported_hs_hfp)) {
            return;
        }
        mTargetContext.unregisterReceiver(mHeadsetIntentReceiver);
        TestUtils.stopService(mServiceRule, HeadsetService.class);
        Intents.release();
        mHeadsetService = HeadsetService.getHeadsetService();
        Assert.assertNull(mHeadsetService);
        Method method = HeadsetObjectsFactory.class.getDeclaredMethod("setInstanceForTesting",
                HeadsetObjectsFactory.class);
        method.setAccessible(true);
        method.invoke(null, (HeadsetObjectsFactory) null);
        TestUtils.clearAdapterService(mAdapterService);
        mBondedDevices.clear();
        mConnectionStateChangedQueue.clear();
        mActiveDeviceChangedQueue.clear();
    }

    /**
     * Test to verify that HeadsetService can be successfully started
     */
    @Test
    public void testGetHeadsetService() {
        Assert.assertEquals(mHeadsetService, HeadsetService.getHeadsetService());
        // Verify default connection and audio states
        mCurrentDevice = TestUtils.getTestDevice(mAdapter, 0);
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(BluetoothHeadset.STATE_AUDIO_DISCONNECTED,
                mHeadsetService.getAudioState(mCurrentDevice));
    }

    /**
     * Test to verify that {@link HeadsetService#connect(BluetoothDevice)} actually result in a
     * call to native interface to create HFP
     */
    @Test
    public void testConnectFromApi() {
        mCurrentDevice = TestUtils.getTestDevice(mAdapter, 0);
        mBondedDevices.add(mCurrentDevice);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(mObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, mAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_CONNECTING, BluetoothProfile.STATE_DISCONNECTED);
        verify(mNativeInterface).connectHfp(mCurrentDevice);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(Collections.singletonList(mCurrentDevice),
                mHeadsetService.getDevicesMatchingConnectionStates(
                        new int[]{BluetoothProfile.STATE_CONNECTING}));
        // Get feedback from native to put device into connected state
        HeadsetStackEvent connectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_CONNECTED, BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(Collections.singletonList(mCurrentDevice),
                mHeadsetService.getDevicesMatchingConnectionStates(
                        new int[]{BluetoothProfile.STATE_CONNECTED}));
    }

    /**
     * Test to verify that {@link BluetoothDevice#ACTION_BOND_STATE_CHANGED} intent with
     * {@link BluetoothDevice#EXTRA_BOND_STATE} as {@link BluetoothDevice#BOND_NONE} will cause a
     * disconnected device to be removed from state machine map
     */
    @Test
    public void testUnbondDevice_disconnectBeforeUnbond() {
        mCurrentDevice = TestUtils.getTestDevice(mAdapter, 0);
        mBondedDevices.add(mCurrentDevice);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(mObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, mAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_CONNECTING, BluetoothProfile.STATE_DISCONNECTED);
        verify(mNativeInterface).connectHfp(mCurrentDevice);
        // Get feedback from native layer to go back to disconnected state
        HeadsetStackEvent connectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_DISCONNECTED, BluetoothProfile.STATE_CONNECTING);
        // Send unbond intent
        doReturn(BluetoothDevice.BOND_NONE).when(mAdapterService).getBondState(eq(mCurrentDevice));
        Intent unbondIntent = new Intent(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, mCurrentDevice);
        InstrumentationRegistry.getTargetContext().sendBroadcast(unbondIntent);
        // Check that the state machine is actually destroyed
        verify(mObjectsFactory, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).destroyStateMachine(
                mStateMachineArgument.capture());
        Assert.assertEquals(mCurrentDevice, mStateMachineArgument.getValue().getDevice());
    }

    /**
     * Test to verify that if a device can be property disconnected after
     * {@link BluetoothDevice#ACTION_BOND_STATE_CHANGED} intent with
     * {@link BluetoothDevice#EXTRA_BOND_STATE} as {@link BluetoothDevice#BOND_NONE} is received.
     */
    @Test
    public void testUnbondDevice_disconnectAfterUnbond() {
        mCurrentDevice = TestUtils.getTestDevice(mAdapter, 0);
        mBondedDevices.add(mCurrentDevice);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(mObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, mAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        verify(mNativeInterface, after(ASYNC_CALL_TIMEOUT_MILLIS)).connectHfp(mCurrentDevice);
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_CONNECTING, BluetoothProfile.STATE_DISCONNECTED);
        // Get feedback from native layer to go to connected state
        HeadsetStackEvent connectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_CONNECTED, BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(Collections.singletonList(mCurrentDevice),
                mHeadsetService.getConnectedDevices());
        // Send unbond intent
        doReturn(BluetoothDevice.BOND_NONE).when(mAdapterService).getBondState(eq(mCurrentDevice));
        Intent unbondIntent = new Intent(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, mCurrentDevice);
        InstrumentationRegistry.getTargetContext().sendBroadcast(unbondIntent);
        // Check that the state machine is not destroyed
        verify(mObjectsFactory, after(ASYNC_CALL_TIMEOUT_MILLIS).never()).destroyStateMachine(
                any());
        // Now disconnect the device
        HeadsetStackEvent connectingEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectingEvent);
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, mCurrentDevice,
                BluetoothProfile.STATE_DISCONNECTED, BluetoothProfile.STATE_CONNECTED);
        // Check that the state machine is destroyed after another async call
        verify(mObjectsFactory, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).destroyStateMachine(
                mStateMachineArgument.capture());
        Assert.assertEquals(mCurrentDevice, mStateMachineArgument.getValue().getDevice());

    }

    /**
     * Test the functionality of
     * {@link BluetoothHeadset#startScoUsingVirtualVoiceCall()} and
     * {@link BluetoothHeadset#stopScoUsingVirtualVoiceCall()}
     *
     * Normal start and stop
     */
    @Test
    public void testVirtualCall_normalStartStop() throws RemoteException {
        for (int i = 0; i < MAX_HEADSET_CONNECTIONS; ++i) {
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, i);
            mBondedDevices.add(mCurrentDevice);
            connectTestDevice(mCurrentDevice);
            Assert.assertThat(mHeadsetServiceBinder.getConnectedDevices(),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
            Assert.assertThat(mHeadsetServiceBinder.getDevicesMatchingConnectionStates(
                    new int[]{BluetoothProfile.STATE_CONNECTED}),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        }
        List<BluetoothDevice> connectedDevices = mHeadsetServiceBinder.getConnectedDevices();
        Assert.assertThat(connectedDevices, Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        BluetoothDevice activeDevice = connectedDevices.get(MAX_HEADSET_CONNECTIONS / 2);
        Assert.assertTrue(mHeadsetServiceBinder.setActiveDevice(activeDevice));
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, activeDevice);
        Assert.assertEquals(activeDevice, mHeadsetServiceBinder.getActiveDevice());
        // Start virtual call
        Assert.assertTrue(mHeadsetServiceBinder.startScoUsingVirtualVoiceCall());
        Assert.assertTrue(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStartSequenceInvocations(connectedDevices);
        // End virtual call
        Assert.assertTrue(mHeadsetServiceBinder.stopScoUsingVirtualVoiceCall());
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStopSequenceInvocations(connectedDevices);
    }

    /**
     * Test the functionality of
     * {@link BluetoothHeadset#startScoUsingVirtualVoiceCall()} and
     * {@link BluetoothHeadset#stopScoUsingVirtualVoiceCall()}
     *
     * Virtual call should be preempted by telecom call
     */
    @Test
    public void testVirtualCall_preemptedByTelecomCall() throws RemoteException {
        for (int i = 0; i < MAX_HEADSET_CONNECTIONS; ++i) {
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, i);
            mBondedDevices.add(mCurrentDevice);
            connectTestDevice(mCurrentDevice);
            Assert.assertThat(mHeadsetServiceBinder.getConnectedDevices(),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
            Assert.assertThat(mHeadsetServiceBinder.getDevicesMatchingConnectionStates(
                    new int[]{BluetoothProfile.STATE_CONNECTED}),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        }
        List<BluetoothDevice> connectedDevices = mHeadsetServiceBinder.getConnectedDevices();
        Assert.assertThat(connectedDevices, Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        BluetoothDevice activeDevice = connectedDevices.get(MAX_HEADSET_CONNECTIONS / 2);
        Assert.assertTrue(mHeadsetServiceBinder.setActiveDevice(activeDevice));
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, activeDevice);
        Assert.assertEquals(activeDevice, mHeadsetServiceBinder.getActiveDevice());
        // Start virtual call
        Assert.assertTrue(mHeadsetServiceBinder.startScoUsingVirtualVoiceCall());
        Assert.assertTrue(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStartSequenceInvocations(connectedDevices);
        // Virtual call should be preempted by telecom call
        mHeadsetServiceBinder.phoneStateChanged(0, 0, HeadsetHalConstants.CALL_STATE_INCOMING,
                TEST_PHONE_NUMBER, 128);
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStopSequenceInvocations(connectedDevices);
        verifyCallStateToNativeInvocation(
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_INCOMING,
                        TEST_PHONE_NUMBER, 128), connectedDevices);
    }

    /**
     * Test the functionality of
     * {@link BluetoothHeadset#startScoUsingVirtualVoiceCall()} and
     * {@link BluetoothHeadset#stopScoUsingVirtualVoiceCall()}
     *
     * Virtual call should be rejected when there is a telecom call
     */
    @Test
    public void testVirtualCall_rejectedWhenThereIsTelecomCall() throws RemoteException {
        for (int i = 0; i < MAX_HEADSET_CONNECTIONS; ++i) {
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, i);
            mBondedDevices.add(mCurrentDevice);
            connectTestDevice(mCurrentDevice);
            Assert.assertThat(mHeadsetServiceBinder.getConnectedDevices(),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
            Assert.assertThat(mHeadsetServiceBinder.getDevicesMatchingConnectionStates(
                    new int[]{BluetoothProfile.STATE_CONNECTED}),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        }
        List<BluetoothDevice> connectedDevices = mHeadsetServiceBinder.getConnectedDevices();
        Assert.assertThat(connectedDevices, Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        BluetoothDevice activeDevice = connectedDevices.get(MAX_HEADSET_CONNECTIONS / 2);
        Assert.assertTrue(mHeadsetServiceBinder.setActiveDevice(activeDevice));
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, activeDevice);
        Assert.assertEquals(activeDevice, mHeadsetServiceBinder.getActiveDevice());
        // Reject virtual call setup if we are in call
        when(mSystemInterface.isInCall()).thenReturn(true);
        Assert.assertFalse(mHeadsetServiceBinder.startScoUsingVirtualVoiceCall());
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        // Reject virtual call setup if we are ringing
        when(mSystemInterface.isInCall()).thenReturn(false);
        when(mSystemInterface.isRinging()).thenReturn(true);
        Assert.assertFalse(mHeadsetServiceBinder.startScoUsingVirtualVoiceCall());
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
    }

    /**
     * Test the behavior when dialing outgoing call from the headset
     */
    @Test
    public void testDialingOutCall_NormalDialingOut() throws RemoteException {
        for (int i = 0; i < MAX_HEADSET_CONNECTIONS; ++i) {
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, i);
            mBondedDevices.add(mCurrentDevice);
            connectTestDevice(mCurrentDevice);
            Assert.assertThat(mHeadsetServiceBinder.getConnectedDevices(),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
            Assert.assertThat(mHeadsetServiceBinder.getDevicesMatchingConnectionStates(
                    new int[]{BluetoothProfile.STATE_CONNECTED}),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        }
        List<BluetoothDevice> connectedDevices = mHeadsetServiceBinder.getConnectedDevices();
        Assert.assertThat(connectedDevices, Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        BluetoothDevice activeDevice = connectedDevices.get(0);
        Assert.assertTrue(mHeadsetServiceBinder.setActiveDevice(activeDevice));
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, activeDevice);
        Assert.assertEquals(activeDevice, mHeadsetServiceBinder.getActiveDevice());
        // Try dialing out from the a non active Headset
        BluetoothDevice dialingOutDevice = connectedDevices.get(1);
        HeadsetStackEvent dialingOutEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_DIAL_CALL, TEST_PHONE_NUMBER,
                        dialingOutDevice);
        Uri dialOutUri = Uri.fromParts(PhoneAccount.SCHEME_TEL, TEST_PHONE_NUMBER, null);
        Instrumentation.ActivityResult result =
                new Instrumentation.ActivityResult(Activity.RESULT_OK, null);
        Intents.intending(IntentMatchers.hasAction(Intent.ACTION_CALL_PRIVILEGED))
                .respondWith(result);
        mHeadsetService.messageFromNative(dialingOutEvent);
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, dialingOutDevice);
        TestUtils.waitForLooperToFinishScheduledTask(
                mHeadsetService.getStateMachinesThreadLooper());
        Assert.assertTrue(mHeadsetService.hasDeviceInitiatedDialingOut());
        // Make sure the correct intent is fired
        Intents.intended(allOf(IntentMatchers.hasAction(Intent.ACTION_CALL_PRIVILEGED),
                IntentMatchers.hasData(dialOutUri)), Intents.times(1));
        // Further dial out attempt from same device will fail
        mHeadsetService.messageFromNative(dialingOutEvent);
        TestUtils.waitForLooperToFinishScheduledTask(
                mHeadsetService.getStateMachinesThreadLooper());
        verify(mNativeInterface).atResponseCode(dialingOutDevice,
                HeadsetHalConstants.AT_RESPONSE_ERROR, 0);
        // Further dial out attempt from other device will fail
        HeadsetStackEvent dialingOutEventOtherDevice =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_DIAL_CALL, TEST_PHONE_NUMBER,
                        activeDevice);
        mHeadsetService.messageFromNative(dialingOutEventOtherDevice);
        TestUtils.waitForLooperToFinishScheduledTask(
                mHeadsetService.getStateMachinesThreadLooper());
        verify(mNativeInterface).atResponseCode(activeDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                0);
        TestUtils.waitForNoIntent(ASYNC_CALL_TIMEOUT_MILLIS, mActiveDeviceChangedQueue);
        Assert.assertEquals(dialingOutDevice, mHeadsetServiceBinder.getActiveDevice());
        // Make sure only one intent is fired
        Intents.intended(allOf(IntentMatchers.hasAction(Intent.ACTION_CALL_PRIVILEGED),
                IntentMatchers.hasData(dialOutUri)), Intents.times(1));
        // Verify that phone state update confirms the dial out event
        mHeadsetServiceBinder.phoneStateChanged(0, 0, HeadsetHalConstants.CALL_STATE_DIALING,
                TEST_PHONE_NUMBER, 128);
        HeadsetCallState dialingCallState =
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_DIALING,
                        TEST_PHONE_NUMBER, 128);
        verifyCallStateToNativeInvocation(dialingCallState, connectedDevices);
        verify(mNativeInterface).atResponseCode(dialingOutDevice,
                HeadsetHalConstants.AT_RESPONSE_OK, 0);
        // Verify that IDLE phone state clears the dialing out flag
        mHeadsetServiceBinder.phoneStateChanged(1, 0, HeadsetHalConstants.CALL_STATE_IDLE,
                TEST_PHONE_NUMBER, 128);
        HeadsetCallState activeCallState =
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_DIALING,
                        TEST_PHONE_NUMBER, 128);
        verifyCallStateToNativeInvocation(activeCallState, connectedDevices);
        Assert.assertFalse(mHeadsetService.hasDeviceInitiatedDialingOut());
    }

    /**
     * Test the behavior when dialing outgoing call from the headset
     */
    @Test
    public void testDialingOutCall_DialingOutPreemptVirtualCall() throws RemoteException {
        for (int i = 0; i < MAX_HEADSET_CONNECTIONS; ++i) {
            mCurrentDevice = TestUtils.getTestDevice(mAdapter, i);
            mBondedDevices.add(mCurrentDevice);
            connectTestDevice(mCurrentDevice);
            Assert.assertThat(mHeadsetServiceBinder.getConnectedDevices(),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
            Assert.assertThat(mHeadsetServiceBinder.getDevicesMatchingConnectionStates(
                    new int[]{BluetoothProfile.STATE_CONNECTED}),
                    Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        }
        List<BluetoothDevice> connectedDevices = mHeadsetServiceBinder.getConnectedDevices();
        Assert.assertThat(connectedDevices, Matchers.containsInAnyOrder(mBondedDevices.toArray()));
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        BluetoothDevice activeDevice = connectedDevices.get(0);
        Assert.assertTrue(mHeadsetServiceBinder.setActiveDevice(activeDevice));
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, activeDevice);
        Assert.assertEquals(activeDevice, mHeadsetServiceBinder.getActiveDevice());
        // Start virtual call
        Assert.assertTrue(mHeadsetServiceBinder.startScoUsingVirtualVoiceCall());
        Assert.assertTrue(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStartSequenceInvocations(connectedDevices);
        // Try dialing out from the a non active Headset
        BluetoothDevice dialingOutDevice = connectedDevices.get(1);
        HeadsetStackEvent dialingOutEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_DIAL_CALL, TEST_PHONE_NUMBER,
                        dialingOutDevice);
        Uri dialOutUri = Uri.fromParts(PhoneAccount.SCHEME_TEL, TEST_PHONE_NUMBER, null);
        Instrumentation.ActivityResult result =
                new Instrumentation.ActivityResult(Activity.RESULT_OK, null);
        Intents.intending(IntentMatchers.hasAction(Intent.ACTION_CALL_PRIVILEGED))
                .respondWith(result);
        mHeadsetService.messageFromNative(dialingOutEvent);
        waitAndVerifyActiveDeviceChangedIntent(ASYNC_CALL_TIMEOUT_MILLIS, dialingOutDevice);
        TestUtils.waitForLooperToFinishScheduledTask(
                mHeadsetService.getStateMachinesThreadLooper());
        Assert.assertTrue(mHeadsetService.hasDeviceInitiatedDialingOut());
        // Make sure the correct intent is fired
        Intents.intended(allOf(IntentMatchers.hasAction(Intent.ACTION_CALL_PRIVILEGED),
                IntentMatchers.hasData(dialOutUri)), Intents.times(1));
        // Virtual call should be preempted by dialing out call
        Assert.assertFalse(mHeadsetService.isVirtualCallStarted());
        verifyVirtualCallStopSequenceInvocations(connectedDevices);
    }


    private void connectTestDevice(BluetoothDevice device) {
        // Use connecting event to indicate that device is connecting
        HeadsetStackEvent rfcommConnectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_CONNECTED, device);
        mHeadsetService.messageFromNative(rfcommConnectedEvent);
        verify(mObjectsFactory).makeStateMachine(device,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, mAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, device,
                BluetoothProfile.STATE_CONNECTING, BluetoothProfile.STATE_DISCONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                mHeadsetService.getConnectionState(device));
        Assert.assertEquals(Collections.singletonList(device),
                mHeadsetService.getDevicesMatchingConnectionStates(
                        new int[]{BluetoothProfile.STATE_CONNECTING}));
        // Get feedback from native to put device into connected state
        HeadsetStackEvent slcConnectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, device);
        mHeadsetService.messageFromNative(slcConnectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        waitAndVerifyConnectionStateIntent(ASYNC_CALL_TIMEOUT_MILLIS, device,
                BluetoothProfile.STATE_CONNECTED, BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
    }

    private void waitAndVerifyConnectionStateIntent(int timeoutMs, BluetoothDevice device,
            int newState, int prevState) {
        Intent intent = TestUtils.waitForIntent(timeoutMs, mConnectionStateChangedQueue);
        Assert.assertNotNull(intent);
        HeadsetTestUtils.verifyConnectionStateBroadcast(device, newState, prevState, intent, false);
    }

    private void waitAndVerifyActiveDeviceChangedIntent(int timeoutMs, BluetoothDevice device) {
        Intent intent = TestUtils.waitForIntent(timeoutMs, mActiveDeviceChangedQueue);
        Assert.assertNotNull(intent);
        HeadsetTestUtils.verifyActiveDeviceChangedBroadcast(device, intent, false);
    }

    /**
     * Verify the series of invocations after
     * {@link BluetoothHeadset#startScoUsingVirtualVoiceCall()}
     *
     * @param connectedDevices must be in the same sequence as
     * {@link BluetoothHeadset#getConnectedDevices()}
     */
    private void verifyVirtualCallStartSequenceInvocations(List<BluetoothDevice> connectedDevices) {
        // Do not verify HeadsetPhoneState changes as it is verified in HeadsetServiceTest
        verifyCallStateToNativeInvocation(
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_DIALING, "", 0),
                connectedDevices);
        verifyCallStateToNativeInvocation(
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_ALERTING, "", 0),
                connectedDevices);
        verifyCallStateToNativeInvocation(
                new HeadsetCallState(1, 0, HeadsetHalConstants.CALL_STATE_IDLE, "", 0),
                connectedDevices);
    }

    private void verifyVirtualCallStopSequenceInvocations(List<BluetoothDevice> connectedDevices) {
        verifyCallStateToNativeInvocation(
                new HeadsetCallState(0, 0, HeadsetHalConstants.CALL_STATE_IDLE, "", 0),
                connectedDevices);
    }

    private void verifyCallStateToNativeInvocation(HeadsetCallState headsetCallState,
            List<BluetoothDevice> connectedDevices) {
        for (BluetoothDevice device : connectedDevices) {
            verify(mNativeInterface, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).phoneStateChange(device,
                    headsetCallState);
        }
    }
}
