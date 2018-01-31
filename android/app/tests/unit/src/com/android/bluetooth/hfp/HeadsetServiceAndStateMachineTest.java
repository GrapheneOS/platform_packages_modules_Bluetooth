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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.content.Intent;
import android.media.AudioManager;
import android.os.ParcelUuid;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.TimeoutException;

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

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    private static AdapterService sAdapterService;
    private static HeadsetObjectsFactory sObjectsFactory;

    private HeadsetService mHeadsetService;
    private BluetoothAdapter mAdapter;
    private HeadsetNativeInterface mNativeInterface;
    private BluetoothDevice mCurrentDevice;
    private ArrayList<BluetoothDevice> mBondedDevices = new ArrayList<>();
    private ArgumentCaptor<HeadsetStateMachine> mStateMachineArgument =
            ArgumentCaptor.forClass(HeadsetStateMachine.class);

    @Mock private HeadsetSystemInterface mSystemInterface;
    @Mock private AudioManager mAudioManager;
    @Mock private HeadsetPhoneState mPhoneState;

    @BeforeClass
    public static void setUpClassOnlyOnce() throws Exception {
        sAdapterService = mock(AdapterService.class);
        // We cannot mock AdapterService.getAdapterService() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the AdapterService.sAdapterService field.
        Method method =
                AdapterService.class.getDeclaredMethod("setAdapterService", AdapterService.class);
        method.setAccessible(true);
        method.invoke(null, sAdapterService);
        // We cannot mock HeadsetObjectsFactory.getInstance() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the HeadsetObjectsFactory.sInstance field.
        sObjectsFactory = spy(HeadsetObjectsFactory.getInstance());
        method = HeadsetObjectsFactory.class.getDeclaredMethod("setInstanceForTesting",
                HeadsetObjectsFactory.class);
        method.setAccessible(true);
        method.invoke(null, sObjectsFactory);
    }

    @AfterClass
    public static void tearDownClassOnlyOnce() throws Exception {
        Method method =
                AdapterService.class.getDeclaredMethod("clearAdapterService", AdapterService.class);
        method.setAccessible(true);
        method.invoke(null, sAdapterService);
        sAdapterService = null;
        method = HeadsetObjectsFactory.class.getDeclaredMethod("setInstanceForTesting",
                HeadsetObjectsFactory.class);
        method.setAccessible(true);
        method.invoke(null, (HeadsetObjectsFactory) null);
        sObjectsFactory = null;
    }

    @Before
    public void setUp() throws TimeoutException {
        MockitoAnnotations.initMocks(this);
        doReturn(true).when(sAdapterService).isEnabled();
        doReturn(MAX_HEADSET_CONNECTIONS).when(sAdapterService).getMaxConnectedAudioDevices();
        doReturn(new ParcelUuid[]{BluetoothUuid.Handsfree}).when(sAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Mock methods in AdapterService
        doReturn(FAKE_HEADSET_UUID).when(sAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        doReturn(BluetoothDevice.BOND_BONDED).when(sAdapterService)
                .getBondState(any(BluetoothDevice.class));
        doAnswer(invocation -> mBondedDevices.toArray(new BluetoothDevice[]{})).when(
                sAdapterService).getBondedDevices();
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
        doCallRealMethod().when(sObjectsFactory)
                .makeStateMachine(any(), any(), any(), any(), any(), any());
        // Mock methods in HeadsetObjectsFactory
        doReturn(mSystemInterface).when(sObjectsFactory).makeSystemInterface(any());
        doReturn(mNativeInterface).when(sObjectsFactory).getNativeInterface();
        Intent startIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), HeadsetService.class);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON);
        mServiceRule.startService(startIntent);
        verify(sAdapterService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).onProfileServiceStateChanged(
                eq(HeadsetService.class.getName()), eq(BluetoothAdapter.STATE_ON));
        mHeadsetService = HeadsetService.getHeadsetService();
        Assert.assertNotNull(mHeadsetService);
        verify(sObjectsFactory).makeSystemInterface(mHeadsetService);
        verify(sObjectsFactory).getNativeInterface();
    }

    @After
    public void tearDown() throws TimeoutException {
        Intent stopIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), HeadsetService.class);
        stopIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        stopIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF);
        mServiceRule.startService(stopIntent);
        verify(sAdapterService, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).onProfileServiceStateChanged(
                eq(HeadsetService.class.getName()), eq(BluetoothAdapter.STATE_OFF));
        mHeadsetService = HeadsetService.getHeadsetService();
        Assert.assertNull(mHeadsetService);
        reset(sObjectsFactory, sAdapterService);
        mCurrentDevice = null;
    }

    /**
     * Test to verify that HeadsetService can be successfully started
     */
    @Test
    public void testGetHeadsetService() {
        Assert.assertEquals(mHeadsetService, HeadsetService.getHeadsetService());
        // Verify default connection and audio states
        mCurrentDevice = getTestDevice(0);
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
        mCurrentDevice = getTestDevice(0);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(sObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, sAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        verify(mNativeInterface, after(ASYNC_CALL_TIMEOUT_MILLIS)).connectHfp(mCurrentDevice);
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
        try {
            Thread.sleep(ASYNC_CALL_TIMEOUT_MILLIS);
        } catch (InterruptedException exception) {
            Assert.fail("Interrupted while waiting for callback");
        }
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(Collections.singletonList(mCurrentDevice),
                mHeadsetService.getDevicesMatchingConnectionStates(
                        new int[]{BluetoothProfile.STATE_CONNECTED}));
        Assert.assertEquals(mCurrentDevice, mHeadsetService.getActiveDevice());
    }

    /**
     * Test to verify that {@link BluetoothDevice#ACTION_BOND_STATE_CHANGED} intent with
     * {@link BluetoothDevice#EXTRA_BOND_STATE} as {@link BluetoothDevice#BOND_NONE} will cause a
     * disconnected device to be removed from state machine map
     */
    @Test
    public void testUnbondDevice_disconnectBeforeUnbond() {
        mCurrentDevice = getTestDevice(0);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(sObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, sAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        verify(mNativeInterface, after(ASYNC_CALL_TIMEOUT_MILLIS)).connectHfp(mCurrentDevice);
        // Get feedback from native layer to go back to disconnected state
        HeadsetStackEvent connectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        try {
            Thread.sleep(ASYNC_CALL_TIMEOUT_MILLIS);
        } catch (InterruptedException exception) {
            Assert.fail("Interrupted while waiting for callback to disconnected state");
        }
        // Send unbond intent
        doReturn(BluetoothDevice.BOND_NONE).when(sAdapterService).getBondState(eq(mCurrentDevice));
        Intent unbondIntent = new Intent(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, mCurrentDevice);
        InstrumentationRegistry.getTargetContext().sendBroadcast(unbondIntent);
        // Check that the state machine is actually destroyed
        verify(sObjectsFactory, timeout(ASYNC_CALL_TIMEOUT_MILLIS)).destroyStateMachine(
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
        mCurrentDevice = getTestDevice(0);
        Assert.assertTrue(mHeadsetService.connect(mCurrentDevice));
        verify(sObjectsFactory).makeStateMachine(mCurrentDevice,
                mHeadsetService.getStateMachinesThreadLooper(), mHeadsetService, sAdapterService,
                mNativeInterface, mSystemInterface);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        verify(mNativeInterface, after(ASYNC_CALL_TIMEOUT_MILLIS)).connectHfp(mCurrentDevice);
        // Get feedback from native layer to go to connected state
        HeadsetStackEvent connectedEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_SLC_CONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectedEvent);
        // Wait ASYNC_CALL_TIMEOUT_MILLIS for state to settle, timing is also tested here and
        // 250ms for processing two messages should be way more than enough. Anything that breaks
        // this indicate some breakage in other part of Android OS
        try {
            Thread.sleep(ASYNC_CALL_TIMEOUT_MILLIS);
        } catch (InterruptedException exception) {
            Assert.fail("Interrupted while waiting for callback to disconnected state");
        }
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                mHeadsetService.getConnectionState(mCurrentDevice));
        Assert.assertEquals(Collections.singletonList(mCurrentDevice),
                mHeadsetService.getConnectedDevices());
        // Send unbond intent
        doReturn(BluetoothDevice.BOND_NONE).when(sAdapterService).getBondState(eq(mCurrentDevice));
        Intent unbondIntent = new Intent(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE);
        unbondIntent.putExtra(BluetoothDevice.EXTRA_DEVICE, mCurrentDevice);
        InstrumentationRegistry.getTargetContext().sendBroadcast(unbondIntent);
        // Check that the state machine is not destroyed
        verify(sObjectsFactory, after(ASYNC_CALL_TIMEOUT_MILLIS).never()).destroyStateMachine(
                any());
        // Now disconnect the device
        HeadsetStackEvent connectingEvent =
                new HeadsetStackEvent(HeadsetStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED,
                        HeadsetHalConstants.CONNECTION_STATE_DISCONNECTED, mCurrentDevice);
        mHeadsetService.messageFromNative(connectingEvent);
        // Check that the state machine is actually destroyed after two async calls
        verify(sObjectsFactory, timeout(ASYNC_CALL_TIMEOUT_MILLIS * 2)).destroyStateMachine(
                mStateMachineArgument.capture());
        Assert.assertEquals(mCurrentDevice, mStateMachineArgument.getValue().getDevice());
    }

    private BluetoothDevice getTestDevice(int i) {
        Assert.assertTrue(i <= 0xFF);
        BluetoothDevice device = mAdapter.getRemoteDevice(String.format("00:01:02:03:04:%02X", i));
        mBondedDevices.add(device);
        return device;
    }
}
