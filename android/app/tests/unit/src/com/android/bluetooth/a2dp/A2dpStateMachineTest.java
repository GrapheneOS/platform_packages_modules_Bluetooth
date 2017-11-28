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

package com.android.bluetooth.a2dp;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.os.HandlerThread;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Method;

@Ignore("Flaky tests. Ignore until the following CL is merged: https://android-review.googlesource.com/c/platform/packages/apps/Bluetooth/+/540316")
@MediumTest
@RunWith(AndroidJUnit4.class)
public class A2dpStateMachineTest {
    private BluetoothAdapter mAdapter;
    private Context mTargetContext;
    private HandlerThread mHandlerThread;
    private A2dpStateMachine mA2dpStateMachine;
    private BluetoothDevice mTestDevice;
    private static final int TIMEOUT_MS = 1000;    // 1s

    @Mock private AdapterService mAdapterService;
    @Mock private A2dpService mA2dpService;
    @Mock private A2dpNativeInterface mA2dpNativeInterface;

    @Before
    public void setUp() throws Exception {
        // Set up mocks and test assets
        MockitoAnnotations.initMocks(this);

        // We cannot mock AdapterService.getAdapterService() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the AdapterService.sAdapterService field.
        Method method = AdapterService.class.getDeclaredMethod("setAdapterService",
                                                               AdapterService.class);
        method.setAccessible(true);
        method.invoke(mAdapterService, mAdapterService);

        mTargetContext = InstrumentationRegistry.getTargetContext();
        mAdapter = BluetoothAdapter.getDefaultAdapter();

        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        // Set up thread and looper
        mHandlerThread = new HandlerThread("A2dpStateMachineTestHandlerThread");
        mHandlerThread.start();
        mA2dpStateMachine = new A2dpStateMachine(mA2dpService, mTargetContext,
                                                 mA2dpNativeInterface,
                                                 mHandlerThread.getLooper());
        // Override the timeout value to speed up the test
        mA2dpStateMachine.sConnectTimeoutMs = 1000;     // 1s
        mA2dpStateMachine.start();
    }

    @After
    public void tearDown() {
        mA2dpStateMachine.doQuit();
        mHandlerThread.quit();
    }

    /**
     * Test that default state is disconnected
     */
    @Test
    public void testDefaultDisconnectedState() {
        Assert.assertEquals(mA2dpStateMachine.getConnectionState(null),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    /**
     * Test that an incoming connection with low priority is rejected
     */
    @Test
    public void testIncomingPriorityReject() {
        // Update the device priority so okToConnect() returns false
        when(mA2dpService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_OFF);

        // Inject an event for when incoming connection is requested
        A2dpStackEvent connStCh =
                new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = A2dpStateMachine.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mA2dpStateMachine.sendMessage(A2dpStateMachine.STACK_EVENT, connStCh);

        // Verify that no connection state broadcast is executed
        verify(mA2dpService, after(TIMEOUT_MS).never()).sendBroadcast(any(Intent.class),
                                                                      anyString());
        // Check that we are in Disconnected state
        Assert.assertTrue(
                mA2dpStateMachine.getCurrentState() instanceof A2dpStateMachine.Disconnected);
    }

    /**
     * Test that an incoming connection with high priority is accepted
     */
    @Test
    public void testIncomingPriorityAccept() {
        // Update the device priority so okToConnect() returns true
        when(mA2dpService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);

        // Inject an event for when incoming connection is requested
        A2dpStackEvent connStCh =
                new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = A2dpStateMachine.CONNECTION_STATE_CONNECTING;
        connStCh.device = mTestDevice;
        mA2dpStateMachine.sendMessage(A2dpStateMachine.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mA2dpService, timeout(TIMEOUT_MS).times(1)).sendBroadcast(intentArgument1.capture(),
                                                                         anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check that we are in Pending state
        Assert.assertTrue(mA2dpStateMachine.getCurrentState() instanceof A2dpStateMachine.Pending);

        // Send a message to trigger connection completed
        A2dpStackEvent connCompletedEvent =
                new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connCompletedEvent.valueInt = A2dpStateMachine.CONNECTION_STATE_CONNECTED;
        connCompletedEvent.device = mTestDevice;
        mA2dpStateMachine.sendMessage(A2dpStateMachine.STACK_EVENT, connCompletedEvent);

        // Verify that the expected number of broadcasts are executed:
        // - two calls to broadcastConnectionState(): Disconnected -> Pending -> Connected
        // - one call to broadcastAudioState() when entering Connected state
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mA2dpService, timeout(TIMEOUT_MS).times(3)).sendBroadcast(intentArgument2.capture(),
                anyString());
        // Verify that the last broadcast was to change the A2DP playing state
        // to STATE_NOT_PLAYING
        Assert.assertEquals(BluetoothA2dp.ACTION_PLAYING_STATE_CHANGED,
                intentArgument2.getValue().getAction());
        Assert.assertEquals(BluetoothA2dp.STATE_NOT_PLAYING,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        // Check that we are in Connected state
        Assert.assertTrue(mA2dpStateMachine.getCurrentState()
                          instanceof A2dpStateMachine.Connected);
    }

    /**
     * Test that an outgoing connection times out
     */
    @Test
    public void testOutgoingTimeout() {
        // Update the device priority so okToConnect() returns true
        when(mA2dpService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);
        when(mA2dpNativeInterface.connectA2dp(any(BluetoothDevice.class))).thenReturn(true);
        when(mA2dpNativeInterface.disconnectA2dp(any(BluetoothDevice.class))).thenReturn(true);

        // Send a connect request
        mA2dpStateMachine.sendMessage(A2dpStateMachine.CONNECT, mTestDevice);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mA2dpService, timeout(TIMEOUT_MS).times(1)).sendBroadcast(intentArgument1.capture(),
                                                                         anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check that we are in Pending state
        Assert.assertTrue(mA2dpStateMachine.getCurrentState() instanceof A2dpStateMachine.Pending);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mA2dpService, timeout(A2dpStateMachine.sConnectTimeoutMs * 2).times(
                2)).sendBroadcast(intentArgument2.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check that we are in Disconnected state
        Assert.assertTrue(
                mA2dpStateMachine.getCurrentState() instanceof A2dpStateMachine.Disconnected);
    }
}
