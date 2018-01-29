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

package com.android.bluetooth.a2dp;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Looper;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Method;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class A2dpServiceTest {
    private BluetoothAdapter mAdapter;
    private Context mTargetContext;
    private A2dpService mA2dpService;
    private BluetoothDevice mTestDevice;
    private static final int TIMEOUT_MS = 1000;    // 1s

    private BroadcastReceiver mConnectionStateChangedReceiver = null;
    private final BlockingQueue<Intent> mConnectionStateChangedQueue = new LinkedBlockingQueue<>();

    @Mock private AdapterService mAdapterService;
    @Mock private A2dpNativeInterface mA2dpNativeInterface;

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Before
    public void setUp() throws Exception {
        // Set up mocks and test assets
        MockitoAnnotations.initMocks(this);

        if (Looper.myLooper() == null) {
            Looper.prepare();
        }

        // We cannot mock AdapterService.getAdapterService() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the AdapterService.sAdapterService field.
        Method method = AdapterService.class.getDeclaredMethod("setAdapterService",
                                                               AdapterService.class);
        method.setAccessible(true);
        method.invoke(mAdapterService, mAdapterService);
        doReturn(1).when(mAdapterService).getMaxConnectedAudioDevices();

        mTargetContext = InstrumentationRegistry.getTargetContext();
        mAdapter = BluetoothAdapter.getDefaultAdapter();

        startService();
        mA2dpService.mA2dpNativeInterface = mA2dpNativeInterface;

        // Override the timeout value to speed up the test
        A2dpStateMachine.sConnectTimeoutMs = TIMEOUT_MS;    // 1s

        // Set up the Connection State Changed receiver
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        mConnectionStateChangedReceiver = new ConnectionStateChangedReceiver();
        mTargetContext.registerReceiver(mConnectionStateChangedReceiver, filter);

        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");
        mA2dpService.setPriority(mTestDevice, BluetoothProfile.PRIORITY_UNDEFINED);
    }

    @After
    public void tearDown() throws Exception {
        stopService();
        mTargetContext.unregisterReceiver(mConnectionStateChangedReceiver);
        mConnectionStateChangedQueue.clear();
    }

    private void startService() throws TimeoutException {
        Intent startIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), A2dpService.class);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                             AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON);
        mServiceRule.startService(startIntent);
        verify(mAdapterService, timeout(TIMEOUT_MS)).onProfileServiceStateChanged(
                eq(A2dpService.class.getName()), eq(BluetoothAdapter.STATE_ON));
        mA2dpService = A2dpService.getA2dpService();
        Assert.assertNotNull(mA2dpService);
    }

    private void stopService() throws TimeoutException {
        Intent stopIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), A2dpService.class);
        stopIntent.putExtra(AdapterService.EXTRA_ACTION,
                            AdapterService.ACTION_SERVICE_STATE_CHANGED);
        stopIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF);
        mServiceRule.startService(stopIntent);
        verify(mAdapterService, timeout(TIMEOUT_MS)).onProfileServiceStateChanged(
                eq(A2dpService.class.getName()), eq(BluetoothAdapter.STATE_OFF));
        mA2dpService = A2dpService.getA2dpService();
        Assert.assertNull(mA2dpService);
    }

    private class ConnectionStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            try {
                mConnectionStateChangedQueue.put(intent);
            } catch (InterruptedException e) {
                Assert.fail("Cannot add Intent to the queue");
            }
        }
    }

    private Intent waitForIntent(int timeoutMs, BlockingQueue<Intent> queue) {
        try {
            Intent intent = queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
            Assert.assertNotNull(intent);
            return intent;
        } catch (InterruptedException e) {
            Assert.fail("Cannot obtain an Intent from the queue");
        }
        return null;
    }

    private void verifyConnectionStateIntent(int timeoutMs, BluetoothDevice device,
                                             int newState, int prevState) {
        Intent intent = waitForIntent(timeoutMs, mConnectionStateChangedQueue);
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED,
                            intent.getAction());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(newState, intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        Assert.assertEquals(prevState, intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                                          -1));
    }

    /**
     * Test getting A2DP Service: getA2dpService();
     */
    @Test
    public void testGetA2dpService() {
        Assert.assertEquals(mA2dpService, A2dpService.getA2dpService());
    }

    /**
     * Test get/set priority for BluetoothDevice
     */
    @Test
    public void testGetSetPriority() {
        Assert.assertEquals("Initial device priority",
                            BluetoothProfile.PRIORITY_UNDEFINED,
                            mA2dpService.getPriority(mTestDevice));

        Assert.assertTrue(mA2dpService.setPriority(mTestDevice,  BluetoothProfile.PRIORITY_OFF));
        Assert.assertEquals("Setting device priority to PRIORITY_OFF",
                            BluetoothProfile.PRIORITY_OFF,
                            mA2dpService.getPriority(mTestDevice));

        Assert.assertTrue(mA2dpService.setPriority(mTestDevice,  BluetoothProfile.PRIORITY_ON));
        Assert.assertEquals("Setting device priority to PRIORITY_ON",
                            BluetoothProfile.PRIORITY_ON,
                            mA2dpService.getPriority(mTestDevice));

        Assert.assertTrue(mA2dpService.setPriority(mTestDevice,
                                                   BluetoothProfile.PRIORITY_AUTO_CONNECT));
        Assert.assertEquals("Setting device priority to PRIORITY_AUTO_CONNECT",
                            BluetoothProfile.PRIORITY_AUTO_CONNECT,
                            mA2dpService.getPriority(mTestDevice));
    }

    /**
     * Test that an outgoing connection times out
     */
    @Test
    public void testOutgoingConnectTimeout() {
        // Update the device priority so okToConnect() returns true
        mA2dpService.setPriority(mTestDevice, BluetoothProfile.PRIORITY_ON);
        doReturn(true).when(mA2dpNativeInterface).connectA2dp(any(BluetoothDevice.class));
        doReturn(true).when(mA2dpNativeInterface).disconnectA2dp(any(BluetoothDevice.class));

        // Send a connect request
        Assert.assertTrue("Connect failed", mA2dpService.connect(mTestDevice));

        // Verify the connection state broadcast, and that we are in Connecting state
        verifyConnectionStateIntent(TIMEOUT_MS, mTestDevice, BluetoothProfile.STATE_CONNECTING,
                                    BluetoothProfile.STATE_DISCONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                            mA2dpService.getConnectionState(mTestDevice));

        // Verify the connection state broadcast, and that we are in Disconnected state
        verifyConnectionStateIntent(A2dpStateMachine.sConnectTimeoutMs * 2,
                                    mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                                    BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                            mA2dpService.getConnectionState(mTestDevice));
    }

    /**
     * Test that an outgoing connection/disconnection succeeds
     */
    @Test
    public void testOutgoingConnectDisconnectSuccess() {
        A2dpStackEvent connCompletedEvent;

        // Update the device priority so okToConnect() returns true
        mA2dpService.setPriority(mTestDevice, BluetoothProfile.PRIORITY_ON);
        doReturn(true).when(mA2dpNativeInterface).connectA2dp(any(BluetoothDevice.class));
        doReturn(true).when(mA2dpNativeInterface).disconnectA2dp(any(BluetoothDevice.class));

        // Send a connect request
        Assert.assertTrue("Connect failed", mA2dpService.connect(mTestDevice));

        // Verify the connection state broadcast, and that we are in Connecting state
        verifyConnectionStateIntent(TIMEOUT_MS, mTestDevice, BluetoothProfile.STATE_CONNECTING,
                                    BluetoothProfile.STATE_DISCONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                            mA2dpService.getConnectionState(mTestDevice));

        // Send a message to trigger connection completed
        connCompletedEvent = new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connCompletedEvent.device = mTestDevice;
        connCompletedEvent.valueInt = A2dpStackEvent.CONNECTION_STATE_CONNECTED;
        mA2dpService.messageFromNative(connCompletedEvent);

        // Verify the connection state broadcast, and that we are in Connected state
        verifyConnectionStateIntent(TIMEOUT_MS, mTestDevice, BluetoothProfile.STATE_CONNECTED,
                                    BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                            mA2dpService.getConnectionState(mTestDevice));

        // Verify the list of connected devices
        Assert.assertTrue(mA2dpService.getConnectedDevices().contains(mTestDevice));

        // Send a disconnect request
        Assert.assertTrue("Disconnect failed", mA2dpService.disconnect(mTestDevice));

        // Verify the connection state broadcast, and that we are in Disconnecting state
        verifyConnectionStateIntent(TIMEOUT_MS, mTestDevice, BluetoothProfile.STATE_DISCONNECTING,
                                    BluetoothProfile.STATE_CONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTING,
                            mA2dpService.getConnectionState(mTestDevice));

        // Send a message to trigger disconnection completed
        connCompletedEvent = new A2dpStackEvent(A2dpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connCompletedEvent.device = mTestDevice;
        connCompletedEvent.valueInt = A2dpStackEvent.CONNECTION_STATE_DISCONNECTED;
        mA2dpService.messageFromNative(connCompletedEvent);

        // Verify the connection state broadcast, and that we are in Disconnected state
        verifyConnectionStateIntent(TIMEOUT_MS, mTestDevice, BluetoothProfile.STATE_DISCONNECTED,
                                    BluetoothProfile.STATE_DISCONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                            mA2dpService.getConnectionState(mTestDevice));

        // Verify the list of connected devices
        Assert.assertFalse(mA2dpService.getConnectedDevices().contains(mTestDevice));
    }
}
