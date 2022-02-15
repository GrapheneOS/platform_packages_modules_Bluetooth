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

import static org.mockito.Mockito.*;

import android.bluetooth.*;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.os.Looper;

import android.os.ParcelUuid;
import androidx.test.InstrumentationRegistry;
import androidx.test.filters.MediumTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.storage.DatabaseManager;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class LeAudioBroadcastServiceTest {
    private static final int TIMEOUT_MS = 1000;
    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();
    private BluetoothAdapter mAdapter;
    private BluetoothDevice mDevice;
    private Context mTargetContext;
    private LeAudioService mService;
    private LeAudioIntentReceiver mLeAudioIntentReceiver;
    private LinkedBlockingQueue<Intent> mIntentQueue;
    @Mock
    private AdapterService mAdapterService;
    @Mock
    private DatabaseManager mDatabaseManager;
    @Mock
    private AudioManager mAudioManager;
    @Mock
    private LeAudioBroadcasterNativeInterface mNativeInterface;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();

        // Set up mocks and test assets
        MockitoAnnotations.initMocks(this);

        if (Looper.myLooper() == null) {
            Looper.prepare();
        }

        TestUtils.setAdapterService(mAdapterService);
        doReturn(mDatabaseManager).when(mAdapterService).getDatabase();
        doReturn(true, false).when(mAdapterService).isStartedProfile(anyString());

        mAdapter = BluetoothAdapter.getDefaultAdapter();

        startService();
        mService.mAudioManager = mAudioManager;
        mService.mLeAudioBroadcasterNativeInterface = mNativeInterface;

        // Set up the State Changed receiver
        IntentFilter filter = new IntentFilter();

        mLeAudioIntentReceiver = new LeAudioIntentReceiver();
        mTargetContext.registerReceiver(mLeAudioIntentReceiver, filter);

        mDevice = TestUtils.getTestDevice(mAdapter, 0);
        when(mNativeInterface.getDevice(any(byte[].class))).thenReturn(mDevice);

        mIntentQueue = new LinkedBlockingQueue<Intent>();
    }

    @After
    public void tearDown() throws Exception {
        stopService();
        mTargetContext.unregisterReceiver(mLeAudioIntentReceiver);
        TestUtils.clearAdapterService(mAdapterService);
        reset(mAudioManager);
    }

    private void startService() throws TimeoutException {
        TestUtils.startService(mServiceRule, LeAudioService.class);
        mService = LeAudioService.getLeAudioService();
        Assert.assertNotNull(mService);
    }

    private void stopService() throws TimeoutException {
        TestUtils.stopService(mServiceRule, LeAudioService.class);
        mService = LeAudioService.getLeAudioService();
        Assert.assertNull(mService);
    }

    /**
     * Test getting LeAudio Service
     */
    @Test
    public void testGetLeAudioService() {
        Assert.assertEquals(mService, LeAudioService.getLeAudioService());
    }

    @Test
    public void testStopLeAudioService() {
        Assert.assertEquals(mService, LeAudioService.getLeAudioService());

        InstrumentationRegistry.getInstrumentation().runOnMainSync(new Runnable() {
            public void run() {
                Assert.assertTrue(mService.stop());
            }
        });
        InstrumentationRegistry.getInstrumentation().runOnMainSync(new Runnable() {
            public void run() {
                Assert.assertTrue(mService.start());
            }
        });
    }

    @Test
    public void testCreateBroadcastNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        verify(mNativeInterface, times(1)).createBroadcast(eq(meta),
                eq(broadcast_profile), eq(code));
    }

    @Test
    public void testStartBroadcastNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.startBroadcast(broadcast_id);
        verify(mNativeInterface, times(1)).startBroadcast(eq(broadcast_id));
    }

    @Test
    public void testStopBroadcastNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.stopBroadcast(broadcast_id);
        verify(mNativeInterface, times(1)).stopBroadcast(eq(broadcast_id));
    }

    @Test
    public void testPauseBroadcastNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.pauseBroadcast(broadcast_id);
        verify(mNativeInterface, times(1)).pauseBroadcast(eq(broadcast_id));
    }

    @Test
    public void testDestroyBroadcastNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.destroyBroadcast(broadcast_id);
        verify(mNativeInterface, times(1)).destroyBroadcast(eq(broadcast_id));
    }

    @Test
    public void testGetBroadcastAddressNative() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.getBroadcastId(broadcast_id);
        verify(mNativeInterface, times(1)).getBroadcastId(eq(broadcast_id));
    }

    @Test
    public void testGetAllBroadcastStates() {
        int broadcast_profile = 0;
        byte[] meta = new byte[]{0x02, 0x01, 0x02};
        byte[] code = {0x00, 0x01, 0x00};
        mService.createBroadcast(meta, broadcast_profile, code);

        int broadcast_id = 243;
        mService.getAllBroadcastStates();
        verify(mNativeInterface, times(1)).getAllBroadcastStates();
    }

    private class LeAudioIntentReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            try {
                mIntentQueue.put(intent);
            } catch (InterruptedException e) {
                Assert.fail("Cannot add Intent to the queue: " + e.getMessage());
            }
        }
    }

}
