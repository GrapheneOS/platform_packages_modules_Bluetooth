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
package com.android.bluetooth.opp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;

import android.bluetooth.BluetoothAdapter;

import androidx.test.filters.MediumTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothOppServiceTest {
    private BluetoothOppService mService = null;
    private BluetoothAdapter mAdapter = null;

    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Mock BluetoothMethodProxy mBluetoothMethodProxy;

    @Mock
    private AdapterService mAdapterService;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        BluetoothMethodProxy.setInstanceForTesting(mBluetoothMethodProxy);

        // BluetoothOppService can create a UpdateThread, which will call
        // BluetoothOppNotification#updateNotification(), which in turn create a new
        // NotificationUpdateThread. Both threads may cause the tests to fail because they try to
        // access to ContentProvider in multiple places (ContentProvider might be disabled & there
        // is no mocking). Since we have no intention to test those threads, avoid running them
        doNothing().when(mBluetoothMethodProxy).threadStart(any());

        TestUtils.setAdapterService(mAdapterService);
        doReturn(true, false).when(mAdapterService).isStartedProfile(anyString());
        TestUtils.startService(mServiceRule, BluetoothOppService.class);
        mService = BluetoothOppService.getBluetoothOppService();
        Assert.assertNotNull(mService);
        // Try getting the Bluetooth adapter
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        Assert.assertNotNull(mAdapter);
    }

    @After
    public void tearDown() throws Exception {
        // Since the update thread is not run (we mocked it), it will not clean itself on interrupt
        // (normally, the service will wait for the update thread to clean itself after
        // being interrupted). We clean it manually here
        mService.mUpdateThread = null;
        BluetoothMethodProxy.setInstanceForTesting(null);
        TestUtils.stopService(mServiceRule, BluetoothOppService.class);
        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void testInitialize() {
        Assert.assertNotNull(BluetoothOppService.getBluetoothOppService());
    }
}

