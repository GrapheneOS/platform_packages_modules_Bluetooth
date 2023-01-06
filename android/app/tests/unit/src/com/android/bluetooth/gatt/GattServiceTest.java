/*
 * Copyright 2023 The Android Open Source Project
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

package com.android.bluetooth.gatt;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothGatt;
import android.content.AttributionSource;
import android.content.Context;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test cases for {@link GattService}.
 */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class GattServiceTest {

    private static final String REMOTE_DEVICE_ADDRESS = "00:00:00:00:00:00";

    private static final int TIMES_UP_AND_DOWN = 3;
    private Context mTargetContext;
    private GattService mService;
    @Mock private GattService.ClientMap mClientMap;
    @Mock private GattService.ScannerMap mScannerMap;

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    private BluetoothAdapter mAdapter;
    private AttributionSource mAttributionSource;

    @Mock private AdapterService mAdapterService;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when GattService is not enabled", GattService.isEnabled());
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);
        doReturn(true).when(mAdapterService).isStartedProfile(anyString());

        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mAttributionSource = mAdapter.getAttributionSource();

        TestUtils.startService(mServiceRule, GattService.class);
        mService = GattService.getGattService();
        Assert.assertNotNull(mService);

        mService.mClientMap = mClientMap;
        mService.mScannerMap = mScannerMap;
    }

    @After
    public void tearDown() throws Exception {
        if (!GattService.isEnabled()) {
            return;
        }
        doReturn(false).when(mAdapterService).isStartedProfile(anyString());
        TestUtils.stopService(mServiceRule, GattService.class);
        mService = GattService.getGattService();
        Assert.assertNull(mService);
        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void testInitialize() {
        Assert.assertEquals(mService, GattService.getGattService());
    }

    @Test
    public void testServiceUpAndDown() throws Exception {
        for (int i = 0; i < TIMES_UP_AND_DOWN; i++) {
            GattService gattService = GattService.getGattService();
            doReturn(false).when(mAdapterService).isStartedProfile(anyString());
            TestUtils.stopService(mServiceRule, GattService.class);
            mService = GattService.getGattService();
            Assert.assertNull(mService);
            gattService.cleanup();
            TestUtils.clearAdapterService(mAdapterService);
            reset(mAdapterService);
            TestUtils.setAdapterService(mAdapterService);
            doReturn(true).when(mAdapterService).isStartedProfile(anyString());
            TestUtils.startService(mServiceRule, GattService.class);
            mService = GattService.getGattService();
            Assert.assertNotNull(mService);
        }
    }

    @Test
    public void testParseBatchTimestamp() {
        long timestampNanos = mService.parseTimestampNanos(new byte[]{
                -54, 7
        });
        Assert.assertEquals(99700000000L, timestampNanos);
    }

    public void emptyClearServices() {
        int serverIf = 1;

        mService.clearServices(serverIf, mAttributionSource);
    }

    @Test
    public void clientReadPhy() {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        Integer connId = 1;
        doReturn(connId).when(mClientMap).connIdByAddress(clientIf, address);

        mService.clientReadPhy(clientIf, address, mAttributionSource);
    }

    @Test
    public void clientSetPreferredPhy() {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int txPhy = 2;
        int rxPhy = 1;
        int phyOptions = 3;

        Integer connId = 1;
        doReturn(connId).when(mClientMap).connIdByAddress(clientIf, address);

        mService.clientSetPreferredPhy(clientIf, address, txPhy, rxPhy, phyOptions,
                mAttributionSource);
    }

    @Test
    public void connectionParameterUpdate() {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        int connectionPriority = BluetoothGatt.CONNECTION_PRIORITY_HIGH;
        mService.connectionParameterUpdate(clientIf, address, connectionPriority,
                mAttributionSource);

        connectionPriority = BluetoothGatt.CONNECTION_PRIORITY_LOW_POWER;
        mService.connectionParameterUpdate(clientIf, address, connectionPriority,
                mAttributionSource);

        connectionPriority = BluetoothGatt.CONNECTION_PRIORITY_BALANCED;;
        mService.connectionParameterUpdate(clientIf, address, connectionPriority,
                mAttributionSource);
    }

    @Test
    public void testDumpDoesNotCrash() {
        mService.dump(new StringBuilder());
    }
}
