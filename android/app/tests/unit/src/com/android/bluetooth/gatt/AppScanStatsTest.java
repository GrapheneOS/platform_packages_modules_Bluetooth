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

package com.android.bluetooth.gatt;

import static com.google.common.truth.Truth.assertThat;


import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.location.LocationManager;
import android.os.WorkSource;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.ArrayList;
import java.util.List;

/**
 * Test cases for {@link AppScanStats}.
 */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class AppScanStatsTest {

    private GattService mService;

    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Mock
    private ContextMap map;

    @Mock
    private AdapterService mAdapterService;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        TestUtils.setAdapterService(mAdapterService);

        TestUtils.mockGetSystemService(
                mAdapterService, Context.LOCATION_SERVICE, LocationManager.class);

        mService = new GattService(InstrumentationRegistry.getTargetContext());
        mService.start();
    }

    @After
    public void tearDown() throws Exception {
        mService.stop();
        mService = null;

        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void constructor() {
        String name = "appName";
        WorkSource source = null;

        AppScanStats appScanStats = new AppScanStats(name, source, map, mService);

        assertThat(appScanStats.mContextMap).isEqualTo(map);
        assertThat(appScanStats.mGattService).isEqualTo(mService);

        assertThat(appScanStats.isScanning()).isEqualTo(false);
    }

    @Test
    public void testDump_doesNotCrash() throws Exception {
        String name = "appName";
        WorkSource source = null;

        AppScanStats appScanStats = new AppScanStats(name, source, map, mService);

        ScanSettings settings = new ScanSettings.Builder().build();
        List<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder().setDeviceName("TestName").build());
        boolean isFilterScan = false;
        boolean isCallbackScan = false;
        int scannerId = 0;

        appScanStats.recordScanStart(settings, filters, isFilterScan, isCallbackScan, scannerId);
        appScanStats.isRegistered = true;

        StringBuilder stringBuilder = new StringBuilder();

        appScanStats.dumpToString(stringBuilder);
    }
}
