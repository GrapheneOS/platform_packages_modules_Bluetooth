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

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

import android.os.Binder;

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

import java.util.UUID;

/**
 * Test cases for {@link ContextMap}.
 */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class ContextMapTest {

    private GattService mService;

    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Mock
    private AdapterService mAdapterService;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        TestUtils.setAdapterService(mAdapterService);
        doReturn(true).when(mAdapterService).isStartedProfile(anyString());

        TestUtils.startService(mServiceRule, GattService.class);
        mService = GattService.getGattService();
    }

    @After
    public void tearDown() throws Exception {
        if (!GattService.isEnabled()) {
            return;
        }

        doReturn(false).when(mAdapterService).isStartedProfile(anyString());
        TestUtils.stopService(mServiceRule, GattService.class);
        mService = GattService.getGattService();

        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void getByMethods() {
        ContextMap contextMap = new ContextMap<>();

        int id = 12345;
        contextMap.add(id, null, mService);

        contextMap.add(UUID.randomUUID(), null, null, null, mService);

        int appUid = Binder.getCallingUid();
        String appName = mService.getPackageManager().getNameForUid(appUid);

        ContextMap.App contextMapById = contextMap.getById(appUid);
        assertThat(contextMapById.name).isEqualTo(appName);

        ContextMap.App contextMapByName = contextMap.getByName(appName);
        assertThat(contextMapByName.name).isEqualTo(appName);
    }

    @Test
    public void testDump_doesNotCrash() throws Exception {
        StringBuilder sb = new StringBuilder();

        ContextMap contextMap = new ContextMap<>();

        int id = 12345;
        contextMap.add(id, null, mService);

        contextMap.add(UUID.randomUUID(), null, null, null, mService);

        contextMap.dump(sb);

        contextMap.dumpAdvertiser(sb);
    }
}
