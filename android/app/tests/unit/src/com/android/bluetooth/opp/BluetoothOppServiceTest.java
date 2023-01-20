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

import static com.android.bluetooth.opp.BluetoothOppService.WHERE_INVISIBLE_UNCONFIRMED;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import android.app.NotificationManager;
import android.bluetooth.BluetoothAdapter;
import android.content.ContentResolver;
import android.database.MatrixCursor;
import android.os.Handler;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
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

@RunWith(AndroidJUnit4.class)
public class BluetoothOppServiceTest {
    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();
    @Mock
    BluetoothMethodProxy mMethodProxy;
    private BluetoothOppService mService = null;
    private BluetoothAdapter mAdapter = null;

    @Mock
    private AdapterService mAdapterService;

    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue("Ignore test when BluetoothOppService is not enabled",
                BluetoothOppService.isEnabled());
        MockitoAnnotations.initMocks(this);

        BluetoothMethodProxy.setInstanceForTesting(mMethodProxy);

        // To void mockito multi-thread inter-tests problem
        // If the thread still run in the next test, it will raise un-related mockito error
        BluetoothOppNotification bluetoothOppNotification = mock(BluetoothOppNotification.class);
        bluetoothOppNotification.mNotificationMgr = mock(NotificationManager.class);
        doReturn(bluetoothOppNotification).when(mMethodProxy).newBluetoothOppNotification(any());

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
        BluetoothMethodProxy.setInstanceForTesting(null);
        if (!BluetoothOppService.isEnabled()) {
            return;
        }
        TestUtils.stopService(mServiceRule, BluetoothOppService.class);
        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void testInitialize() {
        Assert.assertNotNull(BluetoothOppService.getBluetoothOppService());
    }

    @Test
    public void deleteShare_deleteShareAndCorrespondingBatch() {
        int infoTimestamp = 123456789;
        int infoTimestamp2 = 123489;

        BluetoothOppShareInfo shareInfo = mock(BluetoothOppShareInfo.class);
        shareInfo.mTimestamp = infoTimestamp;
        shareInfo.mDestination = "AA:BB:CC:DD:EE:FF";
        BluetoothOppShareInfo shareInfo2 = mock(BluetoothOppShareInfo.class);
        shareInfo2.mTimestamp = infoTimestamp2;
        shareInfo2.mDestination = "00:11:22:33:44:55";

        mService.mShares.clear();
        mService.mShares.add(shareInfo);
        mService.mShares.add(shareInfo2);

        // batch1 will be removed
        BluetoothOppBatch batch1 = new BluetoothOppBatch(mService, shareInfo);
        BluetoothOppBatch batch2 = new BluetoothOppBatch(mService, shareInfo2);
        batch2.mStatus = Constants.BATCH_STATUS_FINISHED;
        mService.mBatches.clear();
        mService.mBatches.add(batch1);
        mService.mBatches.add(batch2);

        mService.deleteShare(0);
        assertThat(mService.mShares.size()).isEqualTo(1);
        assertThat(mService.mBatches.size()).isEqualTo(1);
        assertThat(mService.mShares.get(0)).isEqualTo(shareInfo2);
        assertThat(mService.mBatches.get(0)).isEqualTo(batch2);
    }

    @Test
    public void dump_shouldNotThrow() {
        BluetoothOppShareInfo info = mock(BluetoothOppShareInfo.class);

        mService.mShares.add(info);

        // should not throw
        mService.dump(new StringBuilder());
    }

    @Test
    public void trimDatabase_trimsOldOrInvisibleRecords() {
        ContentResolver contentResolver = InstrumentationRegistry
                .getInstrumentation().getTargetContext().getContentResolver();
        Assume.assumeTrue("Ignore test when there is no content provider",
                contentResolver.acquireContentProviderClient(BluetoothShare.CONTENT_URI) != null);

        doReturn(1 /* any int is Ok */).when(mMethodProxy).contentResolverDelete(
                eq(contentResolver), eq(BluetoothShare.CONTENT_URI), anyString(), any());

        MatrixCursor cursor = new MatrixCursor(new String[]{BluetoothShare._ID}, 500);
        for (long i = 0; i < Constants.MAX_RECORDS_IN_DATABASE + 20; i++) {
            cursor.addRow(new Object[]{i});
        }

        doReturn(cursor).when(mMethodProxy).contentResolverQuery(eq(contentResolver),
                eq(BluetoothShare.CONTENT_URI), any(), any(), any(), any());

        BluetoothOppService.trimDatabase(contentResolver);

        // check trimmed invisible records
        verify(mMethodProxy).contentResolverDelete(eq(contentResolver),
                eq(BluetoothShare.CONTENT_URI), eq(WHERE_INVISIBLE_UNCONFIRMED), any());

        // check trimmed old records
        verify(mMethodProxy).contentResolverDelete(eq(contentResolver),
                eq(BluetoothShare.CONTENT_URI), eq(BluetoothShare._ID + " < " + 20), any());
    }
}