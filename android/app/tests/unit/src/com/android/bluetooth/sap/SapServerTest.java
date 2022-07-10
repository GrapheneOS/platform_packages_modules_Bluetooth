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

package com.android.bluetooth.sap;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.ContextWrapper;
import android.os.Handler;

import androidx.test.InstrumentationRegistry;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.io.InputStream;
import java.io.OutputStream;

@RunWith(JUnit4.class)
public class SapServerTest {
    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();

    private final static long TIMEOUT_MS = 5_000;

    private Context mContext;
    private BluetoothAdapter mAdapter;
    private BluetoothDevice mTestDevice;
    @Mock private AdapterService mAdapterService;
    @Mock private SapService mSapService;
    @Mock private Handler mHandler;
    @Mock private InputStream mRfcommInStream;
    @Mock private OutputStream mRfcommOutStream;
    @Mock private NotificationManager mNotificationManager;
    private SapServer mSapServer;

    @Before
    public void setUp() throws Exception {
        Context targetContext = InstrumentationRegistry.getTargetContext();
        TestUtils.setAdapterService(mAdapterService);

        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mContext = spy(new ContextWrapper(targetContext));

        doReturn(Context.NOTIFICATION_SERVICE).when(mContext)
                .getSystemServiceName(NotificationManager.class);
        doReturn(mNotificationManager).when(mContext)
                .getSystemService(Context.NOTIFICATION_SERVICE);

        mSapServer = new SapServer(mHandler, mContext, mRfcommInStream, mRfcommOutStream);
    }

    @After
    public void tearDown() throws Exception {
        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void testSetTestMode() {
        int previousValue = mSapServer.mTestMode;

        if (SapMessage.TEST) {
            mSapServer.setTestMode(SapMessage.TEST_MODE_ENABLE);
            assertThat(mSapServer.mTestMode).isEqualTo(SapMessage.TEST_MODE_ENABLE);
            mSapServer.setTestMode(SapMessage.TEST_MODE_DISABLE);
            assertThat(mSapServer.mTestMode).isEqualTo(SapMessage.TEST_MODE_DISABLE);

            // recover the previous value
            mSapServer.setTestMode(previousValue);
        } else {
            mSapServer.setTestMode(SapMessage.TEST_MODE_ENABLE);
            assertThat(mSapServer.mTestMode).isEqualTo(previousValue);
        }
    }

    @Test
    public void testClearNotification() {
        mSapServer.clearNotification();

        verify(mNotificationManager).cancel(SapServer.NOTIFICATION_ID);
    }

    @Test
    public void testSetNotification() {
        int type = SapMessage.DISC_GRACEFULL;
        int flag = 0;

        mSapServer.setNotification(type, flag);

        verify(mNotificationManager).createNotificationChannel(any(NotificationChannel.class));
        verify(mNotificationManager).notify(eq(SapServer.NOTIFICATION_ID), any(Notification.class));
    }

    @Test
    public void testEmptyInputStream() throws Exception {
        // Simulate as if EOS was reached.
        when(mRfcommInStream.read()).thenReturn(-1);
        mSapServer.start();

        // Wait for the server finished
        mSapServer.join(TIMEOUT_MS);

        // Check if streams are closed.
        verify(mRfcommInStream).close();
        verify(mRfcommOutStream).close();
    }
}
