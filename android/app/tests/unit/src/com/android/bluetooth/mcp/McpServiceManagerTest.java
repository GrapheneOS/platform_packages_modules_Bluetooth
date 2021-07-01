
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

package com.android.bluetooth.mcp;

import static org.mockito.Mockito.*;

import android.annotation.NonNull;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattService;
import android.content.Context;
import android.os.IBinder;
import android.os.IBinder.DeathRecipient;
import android.os.Looper;
import android.os.RemoteException;
import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;
import java.util.UUID;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class McpServiceManagerTest {
    private BluetoothAdapter mAdapter;
    private McpServiceManager mMcpServiceManager;

    private final McsComponentFactory mMcsComponentFactory = new McsComponentFactory();

    String app_token = "AppToken1";
    Integer ccid = 1;

    @Mock private AdapterService mAdapterService;
    @Mock private ServiceCallbacks mMockMcsCallbacks;
    @Mock private McpServiceGatt mMockMcpService;

    @Before
    public void setUp() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }

        MockitoAnnotations.initMocks(this);

        TestUtils.setAdapterService(mAdapterService);
        mAdapter = BluetoothAdapter.getDefaultAdapter();

        doNothing().when(mMockMcpService).destroy();

        McpServiceManager.setMcsComponentFactory(mMcsComponentFactory);

        mMcpServiceManager = new McpServiceManager();
        mMcpServiceManager.start();
    }

    @After
    public void tearDown() throws Exception {
        mMcpServiceManager.stop();
        mMcpServiceManager = null;

        TestUtils.clearAdapterService(mAdapterService);
    }

    private class McsComponentFactory implements McpServiceManager.IMcsComponentFactory {
        @Override
        public McpService CreateMcpService(Context context, boolean is_generic_mcs,
                @NonNull ServiceCallbacks callbacks, int ccid) {
            mMockMcpService.init(UUID.randomUUID());
            return mMockMcpService;
        }
    }

    @Test
    public void testGetService() {
        McpServiceManager mMcpServiceManagerDuplicate = McpServiceManager.getMcpServiceManager();
        Assert.assertNotNull(mMcpServiceManagerDuplicate);
        Assert.assertSame(mMcpServiceManagerDuplicate, mMcpServiceManager);
    }

    @Test
    public void testRegisterService() {
        mMcpServiceManager.registerServiceInstance(app_token, mMockMcsCallbacks);

        verify(mMockMcpService).init(any(UUID.class));
        mMcpServiceManager.cleanup();
    }

    @Test
    public void testUnregisterService() {
        mMcpServiceManager.registerServiceInstance(app_token, mMockMcsCallbacks);

        mMcpServiceManager.unregisterServiceInstance(app_token);
        verify(mMockMcpService).destroy();
    }

    @Test
    public void testAuthorization() {
        BluetoothDevice device0 = TestUtils.getTestDevice(mAdapter, 0);
        BluetoothDevice device1 = TestUtils.getTestDevice(mAdapter, 1);

        mMcpServiceManager.registerServiceInstance(app_token, mMockMcsCallbacks);

        mMcpServiceManager.setDeviceAuthorization(device0, BluetoothDevice.ACCESS_ALLOWED);
        verify(mMockMcpService).onDeviceAuthorizationSet(eq(device0));
        Assert.assertEquals(
                mMcpServiceManager.getDeviceAuthorization(device0), BluetoothDevice.ACCESS_ALLOWED);

        mMcpServiceManager.setDeviceAuthorization(device1, BluetoothDevice.ACCESS_REJECTED);
        verify(mMockMcpService).onDeviceAuthorizationSet(eq(device1));
        Assert.assertEquals(mMcpServiceManager.getDeviceAuthorization(device1),
                BluetoothDevice.ACCESS_REJECTED);
    }
}
