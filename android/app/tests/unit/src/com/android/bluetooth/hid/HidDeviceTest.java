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

package com.android.bluetooth.hid;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHidDevice;
import android.bluetooth.BluetoothHidDeviceAppSdpSettings;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.os.Looper;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.Field;
import java.lang.reflect.Method;


@MediumTest
@RunWith(AndroidJUnit4.class)
public class HidDeviceTest {
    private static final int TIMEOUT_MS = 1000;    // 1s
    private static final byte[] SAMPLE_OUTGOING_HID_REPORT = new byte[] {0x01, 0x00, 0x02};

    private static AdapterService sAdapterService;
    private static HidDeviceNativeInterface sHidDeviceNativeInterface;

    private BluetoothAdapter mAdapter;
    private BluetoothDevice mTestDevice;
    private HidDeviceService mHidDeviceService;
    private Context mTargetContext;
    private BluetoothHidDeviceAppSdpSettings mSettings;

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @BeforeClass
    public static void setUpClassOnlyOnce() throws Exception {
        sAdapterService = mock(AdapterService.class);
        // We cannot mock AdapterService.getAdapterService() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the AdapterService.sAdapterService field.
        Method method = AdapterService.class.getDeclaredMethod("setAdapterService",
                AdapterService.class);
        method.setAccessible(true);
        method.invoke(sAdapterService, sAdapterService);

        sHidDeviceNativeInterface = mock(HidDeviceNativeInterface.class);

        method = HidDeviceNativeInterface.class.getDeclaredMethod("setInstance",
                HidDeviceNativeInterface.class);
        method.setAccessible(true);
        method.invoke(null, sHidDeviceNativeInterface);
    }

    @AfterClass
    public static void tearDownOnlyOnce() {
        sAdapterService = null;
    }

    @Before
    public void setUp() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Assert.assertNotNull(Looper.myLooper());

        mTargetContext = InstrumentationRegistry.getTargetContext();
        // Set up mocks and test assets
        MockitoAnnotations.initMocks(this);
        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("10:11:12:13:14:15");

        IBinder binder = mServiceRule.bindService(
                new Intent(mTargetContext, HidDeviceService.class));
        mHidDeviceService = ((HidDeviceService.BluetoothHidDeviceBinder) binder)
                .getServiceForTesting();
        Assert.assertNotNull(mHidDeviceService);

        InstrumentationRegistry.getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                mHidDeviceService.start();
            }
        });

        Field field = HidDeviceService.class.getDeclaredField("mHidDeviceNativeInterface");
        field.setAccessible(true);
        HidDeviceNativeInterface nativeInterface =
                (HidDeviceNativeInterface) field.get(mHidDeviceService);
        Assert.assertEquals(nativeInterface, sHidDeviceNativeInterface);

        // Dummy SDP settings
        mSettings = new BluetoothHidDeviceAppSdpSettings(
                "Unit test", "test", "Android",
                BluetoothHidDevice.SUBCLASS1_COMBO, new byte[] {});

    }

    @After
    public void tearDown() {
        mHidDeviceService.stop();
        mHidDeviceService.cleanup();
        mHidDeviceService = null;
        reset(sHidDeviceNativeInterface);
    }

    /**
     * Test getting HidDeviceService: getHidDeviceService().
     */
    @Test
    public void testGetHidDeviceService() {
        Assert.assertEquals(mHidDeviceService, HidDeviceService.getHidDeviceService());
    }

    /**
     * Test the logic in registerApp. Should get a callback onApplicationStateChangedFromNative.
     */
    @Test
    public void testRegisterApp() throws Exception {
        doReturn(true).when(sHidDeviceNativeInterface)
                .registerApp(anyString(), anyString(), anyString(), anyByte(), any(byte[].class),
                        isNull(), isNull());

        verify(sHidDeviceNativeInterface, never()).registerApp(anyString(), anyString(),
                anyString(), anyByte(), any(byte[].class), isNull(), isNull());

        // Register app
        Assert.assertTrue(mHidDeviceService.registerApp(mSettings, null, null, null));

        verify(sHidDeviceNativeInterface).registerApp(anyString(), anyString(), anyString(),
                anyByte(), any(byte[].class), isNull(), isNull());
    }

    /**
     * Test the logic in sendReport(). This should fail when the app is not registered.
     */
    @Test
    public void testSendReport() throws Exception {
        doReturn(true).when(sHidDeviceNativeInterface).sendReport(anyInt(), any(byte[].class));
        // sendReport() should fail without app registered
        Assert.assertEquals(false,
                mHidDeviceService.sendReport(mTestDevice, 0, SAMPLE_OUTGOING_HID_REPORT));

        // register app
        doReturn(true).when(sHidDeviceNativeInterface).registerApp(anyString(), anyString(),
                anyString(), anyByte(), any(byte[].class), isNull(), isNull());
        mHidDeviceService.registerApp(mSettings, null, null, null);

        // app registered
        mHidDeviceService.onApplicationStateChangedFromNative(mTestDevice, true);

        // wait for the app registration callback to complete
        Thread.sleep(TIMEOUT_MS);

        // sendReport() should work when app is registered
        Assert.assertEquals(true,
                mHidDeviceService.sendReport(mTestDevice, 0, SAMPLE_OUTGOING_HID_REPORT));

        verify(sHidDeviceNativeInterface).sendReport(anyInt(), eq(SAMPLE_OUTGOING_HID_REPORT));
    }
}
