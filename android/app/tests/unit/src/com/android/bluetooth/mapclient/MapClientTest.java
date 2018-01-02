/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.bluetooth.mapclient;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;
import android.content.Intent;
import android.os.Parcel;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import com.android.bluetooth.R;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class MapClientTest {
    private static final String TAG = "MapClientTest";
    private MapClientService mService = null;
    private BluetoothAdapter mAdapter = null;
    private Context mTargetContext;

    @Mock private MnsService mMockMnsService;

    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        if (skipTest()) return;
        MapUtils.setMnsService(mMockMnsService);
        startServices();
        cleanUpInstanceMap();
    }

    @After
    public void tearDown() throws Exception {
        mService = null;
        mAdapter = null;
    }

    private boolean skipTest() {
        // On phone side, MapClient may not be included in the APK and thus the test
        // should be skipped
        return !mTargetContext.getResources().getBoolean(R.bool.profile_supported_mapmce);
    }

    private void cleanUpInstanceMap() {
        if (!mService.getInstanceMap().isEmpty()) {
            List<BluetoothDevice> deviceList = mService.getConnectedDevices();
            for (BluetoothDevice d : deviceList) {
                mService.disconnect(d);
            }
        }
        Assert.assertTrue(mService.getInstanceMap().isEmpty());
    }

    private void startServices() {
        Intent startIntent = new Intent(mTargetContext, MapClientService.class);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON);
        try {
            mServiceRule.startService(startIntent);
        } catch (TimeoutException e) {
            Log.e(TAG, "startServices, timeout " + e);
            Assert.fail();
        }

        // At this point the service should have started so check NOT null
        mService = MapClientService.getMapClientService();
        Assert.assertNotNull(mService);
    }

    @Test
    public void testInitialize() {
        if (skipTest()) return;
        // Test that we can initialize the service
        Log.i(TAG, "testInitialize, test passed");
    }

    /**
     * Test connection of one device.
     */
    @Test
    public void testConnect() {
        if (skipTest()) return;
        // make sure there is no statemachine already defined for this device
        BluetoothDevice device = makeBluetoothDevice("11:11:11:11:11:11");
        Assert.assertNull(mService.getInstanceMap().get(device));

        // connect a bluetooth device
        Assert.assertTrue(mService.connect(device));

        // is the statemachine created
        Map<BluetoothDevice, MceStateMachine> map = mService.getInstanceMap();
        Assert.assertEquals(1, map.size());
        Assert.assertNotNull(map.get(device));
    }

    /**
     * Test connecting MAXIMUM_CONNECTED_DEVICES devices.
     */
    @Test
    public void testConnectMaxDevices() {
        if (skipTest()) return;
        // Create bluetoothdevice & mock statemachine objects to be used in this test
        List<BluetoothDevice> list = new ArrayList<>();
        String address = "11:11:11:11:11:1";
        for (int i = 0; i < MapClientService.MAXIMUM_CONNECTED_DEVICES; ++i) {
            list.add(makeBluetoothDevice(address + i));
        }

        // make sure there is no statemachine already defined for the devices defined above
        for (BluetoothDevice d : list) {
            Assert.assertNull(mService.getInstanceMap().get(d));
        }

        // run the test - connect all devices
        for (BluetoothDevice d : list) {
            Assert.assertTrue(mService.connect(d));
        }

        // verify
        Map<BluetoothDevice, MceStateMachine> map = mService.getInstanceMap();
        Assert.assertEquals(MapClientService.MAXIMUM_CONNECTED_DEVICES, map.size());
        for (BluetoothDevice d : list) {
            Assert.assertNotNull(map.get(d));
        }

        // Try to connect one more device. Should fail.
        BluetoothDevice last = makeBluetoothDevice("11:22:33:44:55:66");
        Assert.assertFalse(mService.connect(last));
    }

    private BluetoothDevice makeBluetoothDevice(String address) {
        Parcel p1 = Parcel.obtain();
        p1.writeString(address);
        p1.setDataPosition(0);
        BluetoothDevice device = BluetoothDevice.CREATOR.createFromParcel(p1);
        p1.recycle();
        return device;
    }
}
