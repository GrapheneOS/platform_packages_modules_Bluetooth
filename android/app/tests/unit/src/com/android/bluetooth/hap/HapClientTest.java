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

package com.android.bluetooth.hap;

import static org.mockito.Mockito.*;

import android.bluetooth.*;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Looper;
import android.os.ParcelUuid;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.MediumTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.bluetooth.btservice.storage.DatabaseManager;
import com.android.bluetooth.csip.CsipSetCoordinatorService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class HapClientTest {
    private static final int TIMEOUT_MS = 1000;
    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();
    private BluetoothAdapter mAdapter;
    private BluetoothDevice mDevice;
    private BluetoothDevice mDevice2;
    private BluetoothDevice mDevice3;
    private Context mTargetContext;
    private HapClientService mService;
    private IBluetoothHapClient.Stub mServiceBinder;
    private HasIntentReceiver mHasIntentReceiver;
    private HashMap<BluetoothDevice, LinkedBlockingQueue<Intent>> mIntentQueue;
    @Mock
    private AdapterService mAdapterService;
    @Mock
    private DatabaseManager mDatabaseManager;
    @Mock
    private HapClientNativeInterface mNativeInterface;
    @Mock
    private ServiceFactory mServiceFactory;
    @Mock
    private CsipSetCoordinatorService mCsipService;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when HearingAccessClientService is not enabled",
                mTargetContext.getResources().getBoolean(R.bool.profile_supported_hap_client));

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
        mService.mHapClientNativeInterface = mNativeInterface;
        mService.mFactory = mServiceFactory;
        doReturn(mCsipService).when(mServiceFactory).getCsipSetCoordinatorService();
        mServiceBinder = (IBluetoothHapClient.Stub) mService.initBinder();
        Assert.assertNotNull(mServiceBinder);

        // Set up the State Changed receiver
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE);
        filter.addAction(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET);
        filter.addAction(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET_SELECT_ERROR);
        filter.addAction(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO);
        filter.addAction(BluetoothHapClient.ACTION_HAP_ON_PRESET_NAME_SET_ERROR);
        filter.addAction(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO_GET_ERROR);

        mHasIntentReceiver = new HasIntentReceiver();
        mTargetContext.registerReceiver(mHasIntentReceiver, filter);

        mDevice = TestUtils.getTestDevice(mAdapter, 0);
        when(mNativeInterface.getDevice(getByteAddress(mDevice))).thenReturn(mDevice);
        mDevice2 = TestUtils.getTestDevice(mAdapter, 1);
        when(mNativeInterface.getDevice(getByteAddress(mDevice2))).thenReturn(mDevice2);
        mDevice3 = TestUtils.getTestDevice(mAdapter, 2);
        when(mNativeInterface.getDevice(getByteAddress(mDevice3))).thenReturn(mDevice3);

        doReturn(BluetoothDevice.BOND_BONDED).when(mAdapterService)
                .getBondState(any(BluetoothDevice.class));
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        doReturn(mDatabaseManager).when(mAdapterService).getDatabase();

        mIntentQueue = new HashMap<>();
        mIntentQueue.put(mDevice, new LinkedBlockingQueue<>());
        mIntentQueue.put(mDevice2, new LinkedBlockingQueue<>());
        mIntentQueue.put(mDevice3, new LinkedBlockingQueue<>());
    }

    @After
    public void tearDown() throws Exception {
        if (!mTargetContext.getResources().getBoolean(
                R.bool.profile_supported_hap_client)) {
            return;
        }
        stopService();
        mTargetContext.unregisterReceiver(mHasIntentReceiver);
        TestUtils.clearAdapterService(mAdapterService);
        mIntentQueue.clear();
    }

    private void startService() throws TimeoutException {
        TestUtils.startService(mServiceRule, HapClientService.class);
        mService = HapClientService.getHapClientService();
        Assert.assertNotNull(mService);
    }

    private void stopService() throws TimeoutException {
        TestUtils.stopService(mServiceRule, HapClientService.class);
        mService = HapClientService.getHapClientService();
        Assert.assertNull(mService);
    }

    /**
     * Test getting HA Service Client
     */
    @Test
    public void testGetHearingAidService() {
        Assert.assertEquals(mService, HapClientService.getHapClientService());
    }

    /**
     * Test stop HA Service Client
     */
    @Test
    public void testStopHearingAidService() {
        Assert.assertEquals(mService, HapClientService.getHapClientService());

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

    /**
     * Test get/set policy for BluetoothDevice
     */
    @Test
    public void testGetSetPolicy() {
        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
        Assert.assertEquals("Initial device policy",
                BluetoothProfile.CONNECTION_POLICY_UNKNOWN,
                mService.getConnectionPolicy(mDevice));

        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);
        Assert.assertEquals("Setting device policy to POLICY_FORBIDDEN",
                BluetoothProfile.CONNECTION_POLICY_FORBIDDEN,
                mService.getConnectionPolicy(mDevice));

        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        Assert.assertEquals("Setting device policy to POLICY_ALLOWED",
                BluetoothProfile.CONNECTION_POLICY_ALLOWED,
                mService.getConnectionPolicy(mDevice));
    }

    /**
     * Test okToConnect method using various test cases
     */
    @Test
    public void testOkToConnect() {
        int badPolicyValue = 1024;
        int badBondState = 42;
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_NONE, BluetoothProfile.CONNECTION_POLICY_UNKNOWN, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_NONE, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_NONE, BluetoothProfile.CONNECTION_POLICY_ALLOWED, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_NONE, badPolicyValue, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDING, BluetoothProfile.CONNECTION_POLICY_UNKNOWN, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDING, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDING, BluetoothProfile.CONNECTION_POLICY_ALLOWED, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDING, badPolicyValue, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDED, BluetoothProfile.CONNECTION_POLICY_UNKNOWN, true);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDED, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN, false);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDED, BluetoothProfile.CONNECTION_POLICY_ALLOWED, true);
        testOkToConnectCase(mDevice,
                BluetoothDevice.BOND_BONDED, badPolicyValue, false);
        testOkToConnectCase(mDevice,
                badBondState, BluetoothProfile.CONNECTION_POLICY_UNKNOWN, false);
        testOkToConnectCase(mDevice,
                badBondState, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN, false);
        testOkToConnectCase(mDevice,
                badBondState, BluetoothProfile.CONNECTION_POLICY_ALLOWED, false);
        testOkToConnectCase(mDevice,
                badBondState, badPolicyValue, false);
    }

    /**
     * Test that an outgoing connection to device that does not have HAS UUID is rejected
     */
    @Test
    public void testOutgoingConnectMissingHasUuid() {
        // Update the device policy so okToConnect() returns true
        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        doReturn(true).when(mNativeInterface).connectHapClient(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHapClient(any(BluetoothDevice.class));

        // Return No UUID
        doReturn(new ParcelUuid[]{}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        // Send a connect request
        Assert.assertFalse("Connect expected to fail", mService.connect(mDevice));
    }

    /**
     * Test that an outgoing connection to device that have HAS UUID is successful
     */
    @Test
    public void testOutgoingConnectExistingHasUuid() {
        // Update the device policy so okToConnect() returns true
        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        doReturn(true).when(mNativeInterface).connectHapClient(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHapClient(any(BluetoothDevice.class));

        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        // Send a connect request
        Assert.assertTrue("Connect expected to succeed", mService.connect(mDevice));
    }

    /**
     * Test that an outgoing connection to device with POLICY_FORBIDDEN is rejected
     */
    @Test
    public void testOutgoingConnectPolicyForbidden() {
        doReturn(true).when(mNativeInterface).connectHapClient(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHapClient(any(BluetoothDevice.class));

        // Set the device policy to POLICY_FORBIDDEN so connect() should fail
        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);

        // Send a connect request
        Assert.assertFalse("Connect expected to fail", mService.connect(mDevice));
    }

    /**
     * Test that an outgoing connection times out
     */
    @Test
    public void testOutgoingConnectTimeout() {
        // Update the device policy so okToConnect() returns true
        when(mDatabaseManager
                .getProfileConnectionPolicy(mDevice, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        doReturn(true).when(mNativeInterface).connectHapClient(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHapClient(any(BluetoothDevice.class));

        // Send a connect request
        Assert.assertTrue("Connect failed", mService.connect(mDevice));

        // Verify the connection state broadcast, and that we are in Connecting state
        verifyConnectionStateIntent(TIMEOUT_MS, mDevice, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                mService.getConnectionState(mDevice));

        // Verify the connection state broadcast, and that we are in Disconnected state
        verifyConnectionStateIntent(HapClientStateMachine.sConnectTimeoutMs * 2,
                mDevice, BluetoothProfile.STATE_DISCONNECTED,
                BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                mService.getConnectionState(mDevice));
    }

    /**
     * Test that an outgoing connection to two device that have HAS UUID is successful
     */
    @Test
    public void testConnectTwo() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        // Send a connect request for the 1st device
        testConnectingDevice(mDevice);

        // Send a connect request for the 2nd device
        BluetoothDevice Device2 = TestUtils.getTestDevice(mAdapter, 1);
        testConnectingDevice(Device2);

        List<BluetoothDevice> devices = mService.getConnectedDevices();
        Assert.assertTrue(devices.contains(mDevice));
        Assert.assertTrue(devices.contains(Device2));
        Assert.assertNotEquals(mDevice, Device2);
    }

    /**
     * Test that for the unknown device the API calls are not forwarded down the stack to native.
     */
    @Test
    public void testCallsForNotConnectedDevice() {
        Assert.assertEquals(true, mService.getActivePresetIndex(mDevice));

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(BluetoothHapClient.PRESET_INDEX_UNAVAILABLE,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
    }

    /**
     * Test getting HAS coordinated sets.
     */
    @Test
    public void testGetHapGroupCoordinatedOps() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);
        testConnectingDevice(mDevice2);
        testConnectingDevice(mDevice3);

        int flags = 0x04;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice), flags);

        int flags2 = 0x04;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice2), flags);

        /* This one has no coordinated operation support but is part of a coordinated set with
         * mDevice, which supports it, thus mDevice will forward the operation to mDevice2.
         * This device should also be rocognised as grouped one.
         */
        int flags3 = 0;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice3), flags3);

        /* Prepare CAS groups */
        int base_group_id = 0x03;
        Map groups = new HashMap<Integer, ParcelUuid>();
        groups.put(base_group_id, ParcelUuid.fromString("00001853-0000-1000-8000-00805F9B34FB"));

        Map groups2 = new HashMap<Integer, ParcelUuid>();
        groups2.put(base_group_id + 1,
                ParcelUuid.fromString("00001853-0000-1000-8000-00805F9B34FB"));

        doReturn(groups).when(mCsipService).getGroupUuidMapByDevice(mDevice);
        doReturn(groups).when(mCsipService).getGroupUuidMapByDevice(mDevice3);
        doReturn(groups2).when(mCsipService).getGroupUuidMapByDevice(mDevice2);

        /* Two devices support coordinated operations thus shell report valid group ID */
        Assert.assertEquals(base_group_id, mService.getHapGroup(mDevice));
        Assert.assertEquals(base_group_id + 1, mService.getHapGroup(mDevice2));

        /* Third one has no coordinated operations support but is part of the group */
        Assert.assertEquals(base_group_id, mService.getHapGroup(mDevice3));
    }

    /**
     * Test that selectActivePreset properly calls the native method.
     */
    @Test
    public void testSelectActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);

        // Verify Native Interface call
        Assert.assertFalse(mService.selectActivePreset(mDevice, 0x00));
        verify(mNativeInterface, times(0))
                .selectActivePreset(eq(mDevice), eq(0x00));
        Assert.assertTrue(mService.selectActivePreset(mDevice, 0x01));
        verify(mNativeInterface, times(1))
                .selectActivePreset(eq(mDevice), eq(0x01));
    }

    /**
     * Test that groupSelectActivePreset properly calls the native method.
     */
    @Test
    public void testGroupSelectActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        int flags = 0x01;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice), flags);

        // Verify Native Interface call
        Assert.assertFalse(mService.groupSelectActivePreset(0x03, 0x00));
        Assert.assertTrue(mService.groupSelectActivePreset(0x03, 0x01));
        verify(mNativeInterface, times(1))
                .groupSelectActivePreset(eq(0x03), eq(0x01));
    }

    /**
     * Test that nextActivePreset properly calls the native method.
     */
    @Test
    public void testNextActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);

        // Verify Native Interface call
        Assert.assertTrue(mService.nextActivePreset(mDevice));
        verify(mNativeInterface, times(1))
                .nextActivePreset(eq(mDevice));
    }

    /**
     * Test that groupNextActivePreset properly calls the native method.
     */
    @Test
    public void testGroupNextActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        int flags = 0x01;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice), flags);

        // Verify Native Interface call
        Assert.assertTrue(mService.groupNextActivePreset(0x03));
        verify(mNativeInterface, times(1)).groupNextActivePreset(eq(0x03));
    }

    /**
     * Test that previousActivePreset properly calls the native method.
     */
    @Test
    public void testPreviousActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);

        // Verify Native Interface call
        Assert.assertTrue(mService.previousActivePreset(mDevice));
        verify(mNativeInterface, times(1))
                .previousActivePreset(eq(mDevice));
    }

    /**
     * Test that groupPreviousActivePreset properly calls the native method.
     */
    @Test
    public void testGroupPreviousActivePresetNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);
        testConnectingDevice(mDevice2);

        int flags = 0x01;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice), flags);

        // Verify Native Interface call
        Assert.assertTrue(mService.groupPreviousActivePreset(0x03));
        verify(mNativeInterface, times(1)).groupPreviousActivePreset(eq(0x03));
    }

    /**
     * Test that getActivePresetIndex returns cached value.
     */
    @Test
    public void testGetActivePresetIndex() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);
        testOnActivePresetSelected(mDevice, 0x01);

        // Verify cached value
        Assert.assertEquals(true, mService.getActivePresetIndex(mDevice));

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(0x01,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
    }

    /**
     * Test that getPresetInfo properly calls the native method.
     */
    @Test
    public void testGetPresetInfoNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);

        // Verify Native Interface call
        Assert.assertFalse(mService.getPresetInfo(mDevice, 0x00));
        verify(mNativeInterface, times(0))
                .getPresetInfo(eq(mDevice), eq(0x00));
        Assert.assertTrue(mService.getPresetInfo(mDevice, 0x01));
        verify(mNativeInterface, times(1))
                .getPresetInfo(eq(mDevice), eq(0x01));
    }

    /**
     * Test that setPresetName properly calls the native method.
     */
    @Test
    public void testSetPresetNameNative() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        testConnectingDevice(mDevice);

        // Verify Native Interface call
        Assert.assertFalse(mService.setPresetName(mDevice, 0x00, "ExamplePresetName"));
        verify(mNativeInterface, times(0))
                .setPresetName(eq(mDevice), eq(0x00), eq("ExamplePresetName"));
        Assert.assertTrue(mService.setPresetName(mDevice, 0x01, "ExamplePresetName"));
        verify(mNativeInterface, times(1))
                .setPresetName(eq(mDevice), eq(0x01), eq("ExamplePresetName"));
    }

    /**
     * Test that groupSetPresetName properly calls the native method.
     */
    @Test
    public void testGroupSetPresetName() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));
        int flags = 0x21;
        mNativeInterface.onFeaturesUpdate(getByteAddress(mDevice), flags);

        // Verify Native Interface call
        Assert.assertFalse(mService.groupSetPresetName(0x03, 0x00, "ExamplePresetName"));
        Assert.assertFalse(mService.groupSetPresetName(-1, 0x01, "ExamplePresetName"));
        Assert.assertTrue(mService.groupSetPresetName(0x03, 0x01, "ExamplePresetName"));
        verify(mNativeInterface, times(1))
                .groupSetPresetName(eq(0x03), eq(0x01), eq("ExamplePresetName"));
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventDeviceAvailable() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        // Verify getting current preset return an invalid value when there is no such device
        // available
        Assert.assertEquals(true, mService.getActivePresetIndex(mDevice));

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(BluetoothHapClient.PRESET_INDEX_UNAVAILABLE,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));

        mNativeInterface.onDeviceAvailable(getByteAddress(mDevice), 0x03);

        intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(0x03,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_FEATURES, 0x03));
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventOnActivePresetSelected() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        mNativeInterface.onActivePresetSelected(getByteAddress(mDevice), 0x01);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(0x01,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));

        // Verify that getting current preset returns a proper value now
        Assert.assertEquals(true, mService.getActivePresetIndex(mDevice));

        intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(0x01,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventOnCurrentPresetSelectError() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        mNativeInterface.onActivePresetSelectError(getByteAddress(mDevice),
                BluetoothHapClient.STATUS_INVALID_PRESET_INDEX);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET_SELECT_ERROR,
                intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(BluetoothHapClient.STATUS_INVALID_PRESET_INDEX,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, -1));
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventOnPresetInfo() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        int info_reason = BluetoothHapClient.PRESET_INFO_REASON_PRESET_INFO_UPDATE;
        BluetoothHapPresetInfo[] info =
                {new BluetoothHapPresetInfo.Builder()
                        .setIndex(0x01)
                        .setName("PresetName")
                        .setWritable(true)
                        .setAvailable(true)
                        .build()};
        mNativeInterface.onPresetInfo(getByteAddress(mDevice), info_reason, info);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO, intent.getAction());
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(info_reason,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO_REASON, -1));

        ArrayList presets =
                intent.getParcelableArrayListExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INFO);
        Assert.assertNotNull(presets);

        BluetoothHapPresetInfo preset = (BluetoothHapPresetInfo) presets.get(0);
        Assert.assertEquals(preset.getIndex(), info[0].getIndex());
        Assert.assertEquals(preset.getName(), info[0].getName());
        Assert.assertEquals(preset.isWritable(), info[0].isWritable());
        Assert.assertEquals(preset.isAvailable(), info[0].isAvailable());
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventOnPresetNameSetError() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        mNativeInterface.onPresetNameSetError(getByteAddress(mDevice), 0x01,
                BluetoothHapClient.STATUS_SET_NAME_NOT_ALLOWED);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_PRESET_NAME_SET_ERROR,
                intent.getAction());
        Assert.assertEquals(0x01,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(BluetoothHapClient.STATUS_SET_NAME_NOT_ALLOWED,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, -1));
    }

    /**
     * Test that native callback generates proper intent.
     */
    @Test
    public void testStackEventOnPresetInfoError() {
        doReturn(new ParcelUuid[]{BluetoothUuid.HAS}).when(mAdapterService)
                .getRemoteUuids(any(BluetoothDevice.class));

        mNativeInterface.onPresetInfoError(getByteAddress(mDevice), 0x01,
                BluetoothHapClient.STATUS_INVALID_PRESET_INDEX);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(mDevice));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_PRESET_INFO_GET_ERROR,
                intent.getAction());
        Assert.assertEquals(0x01,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
        Assert.assertEquals(mDevice, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(BluetoothHapClient.STATUS_INVALID_PRESET_INDEX,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_STATUS_CODE, -1));
    }

    /**
     * Helper function to test device connecting
     */
    private void prepareConnectingDevice(BluetoothDevice device) {
        // Prepare intent queue and all the mocks
        mIntentQueue.put(device, new LinkedBlockingQueue<>());
        when(mNativeInterface.getDevice(getByteAddress(device))).thenReturn(device);
        when(mDatabaseManager
                .getProfileConnectionPolicy(device, BluetoothProfile.HAP_CLIENT))
                .thenReturn(BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        doReturn(true).when(mNativeInterface).connectHapClient(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).disconnectHapClient(any(BluetoothDevice.class));
    }

    /**
     * Helper function to test device connecting
     */
    private void testConnectingDevice(BluetoothDevice device) {
        prepareConnectingDevice(device);
        // Send a connect request
        Assert.assertTrue("Connect expected to succeed", mService.connect(device));
        verifyConnectingDevice(device);
    }

    /**
     * Helper function to test device connecting
     */
    private void verifyConnectingDevice(BluetoothDevice device) {
        // Verify the connection state broadcast, and that we are in Connecting state
        verifyConnectionStateIntent(TIMEOUT_MS, device, BluetoothProfile.STATE_CONNECTING,
                BluetoothProfile.STATE_DISCONNECTED);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING, mService.getConnectionState(device));

        // Send a message to trigger connection completed
        HapClientStackEvent evt =
                new HapClientStackEvent(HapClientStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        evt.device = device;
        evt.valueInt1 = HapClientStackEvent.CONNECTION_STATE_CONNECTED;
        mService.messageFromNative(evt);

        // Verify the connection state broadcast, and that we are in Connected state
        verifyConnectionStateIntent(TIMEOUT_MS, device, BluetoothProfile.STATE_CONNECTED,
                BluetoothProfile.STATE_CONNECTING);
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED, mService.getConnectionState(device));

        evt = new HapClientStackEvent(HapClientStackEvent.EVENT_TYPE_DEVICE_AVAILABLE);
        evt.device = device;
        evt.valueInt1 = 0x01;   // features
        mService.messageFromNative(evt);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(device));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE, intent.getAction());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(evt.valueInt1,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_FEATURES, -1));
    }

    private void testOnActivePresetSelected(BluetoothDevice device, int index) {
        HapClientStackEvent evt =
                new HapClientStackEvent(HapClientStackEvent.EVENT_TYPE_ON_ACTIVE_PRESET_SELECTED);
        evt.device = device;
        evt.valueInt1 = index;
        mService.messageFromNative(evt);

        Intent intent = TestUtils.waitForIntent(TIMEOUT_MS, mIntentQueue.get(device));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_ON_ACTIVE_PRESET, intent.getAction());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(index,
                intent.getIntExtra(BluetoothHapClient.EXTRA_HAP_PRESET_INDEX, -1));
    }

    /**
     * Helper function to test ConnectionStateIntent() method
     */
    private void verifyConnectionStateIntent(int timeoutMs, BluetoothDevice device,
                                             int newState, int prevState) {
        Intent intent = TestUtils.waitForIntent(timeoutMs, mIntentQueue.get(device));
        Assert.assertNotNull(intent);
        Assert.assertEquals(BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED,
                intent.getAction());
        Assert.assertEquals(device, intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE));
        Assert.assertEquals(newState, intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        Assert.assertEquals(prevState, intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                -1));
    }

    /**
     * Helper function to test okToConnect() method
     */
    private void testOkToConnectCase(BluetoothDevice device, int bondState, int policy,
                                     boolean expected) {
        doReturn(bondState).when(mAdapterService).getBondState(device);
        when(mDatabaseManager.getProfileConnectionPolicy(device, BluetoothProfile.HAP_CLIENT))
                .thenReturn(policy);
        Assert.assertEquals(expected, mService.okToConnect(device));
    }

    /**
     * Helper function to get byte array for a device address
     */
    private byte[] getByteAddress(BluetoothDevice device) {
        if (device == null) {
            return Utils.getBytesFromAddress("00:00:00:00:00:00");
        }
        return Utils.getBytesFromAddress(device.getAddress());
    }

    private class HasIntentReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            try {
                BluetoothDevice device = intent.getParcelableExtra(
                        BluetoothDevice.EXTRA_DEVICE);
                Assert.assertNotNull(device);
                LinkedBlockingQueue<Intent> queue = mIntentQueue.get(device);
                Assert.assertNotNull(queue);
                queue.put(intent);
            } catch (InterruptedException e) {
                Assert.fail("Cannot add Intent to the queue: " + e.getMessage());
            }
        }
    }
}
