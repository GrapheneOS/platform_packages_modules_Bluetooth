/*
 * Copyright 2019 The Android Open Source Project
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

package com.android.bluetooth.btservice;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import androidx.room.Room;

import com.android.bluetooth.TestUtils;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;

@MediumTest
@RunWith(AndroidJUnit4.class)
public final class DatabaseManagerTest {

    @Mock private AdapterService mAdapterService;

    private MetadataDatabase mDatabase;
    private DatabaseManager mDatabaseManager;
    private BluetoothDevice mTestDevice;

    private static final String LOCAL_STORAGE = "LocalStorage";
    private static final String TEST_BT_ADDR = "11:22:33:44:55:66";
    private static final String OTHER_BT_ADDR = "11:11:11:11:11:11";
    private static final int A2DP_SUPPORT_OP_CODEC_TEST = 0;
    private static final int A2DP_ENALBED_OP_CODEC_TEST = 1;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);

        mTestDevice = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(TEST_BT_ADDR);

        // Create a memory database for DatabaseManager instead of use a real database.
        mDatabase = Room.inMemoryDatabaseBuilder(InstrumentationRegistry.getTargetContext(),
                MetadataDatabase.class).build();

        mDatabaseManager = new DatabaseManager(mAdapterService);
        //mDatabaseManager.doNotMigrateSettingGlobal();

        BluetoothDevice[] bondedDevices = {};
        doReturn(bondedDevices).when(mAdapterService).getBondedDevices();

        mDatabaseManager.start(mDatabase);
        // Wait for handler thread finish its task.
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());

        // Clear local storage
        mDatabaseManager.mMetadataCache.clear();
        mDatabase.delete(LOCAL_STORAGE);
    }

    @After
    public void tearDown() throws Exception {
        TestUtils.clearAdapterService(mAdapterService);
        mDatabase.deleteAll();
        mDatabaseManager.cleanup();
    }

    @Test
    public void testSetGetProfilePriority() {
        int badPriority = -100;

        // Cases of device not in database
        testSetGetProfilePriorityCase(false, BluetoothProfile.PRIORITY_UNDEFINED,
                BluetoothProfile.PRIORITY_UNDEFINED, true);
        testSetGetProfilePriorityCase(false, BluetoothProfile.PRIORITY_OFF,
                BluetoothProfile.PRIORITY_OFF, true);
        testSetGetProfilePriorityCase(false, BluetoothProfile.PRIORITY_ON,
                BluetoothProfile.PRIORITY_ON, true);
        testSetGetProfilePriorityCase(false, BluetoothProfile.PRIORITY_AUTO_CONNECT,
                BluetoothProfile.PRIORITY_AUTO_CONNECT, true);
        testSetGetProfilePriorityCase(false, badPriority,
                BluetoothProfile.PRIORITY_UNDEFINED, false);

        // Cases of device already in database
        testSetGetProfilePriorityCase(true, BluetoothProfile.PRIORITY_UNDEFINED,
                BluetoothProfile.PRIORITY_UNDEFINED, true);
        testSetGetProfilePriorityCase(true, BluetoothProfile.PRIORITY_OFF,
                BluetoothProfile.PRIORITY_OFF, true);
        testSetGetProfilePriorityCase(true, BluetoothProfile.PRIORITY_ON,
                BluetoothProfile.PRIORITY_ON, true);
        testSetGetProfilePriorityCase(true, BluetoothProfile.PRIORITY_AUTO_CONNECT,
                BluetoothProfile.PRIORITY_AUTO_CONNECT, true);
        testSetGetProfilePriorityCase(true, badPriority,
                BluetoothProfile.PRIORITY_UNDEFINED, false);
    }

    @Test
    public void testSetGetA2dpSupportsOptionalCodecs() {
        int badValue = -100;

        // Cases of device not in database
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, false,
                badValue, BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);

        // Cases of device already in database
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED,
                BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED,
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED);
        testSetGetA2dpOptionalCodecsCase(A2DP_SUPPORT_OP_CODEC_TEST, true,
                badValue, BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED);
    }

    @Test
    public void testSetGetA2dpOptionalCodecsEnabled() {
        int badValue = -100;

        // Cases of device not in database
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, false,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, false,
                badValue, BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);

        // Cases of device already in database
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, true,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED,
                BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED);
        testSetGetA2dpOptionalCodecsCase(A2DP_ENALBED_OP_CODEC_TEST, true,
                badValue, BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED);
    }

    @Test
    public void testRemoveUnusedMetadata() {
        // Insert two devices to database and cache, only mTestDevice is
        // in the bonded list
        BluetoothDevice otherDevice = BluetoothAdapter.getDefaultAdapter()
                .getRemoteDevice(OTHER_BT_ADDR);
        Metadata otherData = new Metadata(OTHER_BT_ADDR);
        mDatabaseManager.mMetadataCache.put(OTHER_BT_ADDR, otherData);
        mDatabase.insert(otherData);

        Metadata data = new Metadata(TEST_BT_ADDR);
        mDatabaseManager.mMetadataCache.put(TEST_BT_ADDR, data);
        mDatabase.insert(data);

        BluetoothDevice[] bondedDevices = {mTestDevice};
        doReturn(bondedDevices).when(mAdapterService).getBondedDevices();

        mDatabaseManager.removeUnusedMetadata();
        // Wait for database update
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());

        List<Metadata> list = mDatabase.load();

        // Check number of metadata in the database
        Assert.assertEquals(1, list.size());

        // Check whether the device is in database
        Metadata checkData = list.get(0);
        Assert.assertEquals(TEST_BT_ADDR, checkData.getAddress());

        mDatabase.deleteAll();
        // Wait for clear database
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());
        mDatabaseManager.mMetadataCache.clear();
    }

    void testSetGetProfilePriorityCase(boolean stored, int priority, int expectedPriority,
            boolean expectedSetResult) {
        if (stored) {
            Metadata data = new Metadata(TEST_BT_ADDR);
            mDatabaseManager.mMetadataCache.put(TEST_BT_ADDR, data);
            mDatabase.insert(data);
        }
        Assert.assertEquals(expectedSetResult,
                mDatabaseManager.setProfilePriority(mTestDevice,
                BluetoothProfile.HEADSET, priority));
        Assert.assertEquals(expectedPriority,
                mDatabaseManager.getProfilePriority(mTestDevice, BluetoothProfile.HEADSET));
        // Wait for database update
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());

        List<Metadata> list = mDatabase.load();

        // Check number of metadata in the database
        if (!stored) {
            if (priority != BluetoothProfile.PRIORITY_OFF
                    && priority != BluetoothProfile.PRIORITY_ON
                    && priority != BluetoothProfile.PRIORITY_AUTO_CONNECT) {
                // Database won't be updated
                Assert.assertEquals(0, list.size());
                return;
            }
        }
        Assert.assertEquals(1, list.size());

        // Check whether the device is in database
        Metadata data = list.get(0);
        Assert.assertEquals(TEST_BT_ADDR, data.getAddress());
        Assert.assertEquals(expectedPriority, data.getProfilePriority(BluetoothProfile.HEADSET));

        mDatabase.deleteAll();
        // Wait for clear database
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());
        mDatabaseManager.mMetadataCache.clear();
    }

    void testSetGetA2dpOptionalCodecsCase(int test, boolean stored, int value, int expectedValue) {
        if (stored) {
            Metadata data = new Metadata(TEST_BT_ADDR);
            mDatabaseManager.mMetadataCache.put(TEST_BT_ADDR, data);
            mDatabase.insert(data);
        }
        if (test == A2DP_SUPPORT_OP_CODEC_TEST) {
            mDatabaseManager.setA2dpSupportsOptionalCodecs(mTestDevice, value);
            Assert.assertEquals(expectedValue,
                    mDatabaseManager.getA2dpSupportsOptionalCodecs(mTestDevice));
        } else {
            mDatabaseManager.setA2dpOptionalCodecsEnabled(mTestDevice, value);
            Assert.assertEquals(expectedValue,
                    mDatabaseManager.getA2dpOptionalCodecsEnabled(mTestDevice));
        }
        // Wait for database update
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());

        List<Metadata> list = mDatabase.load();

        // Check number of metadata in the database
        if (!stored) {
            // Database won't be updated
            Assert.assertEquals(0, list.size());
            return;
        }
        Assert.assertEquals(1, list.size());

        // Check whether the device is in database
        Metadata data = list.get(0);
        Assert.assertEquals(TEST_BT_ADDR, data.getAddress());
        if (test == A2DP_SUPPORT_OP_CODEC_TEST) {
            Assert.assertEquals(expectedValue, data.a2dpSupportsOptionalCodecs);
        } else {
            Assert.assertEquals(expectedValue, data.a2dpOptionalCodecsEnabled);
        }

        mDatabase.deleteAll();
        // Wait for clear database
        TestUtils.waitForLooperToFinishScheduledTask(mDatabaseManager.getHandlerLooper());
        mDatabaseManager.mMetadataCache.clear();
    }
}
