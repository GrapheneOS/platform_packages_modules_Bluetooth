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

package com.android.bluetooth.btservice;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.location.LocationManager;
import android.os.Looper;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.MediumTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.a2dp.A2dpNativeInterface;
import com.android.bluetooth.avrcp.AvrcpNativeInterface;
import com.android.bluetooth.btservice.storage.DatabaseManager;
import com.android.bluetooth.gatt.GattService;
import com.android.bluetooth.hearingaid.HearingAidNativeInterface;
import com.android.bluetooth.hfp.HeadsetNativeInterface;
import com.android.bluetooth.hid.HidDeviceNativeInterface;
import com.android.bluetooth.hid.HidHostNativeInterface;
import com.android.bluetooth.pan.PanNativeInterface;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class ProfileServiceTest {
    private static final int PROFILE_START_MILLIS = 1250;
    private static final int NUM_REPEATS = 5;

    @Rule public final ServiceTestRule mServiceTestRule = new ServiceTestRule();
    @Mock private AdapterService mMockAdapterService;
    @Mock private DatabaseManager mDatabaseManager;
    @Mock private LocationManager mLocationManager;

    private Class[] mProfiles;
    ConcurrentHashMap<String, Boolean> mStartedProfileMap = new ConcurrentHashMap();

    private void setProfileState(Class profile, int state) throws TimeoutException {
        if (state == BluetoothAdapter.STATE_ON) {
            mStartedProfileMap.put(profile.getSimpleName(), true);
        } else if (state == BluetoothAdapter.STATE_OFF) {
            mStartedProfileMap.put(profile.getSimpleName(), false);
        }
        Intent startIntent = new Intent(InstrumentationRegistry.getTargetContext(), profile);
        startIntent.putExtra(
                AdapterService.EXTRA_ACTION, AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, state);
        mServiceTestRule.startService(startIntent);
    }

    @Mock private A2dpNativeInterface mA2dpNativeInterface;
    @Mock private AvrcpNativeInterface mAvrcpNativeInterface;
    @Mock private HeadsetNativeInterface mHeadsetNativeInterface;
    @Mock private HearingAidNativeInterface mHearingAidNativeInterface;
    @Mock private HidDeviceNativeInterface mHidDeviceNativeInterface;
    @Mock private HidHostNativeInterface mHidHostNativeInterface;
    @Mock private PanNativeInterface mPanNativeInterface;

    private void setAllProfilesState(int state, int invocationNumber) throws TimeoutException {
        int profileCount = mProfiles.length;
        for (Class profile : mProfiles) {
            if (profile == GattService.class) {
                // GattService is no longer a service to be start independently
                profileCount--;
                continue;
            }
            setProfileState(profile, state);
        }
        if (invocationNumber == 0) {
            verify(mMockAdapterService, after(PROFILE_START_MILLIS).never())
                    .onProfileServiceStateChanged(any(), anyInt());
            return;
        }
        ArgumentCaptor<ProfileService> argument = ArgumentCaptor.forClass(ProfileService.class);
        verify(
                        mMockAdapterService,
                        timeout(PROFILE_START_MILLIS).times(profileCount * invocationNumber))
                .onProfileServiceStateChanged(argument.capture(), eq(state));
        List<ProfileService> argumentProfiles = argument.getAllValues();
        for (Class profile : mProfiles) {
            if (profile == GattService.class) {
                continue;
            }
            int matches = 0;
            for (ProfileService arg : argumentProfiles) {
                if (arg.getClass().getName().equals(profile.getName())) {
                    matches += 1;
                }
            }
            Assert.assertEquals(invocationNumber, matches);
        }
    }

    @Before
    public void setUp()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Assert.assertNotNull(Looper.myLooper());

        MockitoAnnotations.initMocks(this);
        when(mMockAdapterService.isStartedProfile(anyString())).thenAnswer(new Answer<Boolean>() {
            @Override
            public Boolean answer(InvocationOnMock invocation) throws Throwable {
                Object[] args = invocation.getArguments();
                return mStartedProfileMap.get((String) args[0]);
            }
        });
        doReturn(mDatabaseManager).when(mMockAdapterService).getDatabase();

        when(mMockAdapterService.getSystemService(Context.LOCATION_SERVICE))
                .thenReturn(mLocationManager);
        when(mMockAdapterService.getSystemServiceName(LocationManager.class))
                .thenReturn(Context.LOCATION_SERVICE);

        mProfiles = Config.getSupportedProfiles();
        TestUtils.setAdapterService(mMockAdapterService);

        Assert.assertNotNull(AdapterService.getAdapterService());

        A2dpNativeInterface.setInstance(mA2dpNativeInterface);
        AvrcpNativeInterface.setInstance(mAvrcpNativeInterface);
        HeadsetNativeInterface.setInstance(mHeadsetNativeInterface);
        HearingAidNativeInterface.setInstance(mHearingAidNativeInterface);
        HidDeviceNativeInterface.setInstance(mHidDeviceNativeInterface);
        HidHostNativeInterface.setInstance(mHidHostNativeInterface);
        PanNativeInterface.setInstance(mPanNativeInterface);
    }

    @After
    public void tearDown()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        TestUtils.clearAdapterService(mMockAdapterService);
        mMockAdapterService = null;
        mProfiles = null;
        A2dpNativeInterface.setInstance(null);
        AvrcpNativeInterface.setInstance(null);
        HeadsetNativeInterface.setInstance(null);
        HearingAidNativeInterface.setInstance(null);
        HidDeviceNativeInterface.setInstance(null);
        HidHostNativeInterface.setInstance(null);
        PanNativeInterface.setInstance(null);
    }

    /**
     * Test: Start the Bluetooth services that are configured. Verify that the same services start.
     */
    @Test
    public void testEnableDisable() throws TimeoutException {
        setAllProfilesState(BluetoothAdapter.STATE_ON, 1);
        setAllProfilesState(BluetoothAdapter.STATE_OFF, 1);
    }

    /**
     * Test: Start the Bluetooth services that are configured twice. Verify that the services start.
     */
    @Test
    public void testEnableDisableTwice() throws TimeoutException {
        setAllProfilesState(BluetoothAdapter.STATE_ON, 1);
        setAllProfilesState(BluetoothAdapter.STATE_OFF, 1);
        setAllProfilesState(BluetoothAdapter.STATE_ON, 2);
        setAllProfilesState(BluetoothAdapter.STATE_OFF, 2);
    }

    /**
     * Test: Start the Bluetooth services that are configured.
     * Verify that each profile starts and stops.
     */
    @Test
    public void testEnableDisableInterleaved() throws TimeoutException {
        int invocationNumber = mProfiles.length;
        for (Class profile : mProfiles) {
            if (profile == GattService.class) {
                // GattService is no longer a service to be start independently
                invocationNumber--;
                continue;
            }
            setProfileState(profile, BluetoothAdapter.STATE_ON);
            setProfileState(profile, BluetoothAdapter.STATE_OFF);
        }
        ArgumentCaptor<ProfileService> starts = ArgumentCaptor.forClass(ProfileService.class);
        ArgumentCaptor<ProfileService> stops = ArgumentCaptor.forClass(ProfileService.class);
        verify(mMockAdapterService,
                timeout(PROFILE_START_MILLIS).times(invocationNumber)).onProfileServiceStateChanged(
                starts.capture(), eq(BluetoothAdapter.STATE_ON));
        verify(mMockAdapterService,
                timeout(PROFILE_START_MILLIS).times(invocationNumber)).onProfileServiceStateChanged(
                stops.capture(), eq(BluetoothAdapter.STATE_OFF));

        List<ProfileService> startedArguments = starts.getAllValues();
        List<ProfileService> stoppedArguments = stops.getAllValues();
        Assert.assertEquals(startedArguments.size(), stoppedArguments.size());
        for (ProfileService service : startedArguments) {
            Assert.assertTrue(stoppedArguments.contains(service));
            stoppedArguments.remove(service);
            Assert.assertFalse(stoppedArguments.contains(service));
        }
    }

    /**
     * Test: Start and stop a single profile repeatedly.
     * Verify that the profiles start and stop.
     */
    @Test
    public void testRepeatedEnableDisableSingly() throws TimeoutException {
        int profileNumber = 0;
        for (Class profile : mProfiles) {
            if (profile == GattService.class) {
                // GattService is no longer a service to be start independently
                continue;
            }
            for (int i = 0; i < NUM_REPEATS; i++) {
                setProfileState(profile, BluetoothAdapter.STATE_ON);
                ArgumentCaptor<ProfileService> start =
                        ArgumentCaptor.forClass(ProfileService.class);
                verify(mMockAdapterService, timeout(PROFILE_START_MILLIS).times(
                        NUM_REPEATS * profileNumber + i + 1)).onProfileServiceStateChanged(
                        start.capture(), eq(BluetoothAdapter.STATE_ON));
                setProfileState(profile, BluetoothAdapter.STATE_OFF);
                ArgumentCaptor<ProfileService> stop = ArgumentCaptor.forClass(ProfileService.class);
                verify(mMockAdapterService, timeout(PROFILE_START_MILLIS).times(
                        NUM_REPEATS * profileNumber + i + 1)).onProfileServiceStateChanged(
                        stop.capture(), eq(BluetoothAdapter.STATE_OFF));
                Assert.assertEquals(start.getValue(), stop.getValue());
            }
            profileNumber += 1;
        }
    }

    /**
     * Test: Start and stop a single profile repeatedly and verify that the profile services are
     * registered and unregistered accordingly.
     */
    @Test
    public void testProfileServiceRegisterUnregister() throws TimeoutException {
        int profileNumber = 0;
        for (Class profile : mProfiles) {
            if (profile == GattService.class) {
                // GattService is no longer a service to be start independently
                continue;
            }
            for (int i = 0; i < NUM_REPEATS; i++) {
                setProfileState(profile, BluetoothAdapter.STATE_ON);
                ArgumentCaptor<ProfileService> start =
                        ArgumentCaptor.forClass(ProfileService.class);
                verify(mMockAdapterService, timeout(PROFILE_START_MILLIS).times(
                        NUM_REPEATS * profileNumber + i + 1)).addProfile(
                        start.capture());
                setProfileState(profile, BluetoothAdapter.STATE_OFF);
                ArgumentCaptor<ProfileService> stop = ArgumentCaptor.forClass(ProfileService.class);
                verify(mMockAdapterService, timeout(PROFILE_START_MILLIS).times(
                        NUM_REPEATS * profileNumber + i + 1)).removeProfile(
                        stop.capture());
                Assert.assertEquals(start.getValue(), stop.getValue());
            }
            profileNumber += 1;
        }
    }

    /**
     * Test: Stop the Bluetooth profile services that are not started.
     * Verify that the profile service state is not changed.
     */
    @Test
    public void testDisable() throws TimeoutException {
        setAllProfilesState(BluetoothAdapter.STATE_OFF, 0);
    }
}
