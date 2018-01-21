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

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.os.Looper;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class ProfileServiceTest {
    private static final int PROFILE_START_MILLIS = 1250;

    @Rule public final ServiceTestRule mServiceTestRule = new ServiceTestRule();

    private void setProfileState(Class profile, int state) throws TimeoutException {
        Intent startIntent = new Intent(InstrumentationRegistry.getTargetContext(), profile);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, state);
        mServiceTestRule.startService(startIntent);
    }

    private void setAllProfilesState(int state, int invocationNumber) throws TimeoutException {
        for (Class profile : mProfiles) {
            setProfileState(profile, state);
        }
        for (Class profile : mProfiles) {
            verify(mMockAdapterService, timeout(PROFILE_START_MILLIS).times(
                    invocationNumber)).onProfileServiceStateChanged(eq(profile.getName()),
                    eq(state));
        }
    }

    private @Mock AdapterService mMockAdapterService;

    private Class[] mProfiles;

    @Before
    public void setUp()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Assert.assertNotNull(Looper.myLooper());

        MockitoAnnotations.initMocks(this);

        mProfiles = Config.getSupportedProfiles();

        Method method =
                AdapterService.class.getDeclaredMethod("setAdapterService", AdapterService.class);
        method.setAccessible(true);
        method.invoke(null, mMockAdapterService);

        Assert.assertNotNull(AdapterService.getAdapterService());
    }

    @After
    public void tearDown() {
        mMockAdapterService = null;
        mProfiles = null;
    }

    /**
     * Test: Start the Bluetooth services that are configured.
     * Verify that the same services start.
     */
    @Test
    public void testEnableDisable() throws TimeoutException {
        setAllProfilesState(BluetoothAdapter.STATE_ON, 1);
        setAllProfilesState(BluetoothAdapter.STATE_OFF, 1);
    }

    /**
     * Test: Start the Bluetooth services that are configured twice.
     * Verify that the services start.
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
        for (Class profile : mProfiles) {
            setProfileState(profile, BluetoothAdapter.STATE_ON);
            setProfileState(profile, BluetoothAdapter.STATE_OFF);
        }
        for (Class profile : mProfiles) {
            verify(mMockAdapterService,
                    timeout(PROFILE_START_MILLIS)).onProfileServiceStateChanged(
                    eq(profile.getName()), eq(BluetoothAdapter.STATE_ON));
            verify(mMockAdapterService,
                    timeout(PROFILE_START_MILLIS)).onProfileServiceStateChanged(
                    eq(profile.getName()), eq(BluetoothAdapter.STATE_OFF));
        }
    }

    /**
     * Test: Start and stop a single profile repeatedly.
     * Verify that the profiles start and stop.
     */
    @Test
    public void testRepeatedEnableDisableSingly() throws TimeoutException {
        for (Class profile : mProfiles) {
            Log.d("Singly", "profile = " + profile.getSimpleName());
            for (int i = 0; i < 5; i++) {
                setProfileState(profile, BluetoothAdapter.STATE_ON);
                verify(mMockAdapterService,
                        timeout(PROFILE_START_MILLIS).times(i + 1)).onProfileServiceStateChanged(
                        eq(profile.getName()), eq(BluetoothAdapter.STATE_ON));
                Log.d("Singly", "profile = " + profile.getSimpleName() + ": enabled " + i);
                setProfileState(profile, BluetoothAdapter.STATE_OFF);
                verify(mMockAdapterService,
                        timeout(PROFILE_START_MILLIS).times(i + 1)).onProfileServiceStateChanged(
                        eq(profile.getName()), eq(BluetoothAdapter.STATE_OFF));
                Log.d("Singly", " " + profile.getSimpleName() + ": disabled " + i);
            }
        }
    }
}
