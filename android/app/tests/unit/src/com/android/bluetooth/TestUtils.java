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
package com.android.bluetooth;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.support.test.InstrumentationRegistry;
import android.support.test.rule.ServiceTestRule;

import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;

import org.junit.Assert;
import org.mockito.internal.util.MockUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A set of methods useful in Bluetooth instrumentation tests
 */
public class TestUtils {
    private static final int SERVICE_TOGGLE_TIMEOUT_MS = 1000;    // 1s

    /**
     * Utilities class with static method only do not have public constructor
     */
    private TestUtils() {}

    /**
     * Set the return value of {@link AdapterService#getAdapterService()} to a test specified value
     *
     * @param adapterService the designated {@link AdapterService} in test, must not be null, can
     * be mocked or spied
     * @throws NoSuchMethodException when setAdapterService method is not found
     * @throws IllegalAccessException when setAdapterService method cannot be accessed
     * @throws InvocationTargetException when setAdapterService method cannot be invoked, which
     * should never happen since setAdapterService is a static method
     */
    public static void setAdapterService(AdapterService adapterService)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Assert.assertNull("AdapterService.getAdapterService() must be null before setting another"
                + " AdapterService", AdapterService.getAdapterService());
        Assert.assertNotNull(adapterService);
        // We cannot mock AdapterService.getAdapterService() with Mockito.
        // Hence we need to use reflection to call a private method to
        // initialize properly the AdapterService.sAdapterService field.
        Method method =
                AdapterService.class.getDeclaredMethod("setAdapterService", AdapterService.class);
        method.setAccessible(true);
        method.invoke(null, adapterService);
    }

    /**
     * Clear the return value of {@link AdapterService#getAdapterService()} to null
     *
     * @param adapterService the {@link AdapterService} used when calling
     * {@link TestUtils#setAdapterService(AdapterService)}
     * @throws NoSuchMethodException when clearAdapterService method is not found
     * @throws IllegalAccessException when clearAdapterService method cannot be accessed
     * @throws InvocationTargetException when clearAdappterService method cannot be invoked,
     * which should never happen since clearAdapterService is a static method
     */
    public static void clearAdapterService(AdapterService adapterService)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Assert.assertSame("AdapterService.getAdapterService() must return the same object as the"
                        + " supplied adapterService in this method", adapterService,
                AdapterService.getAdapterService());
        Assert.assertNotNull(adapterService);
        Method method =
                AdapterService.class.getDeclaredMethod("clearAdapterService", AdapterService.class);
        method.setAccessible(true);
        method.invoke(null, adapterService);
    }

    /**
     * Start a profile service using the given {@link ServiceTestRule} and verify through
     * {@link AdapterService#getAdapterService()} that the service is actually started within
     * {@link TestUtils#SERVICE_TOGGLE_TIMEOUT_MS} milliseconds.
     * {@link #setAdapterService(AdapterService)} must be called with a mocked
     * {@link AdapterService} before calling this method
     *
     * @param serviceTestRule the {@link ServiceTestRule} used to execute the service start request
     * @param profileServiceClass a class from one of {@link ProfileService}'s child classes
     * @throws TimeoutException when service failed to start within either default timeout of
     * {@link ServiceTestRule#DEFAULT_TIMEOUT} (normally 5s) or user specified time when creating
     * {@link ServiceTestRule} through {@link ServiceTestRule#withTimeout(long, TimeUnit)} method
     */
    public static <T extends ProfileService> void startService(ServiceTestRule serviceTestRule,
            Class<T> profileServiceClass) throws TimeoutException {
        AdapterService adapterService = AdapterService.getAdapterService();
        Assert.assertNotNull(adapterService);
        Assert.assertTrue("AdapterService.getAdapterService() must return a mocked or spied object"
                + " before calling this method", MockUtil.isMock(adapterService));
        Intent startIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), profileServiceClass);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON);
        serviceTestRule.startService(startIntent);
        verify(adapterService, timeout(SERVICE_TOGGLE_TIMEOUT_MS)).onProfileServiceStateChanged(
                eq(profileServiceClass.getName()), eq(BluetoothAdapter.STATE_ON));
    }

    /**
     * Stop a profile service using the given {@link ServiceTestRule} and verify through
     * {@link AdapterService#getAdapterService()} that the service is actually stopped within
     * {@link TestUtils#SERVICE_TOGGLE_TIMEOUT_MS} milliseconds.
     * {@link #setAdapterService(AdapterService)} must be called with a mocked
     * {@link AdapterService} before calling this method
     *
     * @param serviceTestRule the {@link ServiceTestRule} used to execute the service start request
     * @param profileServiceClass a class from one of {@link ProfileService}'s child classes
     * @throws TimeoutException when service failed to start within either default timeout of
     * {@link ServiceTestRule#DEFAULT_TIMEOUT} (normally 5s) or user specified time when creating
     * {@link ServiceTestRule} through {@link ServiceTestRule#withTimeout(long, TimeUnit)} method
     */
    public static <T extends ProfileService> void stopService(ServiceTestRule serviceTestRule,
            Class<T> profileServiceClass) throws TimeoutException {
        AdapterService adapterService = AdapterService.getAdapterService();
        Assert.assertNotNull(adapterService);
        Assert.assertTrue("AdapterService.getAdapterService() must return a mocked or spied object"
                + " before calling this method", MockUtil.isMock(adapterService));
        Intent stopIntent =
                new Intent(InstrumentationRegistry.getTargetContext(), profileServiceClass);
        stopIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        stopIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF);
        serviceTestRule.startService(stopIntent);
        verify(adapterService, timeout(SERVICE_TOGGLE_TIMEOUT_MS)).onProfileServiceStateChanged(
                eq(profileServiceClass.getName()), eq(BluetoothAdapter.STATE_OFF));
    }
}
