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

package com.android.bluetooth.hfp;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.Context;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(AndroidJUnit4.class)
public class AtPhonebookTest {
    private static final String INVALID_COMMAND = "invalid_command";
    private Context mTargetContext;
    private BluetoothAdapter mAdapter;
    private BluetoothDevice mTestDevice;

    @Mock
    private AdapterService mAdapterService;
    private HeadsetNativeInterface mNativeInterface;
    private AtPhonebook mAtPhonebook;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);

        mAdapter = BluetoothAdapter.getDefaultAdapter();
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");
        // Spy on native interface
        mNativeInterface = spy(HeadsetNativeInterface.getInstance());
        mAtPhonebook = new AtPhonebook(mTargetContext, mNativeInterface);
    }

    @After
    public void tearDown() throws Exception {
        TestUtils.clearAdapterService(mAdapterService);
    }

    @Test
    public void checkAccessPermission_returnsCorrectPermission() {
        assertThat(mAtPhonebook.checkAccessPermission(mTestDevice)).isEqualTo(
                BluetoothDevice.ACCESS_UNKNOWN);
    }

    @Test
    public void getAndSetCheckingAccessPermission_setCorrectly() {
        mAtPhonebook.setCheckingAccessPermission(true);
        assertThat(mAtPhonebook.getCheckingAccessPermission()).isTrue();
    }

    @Test
    public void handleCscsCommand() {
        mAtPhonebook.handleCscsCommand(INVALID_COMMAND, AtPhonebook.TYPE_READ, mTestDevice);
        verify(mNativeInterface).atResponseString(mTestDevice,
                "+CSCS: \"" + "UTF-8" + "\"");

        mAtPhonebook.handleCscsCommand(INVALID_COMMAND, AtPhonebook.TYPE_TEST, mTestDevice);
        verify(mNativeInterface).atResponseString(mTestDevice,
                "+CSCS: (\"UTF-8\",\"IRA\",\"GSM\")");

        mAtPhonebook.handleCscsCommand(INVALID_COMMAND, AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface, atLeastOnce()).atResponseCode(mTestDevice,
                HeadsetHalConstants.AT_RESPONSE_ERROR, -1);

        mAtPhonebook.handleCscsCommand("command=GSM", AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface, atLeastOnce()).atResponseCode(mTestDevice,
                HeadsetHalConstants.AT_RESPONSE_OK, -1);

        mAtPhonebook.handleCscsCommand("command=ERR", AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.OPERATION_NOT_SUPPORTED);

        mAtPhonebook.handleCscsCommand(INVALID_COMMAND, AtPhonebook.TYPE_UNKNOWN, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.TEXT_HAS_INVALID_CHARS);
    }

    @Test
    public void handleCpbsCommand() {
        mAtPhonebook.handleCpbsCommand(INVALID_COMMAND, AtPhonebook.TYPE_READ, mTestDevice);
        verify(mNativeInterface).atResponseString(mTestDevice,
                "+CPBS: \"" + "ME" + "\"," + 0 + "," + 256);

        mAtPhonebook.handleCpbsCommand(INVALID_COMMAND, AtPhonebook.TYPE_TEST, mTestDevice);
        verify(mNativeInterface).atResponseString(mTestDevice,
                "+CPBS: (\"ME\",\"SM\",\"DC\",\"RC\",\"MC\")");

        mAtPhonebook.handleCpbsCommand(INVALID_COMMAND, AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.OPERATION_NOT_SUPPORTED);

        mAtPhonebook.handleCpbsCommand("command=ERR", AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.OPERATION_NOT_ALLOWED);

        mAtPhonebook.handleCpbsCommand("command=SM", AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface, atLeastOnce()).atResponseCode(mTestDevice,
                HeadsetHalConstants.AT_RESPONSE_OK, -1);

        mAtPhonebook.handleCpbsCommand(INVALID_COMMAND, AtPhonebook.TYPE_UNKNOWN, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.TEXT_HAS_INVALID_CHARS);
    }

    @Test
    public void handleCpbrCommand() {
        mAtPhonebook.handleCpbrCommand(INVALID_COMMAND, AtPhonebook.TYPE_TEST, mTestDevice);
        verify(mNativeInterface).atResponseString(mTestDevice, "+CPBR: (1-" + 1 + "),30,30");
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_OK,
                -1);

        mAtPhonebook.handleCpbrCommand(INVALID_COMMAND, AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                -1);

        mAtPhonebook.handleCpbrCommand("command=ERR", AtPhonebook.TYPE_SET, mTestDevice);
        verify(mNativeInterface).atResponseCode(mTestDevice, HeadsetHalConstants.AT_RESPONSE_ERROR,
                BluetoothCmeError.TEXT_HAS_INVALID_CHARS);

        mAtPhonebook.handleCpbrCommand("command=123,123", AtPhonebook.TYPE_SET, mTestDevice);
        assertThat(mAtPhonebook.getCheckingAccessPermission()).isTrue();

        mAtPhonebook.handleCpbrCommand(INVALID_COMMAND, AtPhonebook.TYPE_UNKNOWN, mTestDevice);
        verify(mNativeInterface, atLeastOnce()).atResponseCode(mTestDevice,
                HeadsetHalConstants.AT_RESPONSE_ERROR, BluetoothCmeError.TEXT_HAS_INVALID_CHARS);
    }

    @Test
    public void processCpbrCommand() {
        mAtPhonebook.handleCpbsCommand("command=SM", AtPhonebook.TYPE_SET, mTestDevice);
        assertThat(mAtPhonebook.processCpbrCommand(mTestDevice)).isEqualTo(
                HeadsetHalConstants.AT_RESPONSE_OK);

        mAtPhonebook.handleCpbsCommand("command=ME", AtPhonebook.TYPE_SET, mTestDevice);
        assertThat(mAtPhonebook.processCpbrCommand(mTestDevice)).isEqualTo(
                HeadsetHalConstants.AT_RESPONSE_OK);
    }

    @Test
    public void resetAtState() {
        mAtPhonebook.resetAtState();
        assertThat(mAtPhonebook.getCheckingAccessPermission()).isFalse();
    }
}