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

package com.android.bluetooth.pbap;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.os.Handler;
import android.os.UserManager;
import android.util.Log;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.obex.HeaderSet;
import com.android.obex.Operation;
import com.android.obex.ResponseCodes;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import com.android.bluetooth.pbap.BluetoothPbapObexServer.AppParamValue;

import java.io.IOException;
import java.io.OutputStream;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class BluetoothPbapObexServerTest {

    private static final String TAG = BluetoothPbapObexServerTest.class.getSimpleName();

    @Mock Handler mMockHandler;
    @Mock PbapStateMachine mMockStateMachine;

    @Spy
    BluetoothPbapMethodProxy mPbapMethodProxy = BluetoothPbapMethodProxy.getInstance();

    BluetoothPbapObexServer mServer;

    private static final byte[] WRONG_UUID = new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
    };

    private static final byte[] WRONG_LENGTH_UUID = new byte[] {
            0x79,
            0x61,
            0x35,
    };

    private static final String ILLEGAL_PATH = "some/random/path";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        BluetoothPbapMethodProxy.setInstanceForTesting(mPbapMethodProxy);
        mServer = new BluetoothPbapObexServer(
                mMockHandler, InstrumentationRegistry.getTargetContext(), mMockStateMachine);
    }

    @After
    public void tearDown() throws Exception {
        BluetoothPbapMethodProxy.setInstanceForTesting(null);
    }

    @Test
    public void testOnConnect_whenIoExceptionIsThrownFromGettingTargetHeader()
            throws Exception {
        HeaderSet request = new HeaderSet();
        HeaderSet reply = new HeaderSet();

        doThrow(IOException.class).when(mPbapMethodProxy).getHeader(request, HeaderSet.TARGET);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenUuidIsNull() {
        // Create an empty header set.
        HeaderSet request = new HeaderSet();
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnConnect_whenUuidLengthIsWrong() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, WRONG_LENGTH_UUID);
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnConnect_whenUuidIsWrong() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, WRONG_UUID);
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnConnect_whenIoExceptionIsThrownFromGettingWhoHeader()
            throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, BluetoothPbapObexServer.PBAP_TARGET);
        HeaderSet reply = new HeaderSet();

        doThrow(IOException.class).when(mPbapMethodProxy).getHeader(request, HeaderSet.WHO);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenIoExceptionIsThrownFromGettingApplicationParameterHeader()
            throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, BluetoothPbapObexServer.PBAP_TARGET);
        HeaderSet reply = new HeaderSet();

        doThrow(IOException.class).when(mPbapMethodProxy)
                .getHeader(request, HeaderSet.APPLICATION_PARAMETER);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenApplicationParameterIsWrong() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, BluetoothPbapObexServer.PBAP_TARGET);
        HeaderSet reply = new HeaderSet();

        byte[] badApplicationParameter = new byte[] {0x00, 0x01, 0x02};
        request.setHeader(HeaderSet.APPLICATION_PARAMETER, badApplicationParameter);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_BAD_REQUEST);
    }

    @Test
    public void testOnConnect_success() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, BluetoothPbapObexServer.PBAP_TARGET);
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onConnect(request, reply)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnDisconnect() throws Exception {
        HeaderSet request = new HeaderSet();
        HeaderSet response = new HeaderSet();

        mServer.onDisconnect(request, response);

        assertThat(response.getResponseCode()).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnAbort() throws Exception {
        HeaderSet request = new HeaderSet();
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onAbort(request, reply)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
        assertThat(mServer.sIsAborted).isTrue();
    }

    @Test
    public void testOnPut_notSupported() {
        Operation operation = mock(Operation.class);
        assertThat(mServer.onPut(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_BAD_REQUEST);
    }

    @Test
    public void testOnDelete_notSupported() {
        HeaderSet request = new HeaderSet();
        HeaderSet reply = new HeaderSet();

        assertThat(mServer.onDelete(request, reply)).isEqualTo(ResponseCodes.OBEX_HTTP_BAD_REQUEST);
    }

    @Test
    public void testOnClose() {
        mServer.onClose();
        verify(mMockStateMachine).sendMessage(PbapStateMachine.DISCONNECT);
    }

    @Test
    public void testCloseStream_success() throws Exception{
        OutputStream outputStream = mock(OutputStream.class);
        Operation operation = mock(Operation.class);

        assertThat(BluetoothPbapObexServer.closeStream(outputStream, operation)).isTrue();
        verify(outputStream).close();
        verify(operation).close();
    }

    @Test
    public void testCloseStream_failOnClosingOutputStream() throws Exception {
        OutputStream outputStream = mock(OutputStream.class);
        doThrow(IOException.class).when(outputStream).close();
        Operation operation = mock(Operation.class);

        assertThat(BluetoothPbapObexServer.closeStream(outputStream, operation)).isFalse();
    }

    @Test
    public void testCloseStream_failOnClosingOperation() throws Exception {
        OutputStream outputStream = mock(OutputStream.class);
        Operation operation = mock(Operation.class);
        doThrow(IOException.class).when(operation).close();

        assertThat(BluetoothPbapObexServer.closeStream(outputStream, operation)).isFalse();
    }

    @Test
    public void testOnAuthenticationFailure() {
        byte[] userName = {0x57, 0x68, 0x79};
        try {
            mServer.onAuthenticationFailure(userName);
        } catch (Exception ex) {
            assertWithMessage("Exception should not happen.").fail();
        }
    }

    @Test
    public void testLogHeader() throws Exception{
        HeaderSet headerSet = new HeaderSet();
        try {
            BluetoothPbapObexServer.logHeader(headerSet);
        } catch (Exception ex) {
            assertWithMessage("Exception should not happen.").fail();
        }
    }

    @Test
    public void testOnSetPath_whenIoExceptionIsThrownFromGettingNameHeader()
            throws Exception {
        HeaderSet request = new HeaderSet();
        HeaderSet reply = new HeaderSet();
        boolean backup = true;
        boolean create = true;

        doThrow(IOException.class).when(mPbapMethodProxy)
                .getHeader(request, HeaderSet.NAME);

        assertThat(mServer.onSetPath(request, reply, backup, create))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnSetPath_whenPathCreateIsForbidden() throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.NAME, ILLEGAL_PATH);
        HeaderSet reply = new HeaderSet();
        boolean backup = false;
        boolean create = true;

        assertThat(mServer.onSetPath(request, reply, backup, create))
                .isEqualTo(ResponseCodes.OBEX_HTTP_FORBIDDEN);
    }

    @Test
    public void testOnSetPath_whenPathIsIllegal() throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.NAME, ILLEGAL_PATH);
        HeaderSet reply = new HeaderSet();
        boolean backup = false;
        boolean create = false;

        assertThat(mServer.onSetPath(request, reply, backup, create))
                .isEqualTo(ResponseCodes.OBEX_HTTP_NOT_FOUND);
    }

    @Test
    public void testOnSetPath_success() throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.TELECOM_PATH);
        HeaderSet reply = new HeaderSet();
        boolean backup = false;
        boolean create = true;

        assertThat(mServer.onSetPath(request, reply, backup, create))
                .isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        backup = true;
        assertThat(mServer.onSetPath(request, reply, backup, create))
                .isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnGet_whenIoExceptionIsThrownFromGettingApplicationParameterHeader()
            throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet headerSet = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(headerSet);

        doThrow(IOException.class).when(mPbapMethodProxy)
                .getHeader(headerSet, HeaderSet.APPLICATION_PARAMETER);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnGet_whenTypeIsNull() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet headerSet = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(headerSet);

        headerSet.setHeader(HeaderSet.TYPE, null);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnGet_whenUserIsNotUnlocked() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet headerSet = new HeaderSet();
        headerSet.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_VCARD);
        when(operation.getReceivedHeader()).thenReturn(headerSet);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));

        when(userManager.isUserUnlocked()).thenReturn(false);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_UNAVAILABLE);
    }

    @Test
    public void testOnGet_whenNameIsNotSet_andCurrentPathIsTelecom_andTypeIsListing()
            throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        mServer.setCurrentPath(BluetoothPbapObexServer.TELECOM_PATH);
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_FOUND);
    }

    @Test
    public void testOnGet_whenNameIsNotSet_andCurrentPathIsInvalid() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        mServer.setCurrentPath(ILLEGAL_PATH);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnGet_whenAppParamIsInvalid() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        mServer.setCurrentPath(BluetoothPbapObexServer.PB_PATH);
        byte[] badApplicationParameter = new byte[] {0x00, 0x01, 0x02};
        request.setHeader(HeaderSet.APPLICATION_PARAMETER, badApplicationParameter);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_BAD_REQUEST);
    }

    @Test
    public void testOnGet_whenTypeIsInvalid() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        mServer.setCurrentPath(BluetoothPbapObexServer.PB_PATH);
        request.setHeader(HeaderSet.TYPE, "someType");

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnGet_whenNameIsNotSet_andTypeIsListing_success() throws Exception {
        Operation operation = mock(Operation.class);
        OutputStream outputStream = mock(OutputStream.class);
        when(operation.openOutputStream()).thenReturn(outputStream);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);
        mServer.setConnAppParamValue(new AppParamValue());
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);

        mServer.setCurrentPath(BluetoothPbapObexServer.ICH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.OCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.MCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.CCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.PB_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.FAV_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnGet_whenNameIsNotSet_andTypeIsPb_success() throws Exception {
        Operation operation = mock(Operation.class);
        OutputStream outputStream = mock(OutputStream.class);
        when(operation.openOutputStream()).thenReturn(outputStream);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);
        mServer.setConnAppParamValue(new AppParamValue());
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_PB);

        mServer.setCurrentPath(BluetoothPbapObexServer.TELECOM_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.ICH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.OCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.MCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.CCH_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.PB_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        mServer.setCurrentPath(BluetoothPbapObexServer.FAV_PATH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnGet_whenSimPhoneBook() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.PB);
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);
        mServer.setCurrentPath(BluetoothPbapSimVcardManager.SIM_PATH);

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_ACCEPTABLE);
    }

    @Test
    public void testOnGet_whenNameDoesNotMatch() throws Exception {
        Operation operation = mock(Operation.class);
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);

        request.setHeader(HeaderSet.NAME, "someName");

        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_NOT_FOUND);
    }

    @Test
    public void testOnGet_whenNameIsSet_andTypeIsListing_success() throws Exception {
        Operation operation = mock(Operation.class);
        OutputStream outputStream = mock(OutputStream.class);
        when(operation.openOutputStream()).thenReturn(outputStream);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);
        mServer.setConnAppParamValue(new AppParamValue());
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_LISTING);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.ICH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.OCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.MCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.CCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.PB);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.FAV);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testOnGet_whenNameIsSet_andTypeIsPb_success() throws Exception {
        Operation operation = mock(Operation.class);
        OutputStream outputStream = mock(OutputStream.class);
        when(operation.openOutputStream()).thenReturn(outputStream);
        HeaderSet request = new HeaderSet();
        when(operation.getReceivedHeader()).thenReturn(request);
        UserManager userManager = mock(UserManager.class);
        doReturn(userManager).when(mPbapMethodProxy).getSystemService(any(), eq(UserManager.class));
        when(userManager.isUserUnlocked()).thenReturn(true);
        mServer.setConnAppParamValue(new AppParamValue());
        request.setHeader(HeaderSet.TYPE, BluetoothPbapObexServer.TYPE_PB);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.ICH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.OCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.MCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.CCH);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.PB);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);

        request.setHeader(HeaderSet.NAME, BluetoothPbapObexServer.FAV);
        assertThat(mServer.onGet(operation)).isEqualTo(ResponseCodes.OBEX_HTTP_OK);
    }

}
