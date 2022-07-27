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
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import android.os.Handler;

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

import java.io.IOException;
import java.io.OutputStream;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class BluetoothPbapObexServerTest {

    @Mock Handler mMockHandler;
    @Mock PbapStateMachine mMockStateMachine;

    @Spy
    BluetoothPbapMethodProxy mPbapMethodProxy = BluetoothPbapMethodProxy.getInstance();

    BluetoothPbapObexServer mServer;

    // 128 bit UUID for PBAP
    private static final byte[] PBAP_TARGET_UUID = new byte[] {
            0x79,
            0x61,
            0x35,
            (byte) 0xf0,
            (byte) 0xf0,
            (byte) 0xc5,
            0x11,
            (byte) 0xd8,
            0x09,
            0x66,
            0x08,
            0x00,
            0x20,
            0x0c,
            (byte) 0x9a,
            0x66
    };

    private static final byte[] WRONG_UUID = new byte[] {
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
    };

    private static final byte[] WRONG_LENGTH_UUID = new byte[] {
            0x79,
            0x61,
            0x35,
    };

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
    public void testOnConnect_whenIoExceptionIsThrownFromSettingWhoHeader() throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, PBAP_TARGET_UUID);

        HeaderSet reply = new HeaderSet();
        doThrow(IOException.class).when(mPbapMethodProxy)
                .setHeader(eq(reply), eq(HeaderSet.WHO), any());

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenIoExceptionIsThrownFromSettingTargetHeader() throws Exception {
        HeaderSet request = new HeaderSet();
        byte[] whoHeader = new byte[] {0x00, 0x01, 0x02};
        request.setHeader(HeaderSet.WHO, whoHeader);
        request.setHeader(HeaderSet.TARGET, PBAP_TARGET_UUID);

        HeaderSet reply = new HeaderSet();
        doThrow(IOException.class).when(mPbapMethodProxy)
                .setHeader(eq(reply), eq(HeaderSet.TARGET), any());

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenIoExceptionIsThrownFromGettingApplicationParameterHeader()
            throws Exception {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, PBAP_TARGET_UUID);
        HeaderSet reply = new HeaderSet();

        doThrow(IOException.class).when(mPbapMethodProxy)
                .getHeader(request, HeaderSet.APPLICATION_PARAMETER);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_INTERNAL_ERROR);
    }

    @Test
    public void testOnConnect_whenApplicationParameterIsWrong() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, PBAP_TARGET_UUID);
        HeaderSet reply = new HeaderSet();

        byte[] badApplicationParameter = new byte[] {0x00, 0x01, 0x02};
        request.setHeader(HeaderSet.APPLICATION_PARAMETER, badApplicationParameter);

        assertThat(mServer.onConnect(request, reply))
                .isEqualTo(ResponseCodes.OBEX_HTTP_BAD_REQUEST);
    }

    @Test
    public void testOnConnect_success() {
        HeaderSet request = new HeaderSet();
        request.setHeader(HeaderSet.TARGET, PBAP_TARGET_UUID);
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
}
