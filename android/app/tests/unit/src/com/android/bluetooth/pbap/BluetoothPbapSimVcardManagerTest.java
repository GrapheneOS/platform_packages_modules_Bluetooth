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

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
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
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.android.bluetooth.pbap.BluetoothPbapObexServer.AppParamValue;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class BluetoothPbapSimVcardManagerTest {

    private static final String TAG = BluetoothPbapSimVcardManagerTest.class.getSimpleName();

    @Spy
    BluetoothPbapMethodProxy mPbapMethodProxy = BluetoothPbapMethodProxy.getInstance();

    Context mContext;
    BluetoothPbapSimVcardManager mManager;

    private static final Uri WRONG_URI = Uri.parse("content://some/wrong/uri");

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        BluetoothPbapMethodProxy.setInstanceForTesting(mPbapMethodProxy);
        mContext =  InstrumentationRegistry.getTargetContext();
        mManager = new BluetoothPbapSimVcardManager(mContext);
    }

    @After
    public void tearDown() throws Exception {
        BluetoothPbapMethodProxy.setInstanceForTesting(null);
    }

    @Test
    public void testInit_whenUriIsUnsupported() throws Exception {
        assertThat(mManager.init(WRONG_URI, null, null, null))
                .isFalse();
        assertThat(mManager.getErrorReason())
                .isEqualTo(BluetoothPbapSimVcardManager.FAILURE_REASON_UNSUPPORTED_URI);
    }

    @Test
    public void testInit_whenCursorIsNull() throws Exception {
        doReturn(null).when(mPbapMethodProxy)
                .contentResolverQuery(any(), any(), any(), any(), any(), any());

        assertThat(mManager.init(BluetoothPbapSimVcardManager.SIM_URI, null, null, null))
                .isFalse();
        assertThat(mManager.getErrorReason())
                .isEqualTo(BluetoothPbapSimVcardManager.FAILURE_REASON_FAILED_TO_GET_DATABASE_INFO);
    }

    @Test
    public void testInit_whenCursorHasNoEntry() throws Exception {
        Cursor cursor = mock(Cursor.class);
        when(cursor.getCount()).thenReturn(0);
        doReturn(cursor).when(mPbapMethodProxy)
                .contentResolverQuery(any(), any(), any(), any(), any(), any());

        assertThat(mManager.init(BluetoothPbapSimVcardManager.SIM_URI, null, null, null))
                .isFalse();
        verify(cursor).close();
        assertThat(mManager.getErrorReason())
                .isEqualTo(BluetoothPbapSimVcardManager.FAILURE_REASON_NO_ENTRY);
    }

    @Test
    public void testInit_success() throws Exception {
        Cursor cursor = mock(Cursor.class);
        when(cursor.getCount()).thenReturn(1);
        when(cursor.moveToFirst()).thenReturn(true);
        doReturn(cursor).when(mPbapMethodProxy)
                .contentResolverQuery(any(), any(), any(), any(), any(), any());

        assertThat(mManager.init(BluetoothPbapSimVcardManager.SIM_URI, null, null, null))
                .isTrue();
        assertThat(mManager.getErrorReason()).isEqualTo(BluetoothPbapSimVcardManager.NO_ERROR);
    }

    @Test
    public void testCreateOneEntry_whenNotInitialized() throws Exception {
        assertThat(mManager.createOneEntry(true)).isNull();
        assertThat(mManager.getErrorReason())
                .isEqualTo(BluetoothPbapSimVcardManager.FAILURE_REASON_NOT_INITIALIZED);
    }

    @Test
    public void testCreateOneEntry_success() throws Exception {
        Cursor cursor = initManager();

        assertThat(mManager.createOneEntry(true)).isNotNull();
        assertThat(mManager.createOneEntry(false)).isNotNull();
        verify(cursor, times(2)).moveToNext();
    }

    @Test
    public void testTerminate() throws Exception {
        Cursor cursor = initManager();
        mManager.terminate();

        verify(cursor).close();
    }

    @Test
    public void testGetCount_beforeInit() {
        assertThat(mManager.getCount()).isEqualTo(0);
    }

    @Test
    public void testGetCount_success() {
        final int count = 5;
        Cursor cursor = initManager();
        when(cursor.getCount()).thenReturn(count);

        assertThat(mManager.getCount()).isEqualTo(count);
    }

    @Test
    public void testIsAfterLast_beforeInit() {
        assertThat(mManager.isAfterLast()).isFalse();
    }

    @Test
    public void testIsAfterLast_success() {
        final boolean isAfterLast = true;
        Cursor cursor = initManager();
        when(cursor.isAfterLast()).thenReturn(isAfterLast);

        assertThat(mManager.isAfterLast()).isEqualTo(isAfterLast);
    }

    @Test
    public void testMoveToPosition_beforeInit() {
        try {
            mManager.moveToPosition(0, /*sortByAlphabet=*/ true);
            mManager.moveToPosition(0, /*sortByAlphabet=*/ false);
        } catch (Exception e) {
            assertWithMessage("This should not throw exception").fail();
        }
    }

    @Test
    public void testMoveToPosition_byAlphabeticalOrder_success() {
        Cursor cursor = initManager();
        List<String> nameList = Arrays.asList("D", "C", "A", "B");

        // Implement Cursor iteration
        final int size = nameList.size();
        AtomicInteger currentPosition = new AtomicInteger(0);
        when(cursor.moveToFirst()).then((Answer<Boolean>) i -> {
            currentPosition.set(0);
            return true;
        });
        when(cursor.isAfterLast()).then((Answer<Boolean>) i -> {
            return currentPosition.get() >= size;
        });
        when(cursor.moveToNext()).then((Answer<Boolean>) i -> {
            currentPosition.getAndAdd(1);
            return true;
        });
        when(cursor.getString(anyInt())).then((Answer<String>) i -> {
            return nameList.get(currentPosition.get());
        });
        // Find first one in alphabetical order ("A")
        int position = 0;
        mManager.moveToPosition(position, /*sortByAlphabet=*/ true);

        assertThat(currentPosition.get()).isEqualTo(2);
    }

    @Test
    public void testMoveToPosition_notByAlphabeticalOrder_success() {
        Cursor cursor = initManager();
        int position = 3;

        mManager.moveToPosition(position, /*sortByAlphabet=*/ false);

        verify(cursor).moveToPosition(position);
    }

    @Test
    public void testGetSIMContactsSize() {
        final int count = 10;
        Cursor cursor = initManager();
        when(cursor.getCount()).thenReturn(count);

        assertThat(mManager.getSIMContactsSize()).isEqualTo(count);
        verify(cursor).close();
    }

    private Cursor initManager() {
        Cursor cursor = mock(Cursor.class);
        when(cursor.getCount()).thenReturn(10);
        when(cursor.moveToFirst()).thenReturn(true);
        when(cursor.isAfterLast()).thenReturn(false);
        doReturn(cursor).when(mPbapMethodProxy)
                .contentResolverQuery(any(), any(), any(), any(), any(), any());
        mManager.init(BluetoothPbapSimVcardManager.SIM_URI, null, null, null);

        return cursor;
    }
}
