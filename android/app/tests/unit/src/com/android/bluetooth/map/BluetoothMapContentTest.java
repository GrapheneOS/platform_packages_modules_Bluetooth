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

package com.android.bluetooth.map;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.ContentResolver;
import android.database.Cursor;
import android.provider.ContactsContract;
import android.provider.Telephony;

import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

@RunWith(AndroidJUnit4.class)
public class BluetoothMapContentTest {
    private static final String TEST_TEXT = "text";

    @Mock
    private ContentResolver mContentResolver;
    @Spy
    private BluetoothMethodProxy mMapMethodProxy = BluetoothMethodProxy.getInstance();

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        BluetoothMethodProxy.setInstanceForTesting(mMapMethodProxy);
    }

    @After
    public void tearDown() {
        BluetoothMethodProxy.setInstanceForTesting(null);
    }

    @Test
    public void getTextPartsMms() {
        final long id = 1111;
        Cursor cursor = mock(Cursor.class);
        when(cursor.moveToFirst()).thenReturn(true);
        when(cursor.getColumnIndex("ct")).thenReturn(1);
        when(cursor.getString(1)).thenReturn("text/plain");
        when(cursor.getColumnIndex("text")).thenReturn(2);
        when(cursor.getString(2)).thenReturn(TEST_TEXT);
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThat(BluetoothMapContent.getTextPartsMms(mContentResolver, id)).isEqualTo(TEST_TEXT);
    }

    @Test
    public void getContactNameFromPhone() {
        String phoneName = "testPhone";
        Cursor cursor = mock(Cursor.class);
        when(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)).thenReturn(1);
        when(cursor.getCount()).thenReturn(1);
        when(cursor.getString(1)).thenReturn(TEST_TEXT);
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThat(
                BluetoothMapContent.getContactNameFromPhone(phoneName, mContentResolver)).isEqualTo(
                TEST_TEXT);
    }

    @Test
    public void getCanonicalAddressSms() {
        int threadId = 0;
        Cursor cursor = mock(Cursor.class);
        when(cursor.moveToFirst()).thenReturn(true);
        when(cursor.getString(0)).thenReturn("recipientIdOne recipientIdTwo");
        when(cursor.getColumnIndex(Telephony.CanonicalAddressesColumns.ADDRESS)).thenReturn(1);
        when(cursor.getString(1)).thenReturn("recipientAddress");
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThat(
                BluetoothMapContent.getCanonicalAddressSms(mContentResolver, threadId)).isEqualTo(
                "recipientAddress");
    }

    @Test
    public void getAddressMms() {
        long id = 1111;
        int type = 0;
        Cursor cursor = mock(Cursor.class);
        when(cursor.moveToFirst()).thenReturn(true);
        when(cursor.getColumnIndex(Telephony.Mms.Addr.ADDRESS)).thenReturn(1);
        when(cursor.getString(1)).thenReturn(TEST_TEXT);
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThat(BluetoothMapContent.getAddressMms(mContentResolver, id, type)).isEqualTo(
                TEST_TEXT);
    }
}