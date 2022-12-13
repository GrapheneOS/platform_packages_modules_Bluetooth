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
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.provider.ContactsContract;
import android.provider.Telephony;
import android.provider.Telephony.Threads;
import android.telephony.TelephonyManager;

import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.SignedLongLong;
import com.android.bluetooth.map.BluetoothMapContent.FilterInfo;

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
    private BluetoothMapAccountItem mAccountItem;
    @Mock
    private BluetoothMapMasInstance mMasInstance;
    @Mock
    private Context mContext;
    @Mock
    private TelephonyManager mTelephonyManager;
    @Mock
    private ContentResolver mContentResolver;
    @Mock
    private BluetoothMapAppParams mParams;
    @Spy
    private BluetoothMethodProxy mMapMethodProxy = BluetoothMethodProxy.getInstance();

    private BluetoothMapContent mContent;
    private FilterInfo mInfo;
    private BluetoothMapMessageListingElement mElement;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        BluetoothMethodProxy.setInstanceForTesting(mMapMethodProxy);

        mContent = new BluetoothMapContent(mContext, mAccountItem, mMasInstance);
        mInfo = new FilterInfo();
        mElement = new BluetoothMapMessageListingElement();
    }

    @After
    public void tearDown() {
        BluetoothMethodProxy.setInstanceForTesting(null);
    }

    @Test
    public void constructor_withNonNullAccountItem() {
        BluetoothMapContent content = new BluetoothMapContent(mContext, mAccountItem,
                mMasInstance);

        assertThat(content.mBaseUri).isNotNull();
    }

    @Test
    public void constructor_withNullAccountItem() {
        BluetoothMapContent content = new BluetoothMapContent(mContext, null, mMasInstance);

        assertThat(content.mBaseUri).isNull();
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

    @Test
    public void setAttachment_withTypeMms() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_ATTACHMENT_SIZE);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColTextOnly = 0;
        mInfo.mMmsColAttachmentSize = 1;
        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MmsColTextOnly", "MmsColAttachmentSize"});
        cursor.addRow(new Object[]{0, -1});
        cursor.moveToFirst();

        mContent.setAttachment(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getAttachmentSize()).isEqualTo(1);
    }

    @Test
    public void setAttachment_withTypeEmail() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_ATTACHMENT_SIZE);
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mMessageColAttachment = 0;
        mInfo.mMessageColAttachmentSize = 1;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MessageColAttachment",
                "MessageColAttachmentSize"});
        cursor.addRow(new Object[]{1, 0});
        cursor.moveToFirst();

        mContent.setAttachment(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getAttachmentSize()).isEqualTo(1);
    }

    @Test
    public void setAttachment_withTypeIm() {
        int featureMask = 1 << 9;
        long parameterMask = 0x00100400;
        when(mParams.getParameterMask()).thenReturn(parameterMask);
        mInfo.mMsgType = FilterInfo.TYPE_IM;
        mInfo.mMessageColAttachment = 0;
        mInfo.mMessageColAttachmentSize = 1;
        mInfo.mMessageColAttachmentMime = 2;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MessageColAttachment",
                "MessageColAttachmentSize",
                "MessageColAttachmentMime"});
        cursor.addRow(new Object[]{1, 0, "test_mime_type"});
        cursor.moveToFirst();

        mContent.setRemoteFeatureMask(featureMask);
        mContent.setAttachment(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getAttachmentSize()).isEqualTo(1);
        assertThat(mElement.getAttachmentMimeTypes()).isEqualTo("test_mime_type");
    }

    @Test
    public void setRemoteFeatureMask() {
        int featureMask = 1 << 9;

        mContent.setRemoteFeatureMask(featureMask);

        assertThat(mContent.getRemoteFeatureMask()).isEqualTo(featureMask);
        assertThat(mContent.mMsgListingVersion).isEqualTo(
                BluetoothMapUtils.MAP_MESSAGE_LISTING_FORMAT_V11);
    }

    @Test
    public void setConvoWhereFilterSmsMms() throws Exception {
        when(mParams.getFilterMessageType()).thenReturn(0);
        when(mParams.getFilterReadStatus()).thenReturn(0x03);
        long lastActivity = 1L;
        when(mParams.getFilterLastActivityBegin()).thenReturn(lastActivity);
        when(mParams.getFilterLastActivityEnd()).thenReturn(lastActivity);
        String convoId = "1111";
        when(mParams.getFilterConvoId()).thenReturn(SignedLongLong.fromString(convoId));
        StringBuilder selection = new StringBuilder();

        mContent.setConvoWhereFilterSmsMms(selection, mInfo, mParams);

        StringBuilder expected = new StringBuilder();
        expected.append(" AND ").append(Threads.READ).append(" = 0");
        expected.append(" AND ").append(Threads.READ).append(" = 1");
        expected.append(" AND ")
                .append(Threads.DATE)
                .append(" >= ")
                .append(lastActivity);
        expected.append(" AND ")
                .append(Threads.DATE)
                .append(" <= ")
                .append(lastActivity);
        expected.append(" AND ")
                .append(Threads._ID)
                .append(" = ")
                .append(SignedLongLong.fromString(convoId).getLeastSignificantBits());
        assertThat(selection.toString()).isEqualTo(expected.toString());
    }

    @Test
    public void setDateTime_withTypeSms() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_DATETIME);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mSmsColDate = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"SmsColDate"});
        cursor.addRow(new Object[]{2L});
        cursor.moveToFirst();

        mContent.setDateTime(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getDateTime()).isEqualTo(2L);
    }

    @Test
    public void setDateTime_withTypeMms() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_DATETIME);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColDate = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MmsColDate"});
        cursor.addRow(new Object[]{2L});
        cursor.moveToFirst();

        mContent.setDateTime(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getDateTime()).isEqualTo(2L * 1000L);
    }

    @Test
    public void setDateTime_withTypeIM() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_DATETIME);
        mInfo.mMsgType = FilterInfo.TYPE_IM;
        mInfo.mMessageColDate = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MessageColDate"});
        cursor.addRow(new Object[]{2L});
        cursor.moveToFirst();

        mContent.setDateTime(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getDateTime()).isEqualTo(2L);
    }

    @Test
    public void setDeliveryStatus() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_DELIVERY_STATUS);
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mMessageColDelivery = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MessageColDelivery"});
        cursor.addRow(new Object[]{"test_delivery_status"});
        cursor.moveToFirst();

        mContent.setDeliveryStatus(mElement, cursor, mInfo, mParams);

        assertThat(mElement.getDeliveryStatus()).isEqualTo("test_delivery_status");
    }

    @Test
    public void setFilterInfo() {
        when(mContext.getSystemService(Context.TELEPHONY_SERVICE)).thenReturn(mTelephonyManager);
        when(mContext.getSystemServiceName(TelephonyManager.class))
                .thenReturn(Context.TELEPHONY_SERVICE);
        when(mTelephonyManager.getPhoneType()).thenReturn(TelephonyManager.PHONE_TYPE_GSM);

        mContent.setFilterInfo(mInfo);

        assertThat(mInfo.mPhoneType).isEqualTo(TelephonyManager.PHONE_TYPE_GSM);
    }

    @Test
    public void smsSelected_withInvalidFilter() {
        when(mParams.getFilterMessageType()).thenReturn(
                BluetoothMapAppParams.INVALID_VALUE_PARAMETER);

        assertThat(mContent.smsSelected(mInfo, mParams)).isTrue();
    }

    @Test
    public void smsSelected_withNoFilter() {
        int noFilter = 0;
        when(mParams.getFilterMessageType()).thenReturn(noFilter);

        assertThat(mContent.smsSelected(mInfo, mParams)).isTrue();
    }

    @Test
    public void smsSelected_withSmsCdmaExcludeFilter_andPhoneTypeGsm() {
        when(mParams.getFilterMessageType()).thenReturn(BluetoothMapAppParams.FILTER_NO_SMS_CDMA);

        mInfo.mPhoneType = TelephonyManager.PHONE_TYPE_GSM;
        assertThat(mContent.smsSelected(mInfo, mParams)).isTrue();

        mInfo.mPhoneType = TelephonyManager.PHONE_TYPE_CDMA;
        assertThat(mContent.smsSelected(mInfo, mParams)).isFalse();
    }

    @Test
    public void smsSelected_witSmsGsmExcludeFilter_andPhoneTypeCdma() {
        when(mParams.getFilterMessageType()).thenReturn(BluetoothMapAppParams.FILTER_NO_SMS_GSM);

        mInfo.mPhoneType = TelephonyManager.PHONE_TYPE_CDMA;
        assertThat(mContent.smsSelected(mInfo, mParams)).isTrue();

        mInfo.mPhoneType = TelephonyManager.PHONE_TYPE_GSM;
        assertThat(mContent.smsSelected(mInfo, mParams)).isFalse();
    }

    @Test
    public void smsSelected_withGsmAndCdmaExcludeFilter() {
        int noSms =
                BluetoothMapAppParams.FILTER_NO_SMS_CDMA | BluetoothMapAppParams.FILTER_NO_SMS_GSM;
        when(mParams.getFilterMessageType()).thenReturn(noSms);

        assertThat(mContent.smsSelected(mInfo, mParams)).isFalse();
    }

    @Test
    public void mmsSelected_withInvalidFilter() {
        when(mParams.getFilterMessageType()).thenReturn(
                BluetoothMapAppParams.INVALID_VALUE_PARAMETER);

        assertThat(mContent.mmsSelected(mParams)).isTrue();
    }

    @Test
    public void mmsSelected_withNoFilter() {
        int noFilter = 0;
        when(mParams.getFilterMessageType()).thenReturn(noFilter);

        assertThat(mContent.mmsSelected(mParams)).isTrue();
    }

    @Test
    public void mmsSelected_withMmsExcludeFilter() {
        when(mParams.getFilterMessageType()).thenReturn(BluetoothMapAppParams.FILTER_NO_MMS);

        assertThat(mContent.mmsSelected(mParams)).isFalse();
    }
}