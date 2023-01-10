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

import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.ParcelFileDescriptor;
import android.provider.BaseColumns;
import android.provider.ContactsContract;
import android.provider.Telephony;
import android.provider.Telephony.Threads;
import android.telephony.PhoneNumberUtils;
import android.telephony.TelephonyManager;
import android.text.util.Rfc822Tokenizer;

import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.SignedLongLong;
import com.android.bluetooth.map.BluetoothMapContent.FilterInfo;
import com.android.bluetooth.map.BluetoothMapUtils.TYPE;
import com.android.bluetooth.mapapi.BluetoothMapContract;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.io.ByteArrayInputStream;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.HashMap;

@RunWith(AndroidJUnit4.class)
public class BluetoothMapContentTest {
    private static final String TEST_TEXT = "text";
    private static final String TEST_TO_ADDRESS = "toName (toAddress) <to@google.com>";
    private static final String TEST_CC_ADDRESS = "ccName (ccAddress) <cc@google.com>";
    private static final String TEST_BCC_ADDRESS = "bccName (bccAddress) <bcc@google.com>";
    private static final String TEST_FROM_ADDRESS = "fromName (fromAddress) <from@google.com>";
    private static final String TEST_ADDRESS = "111-1111-1111";
    private static final long TEST_DATE_SMS = 1;
    private static final long TEST_DATE_EMAIL = 2;
    private static final String TEST_NAME = "test_name";
    private static final String TEST_FORMATTED_NAME = "test_formatted_name";
    private static final String TEST_PHONE = "test_phone";
    private static final String TEST_PHONE_NAME = "test_phone_name";
    private static final long TEST_ID = 1;
    private static final long TEST_INBOX_FOLDER_ID = BluetoothMapContract.FOLDER_ID_INBOX;
    private static final long TEST_SENT_FOLDER_ID = BluetoothMapContract.FOLDER_ID_SENT;
    private static final String TEST_SUBJECT = "subject";
    private static final long TEST_DATE = 1;
    private static final String TEST_MESSAGE_ID = "test_message_id";
    private static final String TEST_FIRST_BT_UID = "1111";
    private static final String TEST_FIRST_BT_UCI_RECIPIENT = "test_first_bt_uci_recipient";
    private static final String TEST_FIRST_BT_UCI_ORIGINATOR = "test_first_bt_uci_originator";

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
    private BluetoothMapMessageListingElement mMessageListingElement;
    private BluetoothMapConvoListingElement mConvoListingElement;
    private BluetoothMapFolderElement mCurrentFolder;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        BluetoothMethodProxy.setInstanceForTesting(mMapMethodProxy);

        mContent = new BluetoothMapContent(mContext, mAccountItem, mMasInstance);
        mInfo = new FilterInfo();
        mMessageListingElement = new BluetoothMapMessageListingElement();
        mConvoListingElement = new BluetoothMapConvoListingElement();
        mCurrentFolder = new BluetoothMapFolderElement("current", null);
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

        mContent.setAttachment(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getAttachmentSize()).isEqualTo(1);
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

        mContent.setAttachment(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getAttachmentSize()).isEqualTo(1);
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
        mContent.setAttachment(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getAttachmentSize()).isEqualTo(1);
        assertThat(mMessageListingElement.getAttachmentMimeTypes()).isEqualTo("test_mime_type");
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

        mContent.setDateTime(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getDateTime()).isEqualTo(2L);
    }

    @Test
    public void setDateTime_withTypeMms() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_DATETIME);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColDate = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MmsColDate"});
        cursor.addRow(new Object[]{2L});
        cursor.moveToFirst();

        mContent.setDateTime(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getDateTime()).isEqualTo(2L * 1000L);
    }

    @Test
    public void setDateTime_withTypeIM() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_DATETIME);
        mInfo.mMsgType = FilterInfo.TYPE_IM;
        mInfo.mMessageColDate = 0;
        MatrixCursor cursor = new MatrixCursor(new String[]{"MessageColDate"});
        cursor.addRow(new Object[]{2L});
        cursor.moveToFirst();

        mContent.setDateTime(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getDateTime()).isEqualTo(2L);
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

        mContent.setDeliveryStatus(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getDeliveryStatus()).isEqualTo("test_delivery_status");
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

    @Test
    public void getRecipientNameEmail() {
        mInfo.mMessageColToAddress = 0;
        mInfo.mMessageColCcAddress = 1;
        mInfo.mMessageColBccAddress = 2;

        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MessageColToAddress", "MessageColCcAddress", "MessageColBccAddress"});
        cursor.addRow(new Object[]{TEST_TO_ADDRESS, TEST_CC_ADDRESS, TEST_BCC_ADDRESS});
        cursor.moveToFirst();

        StringBuilder expected = new StringBuilder();
        expected.append(Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getName());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_CC_ADDRESS)[0].getName());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_BCC_ADDRESS)[0].getName());
        assertThat(mContent.getRecipientNameEmail(cursor, mInfo)).isEqualTo(
                expected.toString());
    }

    @Test
    public void getRecipientAddressingEmail() {
        mInfo.mMessageColToAddress = 0;
        mInfo.mMessageColCcAddress = 1;
        mInfo.mMessageColBccAddress = 2;

        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MessageColToAddress", "MessageColCcAddress", "MessageColBccAddress"});
        cursor.addRow(new Object[]{TEST_TO_ADDRESS, TEST_CC_ADDRESS, TEST_BCC_ADDRESS});
        cursor.moveToFirst();

        StringBuilder expected = new StringBuilder();
        expected.append(Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getAddress());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_CC_ADDRESS)[0].getAddress());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_BCC_ADDRESS)[0].getAddress());
        assertThat(mContent.getRecipientAddressingEmail(cursor, mInfo)).isEqualTo(
                expected.toString());
    }

    @Test
    public void setRecipientAddressing_withFilterMsgTypeSms_andSmsMsgTypeInbox() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_RECIPIENT_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mPhoneNum = TEST_ADDRESS;
        mInfo.mSmsColType = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"SmsColType"});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_INBOX});
        cursor.moveToFirst();

        mContent.setRecipientAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getRecipientAddressing()).isEqualTo(TEST_ADDRESS);
    }

    @Test
    public void setRecipientAddressing_withFilterMsgTypeSms_andSmsMsgTypeDraft() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_RECIPIENT_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mSmsColType = 2;
        MatrixCursor cursor = new MatrixCursor(new String[] {"RecipientIds",
                Telephony.CanonicalAddressesColumns.ADDRESS, "SmsColType",
                Telephony.Sms.ADDRESS, Telephony.Sms.THREAD_ID});
        cursor.addRow(new Object[] {"recipientIdOne recipientIdTwo", "recipientAddress",
                Telephony.Sms.MESSAGE_TYPE_DRAFT, null, "0"});
        cursor.moveToFirst();

        mContent.setRecipientAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getRecipientAddressing()).isEqualTo("recipientAddress");
    }

    @Test
    public void setRecipientAddressing_withFilterMsgTypeMms() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_RECIPIENT_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        MatrixCursor cursor = new MatrixCursor(
                new String[]{BaseColumns._ID, Telephony.Mms.Addr.ADDRESS});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_INBOX, null});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setRecipientAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getRecipientAddressing()).isEqualTo("");
    }

    @Test
    public void setRecipientAddressing_withFilterMsgTypeEmail() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_RECIPIENT_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mMessageColToAddress = 0;
        mInfo.mMessageColCcAddress = 1;
        mInfo.mMessageColBccAddress = 2;
        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MessageColToAddress", "MessageColCcAddress", "MessageColBccAddress"});
        cursor.addRow(new Object[]{TEST_TO_ADDRESS, TEST_CC_ADDRESS, TEST_BCC_ADDRESS});
        cursor.moveToFirst();

        mContent.setRecipientAddressing(mMessageListingElement, cursor, mInfo, mParams);

        StringBuilder expected = new StringBuilder();
        expected.append(Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getAddress());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_CC_ADDRESS)[0].getAddress());
        expected.append("; ");
        expected.append(Rfc822Tokenizer.tokenize(TEST_BCC_ADDRESS)[0].getAddress());
        assertThat(mMessageListingElement.getRecipientAddressing()).isEqualTo(expected.toString());
    }

    @Test
    public void setSenderAddressing_withFilterMsgTypeSms_andSmsMsgTypeInbox() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_SENDER_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mSmsColType = 0;
        mInfo.mSmsColAddress = 1;
        MatrixCursor cursor = new MatrixCursor(new String[] {"SmsColType", "SmsColAddress"});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_INBOX, TEST_ADDRESS});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderAddressing()).isEqualTo(
                PhoneNumberUtils.extractNetworkPortion(TEST_ADDRESS));
    }

    @Test
    public void setSenderAddressing_withFilterMSgTypeSms_andSmsMsgTypeDraft() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_SENDER_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mPhoneNum = null;
        mInfo.mSmsColType = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"SmsColType"});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_DRAFT});
        cursor.moveToFirst();

        mContent.setSenderAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderAddressing()).isEqualTo("");
    }

    @Test
    public void setSenderAddressing_withFilterMsgTypeMms() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_SENDER_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColId = 0;
        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MmsColId", Telephony.Mms.Addr.ADDRESS});
        cursor.addRow(new Object[] {0, ""});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderAddressing()).isEqualTo("");
    }

    @Test
    public void setSenderAddressing_withFilterTypeEmail() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_SENDER_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mMessageColFromAddress = 0;
        MatrixCursor cursor = new MatrixCursor(
                new String[]{"MessageColFromAddress"});
        cursor.addRow(new Object[]{TEST_FROM_ADDRESS});
        cursor.moveToFirst();

        mContent.setSenderAddressing(mMessageListingElement, cursor, mInfo, mParams);

        StringBuilder expected = new StringBuilder();
        expected.append(Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getAddress());
        assertThat(mMessageListingElement.getSenderAddressing()).isEqualTo(expected.toString());
    }

    @Test
    public void setSenderAddressing_withFilterTypeIm() {
        when(mParams.getParameterMask()).thenReturn(
                (long) BluetoothMapContent.MASK_SENDER_ADDRESSING);
        mInfo.mMsgType = FilterInfo.TYPE_IM;
        mInfo.mMessageColFromAddress = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"MessageColFromAddress",
                BluetoothMapContract.ConvoContactColumns.UCI});
        cursor.addRow(new Object[] {(long) 1, TEST_ADDRESS});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderAddressing(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderAddressing()).isEqualTo(TEST_ADDRESS);
    }

    @Test
    public void setSenderName_withFilterTypeSms_andSmsMsgTypeInbox() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mSmsColAddress = 1;
        MatrixCursor cursor = new MatrixCursor(new String[] {Telephony.Sms.TYPE, "SmsColAddress",
                ContactsContract.Contacts.DISPLAY_NAME});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_INBOX, TEST_PHONE, TEST_PHONE_NAME});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderName()).isEqualTo(TEST_PHONE_NAME);
    }

    @Test
    public void setSenderName_withFilterTypeSms_andSmsMsgTypeDraft() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mPhoneAlphaTag = TEST_NAME;
        MatrixCursor cursor = new MatrixCursor(new String[] {Telephony.Sms.TYPE});
        cursor.addRow(new Object[] {Telephony.Sms.MESSAGE_TYPE_DRAFT});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderName()).isEqualTo(TEST_NAME);
    }

    @Test
    public void setSenderName_withFilterTypeMms_withNonNullSenderAddressing() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColId = 0;
        mMessageListingElement.setSenderAddressing(TEST_ADDRESS);
        MatrixCursor cursor = new MatrixCursor(new String[] {"MmsColId", Telephony.Mms.Addr.ADDRESS,
                ContactsContract.Contacts.DISPLAY_NAME});
        cursor.addRow(new Object[] {0, TEST_PHONE, TEST_PHONE_NAME});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderName()).isEqualTo(TEST_PHONE_NAME);
    }

    @Test
    public void setSenderName_withFilterTypeMms_withNullSenderAddressing() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_MMS;
        mInfo.mMmsColId = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"MmsColId"});
        cursor.addRow(new Object[] {0});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderName()).isEqualTo("");
    }

    @Test
    public void setSenderName_withFilterTypeEmail() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mMessageColFromAddress = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"MessageColFromAddress"});
        cursor.addRow(new Object[] {TEST_FROM_ADDRESS});
        cursor.moveToFirst();

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        StringBuilder expected = new StringBuilder();
        expected.append(Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getName());
        assertThat(mMessageListingElement.getSenderName()).isEqualTo(expected.toString());
    }

    @Test
    public void setSenderName_withFilterTypeIm() {
        when(mParams.getParameterMask()).thenReturn((long) BluetoothMapContent.MASK_SENDER_NAME);
        mInfo.mMsgType = FilterInfo.TYPE_IM;
        mInfo.mMessageColFromAddress = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"MessageColFromAddress",
                BluetoothMapContract.ConvoContactColumns.NAME});
        cursor.addRow(new Object[] {(long) 1, TEST_NAME});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mContent.setSenderName(mMessageListingElement, cursor, mInfo, mParams);

        assertThat(mMessageListingElement.getSenderName()).isEqualTo(TEST_NAME);
    }

    @Test
    public void setters_withConvoList() {
        BluetoothMapMasInstance instance = spy(BluetoothMapMasInstance.class);
        BluetoothMapContent content = new BluetoothMapContent(mContext, mAccountItem, instance);
        HashMap<Long, BluetoothMapConvoListingElement> emailMap =
                new HashMap<Long, BluetoothMapConvoListingElement>();
        HashMap<Long, BluetoothMapConvoListingElement> smsMap =
                new HashMap<Long, BluetoothMapConvoListingElement>();

        content.setImEmailConvoList(emailMap);
        content.setSmsMmsConvoList(smsMap);

        assertThat(content.getImEmailConvoList()).isEqualTo(emailMap);
        assertThat(content.getSmsMmsConvoList()).isEqualTo(smsMap);
    }

    @Test
    public void setLastActivity_withFilterTypeSms() {
        mInfo.mMsgType = FilterInfo.TYPE_SMS;
        mInfo.mConvoColLastActivity = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"ConvoColLastActivity",
                "MmsSmsThreadColDate"});
        cursor.addRow(new Object[] {TEST_DATE_EMAIL, TEST_DATE_SMS});
        cursor.moveToFirst();

        mContent.setLastActivity(mConvoListingElement, cursor, mInfo);

        assertThat(mConvoListingElement.getLastActivity()).isEqualTo(TEST_DATE_SMS);
    }

    @Test
    public void setLastActivity_withFilterTypeEmail() {
        mInfo.mMsgType = FilterInfo.TYPE_EMAIL;
        mInfo.mConvoColLastActivity = 0;
        MatrixCursor cursor = new MatrixCursor(new String[] {"ConvoColLastActivity",
                "MmsSmsThreadColDate"});
        cursor.addRow(new Object[] {TEST_DATE_EMAIL, TEST_DATE_SMS});
        cursor.moveToFirst();

        mContent.setLastActivity(mConvoListingElement, cursor, mInfo);

        assertThat(mConvoListingElement.getLastActivity()).isEqualTo(TEST_DATE_EMAIL);
    }

    @Test
    public void getEmailMessage_withCharsetNative() {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_NATIVE);

        assertThrows(IllegalArgumentException.class, () -> mContent.getEmailMessage(TEST_ID,
                mParams, mCurrentFolder));
    }

    @Test
    public void getEmailMessage_withEmptyCursor() {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        MatrixCursor cursor = new MatrixCursor(new String[] {});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThrows(IllegalArgumentException.class, () -> mContent.getEmailMessage(TEST_ID,
                mParams, mCurrentFolder));
    }

    @Test
    public void getEmailMessage_withFileNotFoundExceptionForEmailBodyAccess() throws Exception {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        when(mParams.getFractionRequest()).thenReturn(BluetoothMapAppParams.FRACTION_REQUEST_FIRST);
        when(mParams.getAttachment()).thenReturn(0);

        MatrixCursor cursor = new MatrixCursor(new String[] {
                BluetoothMapContract.MessageColumns.RECEPTION_STATE,
                BluetoothMapContract.MessageColumns.FLAG_READ,
                BluetoothMapContract.MessageColumns.FOLDER_ID,
                BluetoothMapContract.MessageColumns.TO_LIST,
                BluetoothMapContract.MessageColumns.FROM_LIST
        });
        cursor.addRow(new Object[] {BluetoothMapContract.RECEPTION_STATE_FRACTIONED, "1",
        TEST_INBOX_FOLDER_ID, TEST_TO_ADDRESS, TEST_FROM_ADDRESS});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mCurrentFolder.setFolderId(TEST_INBOX_FOLDER_ID);
        // This mock sets up FileNotFoundException during email body access
        doThrow(FileNotFoundException.class).when(
                mMapMethodProxy).contentResolverOpenFileDescriptor(any(), any(), any());

        byte[] encodedMessageEmail = mContent.getEmailMessage(TEST_ID, mParams, mCurrentFolder);
        InputStream inputStream = new ByteArrayInputStream(encodedMessageEmail);
        BluetoothMapbMessage messageParsed = BluetoothMapbMessage.parse(inputStream,
                BluetoothMapAppParams.CHARSET_UTF8);

        assertThat(messageParsed.getType()).isEqualTo(TYPE.EMAIL);
        assertThat(messageParsed.getVersionString()).isEqualTo("VERSION:" +
                mContent.mMessageVersion);
        assertThat(messageParsed.getFolder()).isEqualTo(mCurrentFolder.getFullPath());
        assertThat(messageParsed.getRecipients().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getName());
        assertThat(messageParsed.getRecipients().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getAddress());
        assertThat(messageParsed.getOriginators().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getName());
        assertThat(messageParsed.getOriginators().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getAddress());
    }

    @Test
    public void getEmailMessage_withNullPointerExceptionForEmailBodyAccess() throws Exception {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        when(mParams.getFractionRequest()).thenReturn(BluetoothMapAppParams.FRACTION_REQUEST_FIRST);
        when(mParams.getAttachment()).thenReturn(0);

        MatrixCursor cursor = new MatrixCursor(new String[] {
                BluetoothMapContract.MessageColumns.RECEPTION_STATE,
                BluetoothMapContract.MessageColumns.FLAG_READ,
                BluetoothMapContract.MessageColumns.FOLDER_ID,
                BluetoothMapContract.MessageColumns.TO_LIST,
                BluetoothMapContract.MessageColumns.FROM_LIST
        });
        cursor.addRow(new Object[] {BluetoothMapContract.RECEPTION_STATE_FRACTIONED, null,
                TEST_INBOX_FOLDER_ID, TEST_TO_ADDRESS, TEST_FROM_ADDRESS});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mCurrentFolder.setFolderId(TEST_INBOX_FOLDER_ID);
        // This mock sets up NullPointerException during email body access
        doThrow(NullPointerException.class).when(
                mMapMethodProxy).contentResolverOpenFileDescriptor(any(), any(), any());

        byte[] encodedMessageEmail = mContent.getEmailMessage(TEST_ID, mParams, mCurrentFolder);
        InputStream inputStream = new ByteArrayInputStream(encodedMessageEmail);
        BluetoothMapbMessage messageParsed = BluetoothMapbMessage.parse(inputStream,
                BluetoothMapAppParams.CHARSET_UTF8);

        assertThat(messageParsed.getType()).isEqualTo(TYPE.EMAIL);
        assertThat(messageParsed.getVersionString()).isEqualTo("VERSION:" +
                mContent.mMessageVersion);
        assertThat(messageParsed.getFolder()).isEqualTo(mCurrentFolder.getFullPath());
        assertThat(messageParsed.getRecipients().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getName());
        assertThat(messageParsed.getRecipients().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getAddress());
        assertThat(messageParsed.getOriginators().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getName());
        assertThat(messageParsed.getOriginators().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getAddress());
    }

    @Test
    public void getEmailMessage() throws Exception {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        when(mParams.getFractionRequest()).thenReturn(BluetoothMapAppParams.FRACTION_REQUEST_FIRST);
        when(mParams.getAttachment()).thenReturn(0);

        MatrixCursor cursor = new MatrixCursor(new String[] {
                BluetoothMapContract.MessageColumns.RECEPTION_STATE,
                BluetoothMapContract.MessageColumns.FLAG_READ,
                BluetoothMapContract.MessageColumns.FOLDER_ID,
                BluetoothMapContract.MessageColumns.TO_LIST,
                BluetoothMapContract.MessageColumns.FROM_LIST
        });
        cursor.addRow(new Object[] {BluetoothMapContract.RECEPTION_STATE_FRACTIONED, "1",
                TEST_INBOX_FOLDER_ID, TEST_TO_ADDRESS, TEST_FROM_ADDRESS});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mCurrentFolder.setFolderId(TEST_INBOX_FOLDER_ID);
        FileDescriptor fd = new FileDescriptor();
        ParcelFileDescriptor pfd = mock(ParcelFileDescriptor.class);
        doReturn(fd).when(pfd).getFileDescriptor();
        doReturn(pfd).when(mMapMethodProxy).contentResolverOpenFileDescriptor(any(), any(), any());

        byte[] encodedMessageEmail = mContent.getEmailMessage(TEST_ID, mParams, mCurrentFolder);
        InputStream inputStream = new ByteArrayInputStream(encodedMessageEmail);
        BluetoothMapbMessage messageParsed = BluetoothMapbMessage.parse(inputStream,
                BluetoothMapAppParams.CHARSET_UTF8);

        assertThat(messageParsed.getType()).isEqualTo(TYPE.EMAIL);
        assertThat(messageParsed.getVersionString()).isEqualTo("VERSION:" +
                mContent.mMessageVersion);
        assertThat(messageParsed.getFolder()).isEqualTo(mCurrentFolder.getFullPath());
        assertThat(messageParsed.getRecipients().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getName());
        assertThat(messageParsed.getRecipients().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_TO_ADDRESS)[0].getAddress());
        assertThat(messageParsed.getOriginators().get(0).getName()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getName());
        assertThat(messageParsed.getOriginators().get(0).getFirstEmail()).isEqualTo(
                Rfc822Tokenizer.tokenize(TEST_FROM_ADDRESS)[0].getAddress());
    }

    @Test
    public void getIMMessage_withCharsetNative() {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_NATIVE);

        assertThrows(IllegalArgumentException.class, () -> mContent.getIMMessage(TEST_ID,
                mParams, mCurrentFolder));
    }

    @Test
    public void getIMMessage_withEmptyCursor() {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        MatrixCursor cursor = new MatrixCursor(new String[] {});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        assertThrows(IllegalArgumentException.class, () -> mContent.getIMMessage(TEST_ID,
                mParams, mCurrentFolder));
    }

    @Test
    public void getIMMessage_withSentFolderId() throws Exception {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        when(mParams.getAttachment()).thenReturn(1);

        MatrixCursor cursor = new MatrixCursor(new String[] {
                BluetoothMapContract.MessageColumns.FLAG_READ,
                BluetoothMapContract.MessageColumns.THREAD_ID,
                BluetoothMapContract.MessageColumns.FOLDER_ID,
                BluetoothMapContract.MessageColumns.SUBJECT,
                BluetoothMapContract.MessageColumns._ID,
                BluetoothMapContract.MessageColumns.DATE,
                BluetoothMapContract.MessageColumns.ATTACHMENT_SIZE,
                BluetoothMapContract.MessageColumns.BODY,
                BluetoothMapContract.ConvoContactColumns.NAME,
                BluetoothMapContract.ConvoContactColumns.X_BT_UID,
                BluetoothMapContract.ConvoContactColumns.NICKNAME,
                BluetoothMapContract.ConvoContactColumns.UCI,
        });
        cursor.addRow(new Object[] {1, 1, TEST_SENT_FOLDER_ID, TEST_SUBJECT, TEST_MESSAGE_ID,
                TEST_DATE, 0, "body", TEST_NAME, TEST_FIRST_BT_UID, TEST_FORMATTED_NAME,
                TEST_FIRST_BT_UCI_RECIPIENT});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mCurrentFolder.setFolderId(TEST_SENT_FOLDER_ID);
        when(mAccountItem.getUciFull()).thenReturn(TEST_FIRST_BT_UCI_ORIGINATOR);

        byte[] encodedMessageMime = mContent.getIMMessage(TEST_ID, mParams, mCurrentFolder);
        InputStream inputStream = new ByteArrayInputStream(encodedMessageMime);
        BluetoothMapbMessage messageMimeParsed = BluetoothMapbMessage.parse(inputStream, 1);

        assertThat(messageMimeParsed.mAppParamCharset).isEqualTo(1);
        assertThat(messageMimeParsed.getType()).isEqualTo(TYPE.IM);
        assertThat(messageMimeParsed.getVersionString()).isEqualTo("VERSION:" +
                mContent.mMessageVersion);
        assertThat(messageMimeParsed.getFolder()).isEqualTo(mCurrentFolder.getFullPath());
        assertThat(messageMimeParsed.getRecipients().size()).isEqualTo(1);
        assertThat(messageMimeParsed.getOriginators().size()).isEqualTo(1);
        assertThat(messageMimeParsed.getOriginators().get(0).getName()).isEmpty();
        assertThat(messageMimeParsed.getRecipients().get(0).getName()).isEqualTo(
                TEST_FORMATTED_NAME);
    }

    @Test
    public void getIMMessage_withInboxFolderId() throws Exception {
        when(mParams.getCharset()).thenReturn(BluetoothMapContent.MAP_MESSAGE_CHARSET_UTF8);
        when(mParams.getAttachment()).thenReturn(1);

        MatrixCursor cursor = new MatrixCursor(new String[] {
                BluetoothMapContract.MessageColumns.FLAG_READ,
                BluetoothMapContract.MessageColumns.THREAD_ID,
                BluetoothMapContract.MessageColumns.FOLDER_ID,
                BluetoothMapContract.MessageColumns.SUBJECT,
                BluetoothMapContract.MessageColumns._ID,
                BluetoothMapContract.MessageColumns.DATE,
                BluetoothMapContract.MessageColumns.ATTACHMENT_SIZE,
                BluetoothMapContract.MessageColumns.BODY,
                BluetoothMapContract.ConvoContactColumns.NAME,
                BluetoothMapContract.ConvoContactColumns.X_BT_UID,
                BluetoothMapContract.ConvoContactColumns.NICKNAME,
                BluetoothMapContract.ConvoContactColumns.UCI,
        });
        cursor.addRow(new Object[] {0, 1, TEST_INBOX_FOLDER_ID, TEST_SUBJECT, TEST_MESSAGE_ID,
                TEST_DATE, 0, "body", TEST_NAME, TEST_FIRST_BT_UID, TEST_FORMATTED_NAME,
                TEST_FIRST_BT_UCI_ORIGINATOR});
        cursor.moveToFirst();
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());

        mCurrentFolder.setFolderId(TEST_INBOX_FOLDER_ID);
        when(mAccountItem.getUciFull()).thenReturn(TEST_FIRST_BT_UCI_RECIPIENT);

        byte[] encodedMessageMime = mContent.getIMMessage(TEST_ID, mParams, mCurrentFolder);
        InputStream inputStream = new ByteArrayInputStream(encodedMessageMime);
        BluetoothMapbMessage messageMimeParsed = BluetoothMapbMessage.parse(inputStream, 1);

        assertThat(messageMimeParsed.mAppParamCharset).isEqualTo(1);
        assertThat(messageMimeParsed.getType()).isEqualTo(TYPE.IM);
        assertThat(messageMimeParsed.getVersionString()).isEqualTo("VERSION:" +
                mContent.mMessageVersion);
        assertThat(messageMimeParsed.getFolder()).isEqualTo(mCurrentFolder.getFullPath());
        assertThat(messageMimeParsed.getRecipients().size()).isEqualTo(1);
        assertThat(messageMimeParsed.getOriginators().size()).isEqualTo(1);
        assertThat(messageMimeParsed.getOriginators().get(0).getName()).isEqualTo(
                TEST_FORMATTED_NAME);
        assertThat(messageMimeParsed.getRecipients().get(0).getName()).isEmpty();
    }
}