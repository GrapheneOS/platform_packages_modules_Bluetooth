/*
 * Copyright 2016 The Android Open Source Project
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

import static org.mockito.Mockito.*;

import android.content.ContentProviderClient;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.os.UserManager;
import android.provider.Telephony;
import android.provider.Telephony.Mms;
import android.provider.Telephony.Sms;
import android.telephony.TelephonyManager;
import android.test.mock.MockContentProvider;
import android.test.mock.MockContentResolver;

import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.R;
import com.android.bluetooth.map.BluetoothMapUtils.TYPE;
import com.android.obex.ResponseCodes;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothMapContentObserverTest {
    static final String TEST_NUMBER_ONE = "5551212";
    static final String TEST_NUMBER_TWO = "5551234";
    static final int TEST_MAS_ID = 1;
    static final long TEST_HANDLE = 1;
    static final String TEST_URI_STR = "test_uri_str";
    static final int TEST_STATUS_VALUE = 1;
    static final int TEST_THREAD_ID = 1;
    static final long TEST_OLD_THREAD_ID = 2;
    static final int TEST_PLACEHOLDER_INT = 1;
    static final String TEST_ADDRESS = "test_address";

    @Mock
    private BluetoothMnsObexClient mClient;
    @Mock
    private BluetoothMapMasInstance mInstance;
    @Mock
    private TelephonyManager mTelephonyManager;
    @Mock
    private UserManager mUserService;
    @Mock
    private Context mContext;
    @Mock
    private ContentProviderClient mProviderClient;
    @Spy
    private BluetoothMethodProxy mMapMethodProxy = BluetoothMethodProxy.getInstance();

    private ExceptionTestProvider mProvider;
    private MockContentResolver mMockContentResolver;
    private BluetoothMapContentObserver mObserver;

    static class ExceptionTestProvider extends MockContentProvider {
        HashSet<String> mContents = new HashSet<String>();

        public ExceptionTestProvider(Context context) {
            super(context);
        }

        @Override
        public Cursor query(Uri uri, String[] b, String s, String[] c, String d) {
            // Throw exception for SMS queries for easy initialization
            if (Sms.CONTENT_URI.equals(uri)) throw new SQLiteException();

            // Return a cursor otherwise for Thread IDs
            Cursor cursor = Mockito.mock(Cursor.class);
            when(cursor.moveToFirst()).thenReturn(true);
            when(cursor.getLong(anyInt())).thenReturn(0L);
            return cursor;
        }

        @Override
        public Uri insert(Uri uri, ContentValues values) {
            // Store addresses for later verification
            Object address = values.get(Mms.Addr.ADDRESS);
            if (address != null) mContents.add((String) address);
            return Uri.withAppendedPath(Mms.Outbox.CONTENT_URI, "0");
        }
    }

    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue("Ignore test when BluetoothMapService is not enabled",
                BluetoothMapService.isEnabled());
        MockitoAnnotations.initMocks(this);
        BluetoothMethodProxy.setInstanceForTesting(mMapMethodProxy);
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        mMockContentResolver = new MockContentResolver();
        mProvider = new ExceptionTestProvider(mContext);
        mMockContentResolver.addProvider("sms", mProvider);

        // Functions that get called when BluetoothMapContentObserver is created
        when(mUserService.isUserUnlocked()).thenReturn(true);
        when(mContext.getContentResolver()).thenReturn(mMockContentResolver);
        when(mContext.getSystemService(Context.TELEPHONY_SERVICE)).thenReturn(mTelephonyManager);
        when(mContext.getSystemServiceName(TelephonyManager.class))
                .thenReturn(Context.TELEPHONY_SERVICE);
        when(mContext.getSystemService(Context.USER_SERVICE)).thenReturn(mUserService);
        when(mContext.getSystemServiceName(UserManager.class)).thenReturn(Context.USER_SERVICE);
        when(mInstance.getMasId()).thenReturn(TEST_MAS_ID);

        mObserver = new BluetoothMapContentObserver(mContext, mClient, mInstance, null, true);
    }

    @After
    public void tearDown() throws Exception {
        BluetoothMethodProxy.setInstanceForTesting(null);
    }

    @Test
    public void testPushGroupMMS() {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        mMockContentResolver.addProvider("mms", mProvider);
        mMockContentResolver.addProvider("mms-sms", mProvider);

        BluetoothMapbMessageMime message = new BluetoothMapbMessageMime();
        message.setType(BluetoothMapUtils.TYPE.MMS);
        message.setFolder("telecom/msg/outbox");
        message.addSender("Zero", "0");
        message.addRecipient("One", new String[]{TEST_NUMBER_ONE}, null);
        message.addRecipient("Two", new String[]{TEST_NUMBER_TWO}, null);
        BluetoothMapbMessageMime.MimePart body = message.addMimePart();
        try {
            body.mContentType = "text/plain";
            body.mData = "HelloWorld".getBytes("utf-8");
        } catch (Exception e) {
            Assert.fail("Failed to setup test message");
        }

        BluetoothMapAppParams appParams = new BluetoothMapAppParams();
        BluetoothMapFolderElement folderElement = new BluetoothMapFolderElement("outbox", null);

        try {
            // The constructor of BluetoothMapContentObserver calls initMsgList
            BluetoothMapContentObserver observer =
                    new BluetoothMapContentObserver(mContext, null, mInstance, null, true);
            observer.pushMessage(message, folderElement, appParams, null);
        } catch (RemoteException e) {
            Assert.fail("Failed to created BluetoothMapContentObserver object");
        } catch (SQLiteException e) {
            Assert.fail("Threw SQLiteException instead of Assert.failing cleanly");
        } catch (IOException e) {
            Assert.fail("Threw IOException");
        } catch (NullPointerException e) {
            //expected that the test case will end in a NPE as part of the sendMultimediaMessage
            //pendingSendIntent
        }

        // Validate that 3 addresses were inserted into the database with 2 being the recipients
        Assert.assertEquals(3, mProvider.mContents.size());
        Assert.assertTrue(mProvider.mContents.contains(TEST_NUMBER_ONE));
        Assert.assertTrue(mProvider.mContents.contains(TEST_NUMBER_TWO));
    }

    @Test
    public void testSendEvent_withZeroEventFilter() {
        when(mClient.isConnected()).thenReturn(true);
        mObserver.setNotificationFilter(0);

        String eventType = BluetoothMapContentObserver.EVENT_TYPE_NEW;
        BluetoothMapContentObserver.Event event = mObserver.new Event(eventType, TEST_HANDLE, null,
                null);
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_DELETE;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_REMOVED;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_SHIFT;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_DELEVERY_SUCCESS;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_SENDING_SUCCESS;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_SENDING_FAILURE;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_READ_STATUS;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_CONVERSATION;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_PRESENCE;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());

        event.eventType = BluetoothMapContentObserver.EVENT_TYPE_CHAT_STATE;
        mObserver.sendEvent(event);
        verify(mClient, never()).sendEvent(any(), anyInt());
    }

    @Test
    public void testEvent_withNonZeroEventFilter() throws Exception {
        when(mClient.isConnected()).thenReturn(true);

        String eventType = BluetoothMapContentObserver.EVENT_TYPE_NEW;
        BluetoothMapContentObserver.Event event = mObserver.new Event(eventType, TEST_HANDLE, null,
                null);

        mObserver.sendEvent(event);

        verify(mClient).sendEvent(event.encode(), TEST_MAS_ID);
    }

    @Test
    public void testSetContactList() {
        Map<String, BluetoothMapConvoContactElement> map = Map.of();

        mObserver.setContactList(map, true);

        Assert.assertEquals(mObserver.getContactList(), map);
    }

    @Test
    public void testSetMsgListSms() {
        Map<Long, BluetoothMapContentObserver.Msg> map = Map.of();

        mObserver.setMsgListSms(map, true);

        Assert.assertEquals(mObserver.getMsgListSms(), map);
    }

    @Test
    public void testSetMsgListMsg() {
        Map<Long, BluetoothMapContentObserver.Msg> map = Map.of();

        mObserver.setMsgListMsg(map, true);

        Assert.assertEquals(mObserver.getMsgListMsg(), map);
    }

    @Test
    public void testSetMsgListMms() {
        Map<Long, BluetoothMapContentObserver.Msg> map = Map.of();

        mObserver.setMsgListMms(map, true);

        Assert.assertEquals(mObserver.getMsgListMms(), map);
    }

    @Test
    public void testSetNotificationRegistration_withNullHandler() throws Exception {
        when(mClient.getMessageHandler()).thenReturn(null);

        Assert.assertEquals(
                mObserver.setNotificationRegistration(BluetoothMapAppParams.NOTIFICATION_STATUS_NO),
                ResponseCodes.OBEX_HTTP_UNAVAILABLE);
    }

    @Test
    public void testSetNotificationRegistration_withInvalidMnsRecord() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Handler handler = new Handler();
        when(mClient.getMessageHandler()).thenReturn(handler);
        when(mClient.isValidMnsRecord()).thenReturn(false);

        Assert.assertEquals(
                mObserver.setNotificationRegistration(BluetoothMapAppParams.NOTIFICATION_STATUS_NO),
                ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testSetNotificationRegistration_withValidMnsRecord() throws Exception {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Handler handler = new Handler();
        when(mClient.getMessageHandler()).thenReturn(handler);
        when(mClient.isValidMnsRecord()).thenReturn(true);

        Assert.assertEquals(
                mObserver.setNotificationRegistration(BluetoothMapAppParams.NOTIFICATION_STATUS_NO),
                ResponseCodes.OBEX_HTTP_OK);
    }

    @Test
    public void testSetMessageStatusRead_withTypeSmsGsm() throws Exception {
        TYPE type = TYPE.SMS_GSM;
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createSimpleMsg();
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListSms(map, true);
        int count = 1;
        doReturn(count).when(mMapMethodProxy).contentResolverUpdate(any(), any(), any(), any(),
                any());

        Assert.assertTrue(mObserver.setMessageStatusRead(TEST_HANDLE, type, TEST_URI_STR,
                TEST_STATUS_VALUE));

        Assert.assertEquals(msg.flagRead, TEST_STATUS_VALUE);
    }

    @Test
    public void testSetMessageStatusRead_withTypeMms() throws Exception {
        TYPE type = TYPE.MMS;
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createSimpleMsg();
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        int count = 1;
        doReturn(count).when(mMapMethodProxy).contentResolverUpdate(any(), any(), any(), any(),
                any());

        Assert.assertTrue(mObserver.setMessageStatusRead(TEST_HANDLE, type, TEST_URI_STR,
                TEST_STATUS_VALUE));

        Assert.assertEquals(msg.flagRead, TEST_STATUS_VALUE);
    }

    @Test
    public void testSetMessageStatusRead_withTypeEmail() throws Exception {
        TYPE type = TYPE.EMAIL;
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createSimpleMsg();
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMsg(map, true);
        int count = 1;
        mObserver.mProviderClient = mProviderClient;
        when(mProviderClient.update(any(), any(), any(), any())).thenReturn(count);

        Assert.assertTrue(mObserver.setMessageStatusRead(TEST_HANDLE, type, TEST_URI_STR,
                TEST_STATUS_VALUE));

        Assert.assertEquals(msg.flagRead, TEST_STATUS_VALUE);
    }

    @Test
    public void testDeleteMessageMms_withNonDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Mms.MESSAGE_BOX_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);

        MatrixCursor cursor = new MatrixCursor(new String[] {Mms.THREAD_ID});
        cursor.addRow(new Object[] {TEST_THREAD_ID});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverUpdate(any(), any(),
                any(), any(), any());

        Assert.assertTrue(mObserver.deleteMessageMms(TEST_HANDLE));

        Assert.assertEquals(msg.threadId, BluetoothMapContentObserver.DELETED_THREAD_ID);
    }

    @Test
    public void testDeleteMessageMms_withDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Mms.MESSAGE_BOX_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        Assert.assertNotNull(mObserver.getMsgListMms().get(TEST_HANDLE));

        MatrixCursor cursor = new MatrixCursor(new String[] {Mms.THREAD_ID});
        cursor.addRow(new Object[] {BluetoothMapContentObserver.DELETED_THREAD_ID});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverDelete(any(), any(),
                any(), any());

        Assert.assertTrue(mObserver.deleteMessageMms(TEST_HANDLE));

        Assert.assertNull(mObserver.getMsgListMms().get(TEST_HANDLE));
    }

    @Test
    public void testDeleteMessageSms_withNonDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Sms.MESSAGE_TYPE_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListSms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);

        MatrixCursor cursor = new MatrixCursor(new String[] {Mms.THREAD_ID});
        cursor.addRow(new Object[] {TEST_THREAD_ID});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverUpdate(any(), any(),
                any(), any(), any());

        Assert.assertTrue(mObserver.deleteMessageSms(TEST_HANDLE));

        Assert.assertEquals(msg.threadId, BluetoothMapContentObserver.DELETED_THREAD_ID);
    }

    @Test
    public void testDeleteMessageSms_withDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Sms.MESSAGE_TYPE_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListSms(map, true);
        Assert.assertNotNull(mObserver.getMsgListSms().get(TEST_HANDLE));

        MatrixCursor cursor = new MatrixCursor(new String[] {Mms.THREAD_ID});
        cursor.addRow(new Object[] {BluetoothMapContentObserver.DELETED_THREAD_ID});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverDelete(any(), any(),
                any(), any());

        Assert.assertTrue(mObserver.deleteMessageSms(TEST_HANDLE));

        Assert.assertNull(mObserver.getMsgListSms().get(TEST_HANDLE));
    }

    @Test
    public void testUnDeleteMessageMms_withDeletedThreadId_andMessageBoxInbox() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Mms.MESSAGE_BOX_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Mms.MESSAGE_BOX_ALL);

        MatrixCursor cursor = new MatrixCursor(
                new String[] {Mms.THREAD_ID, Mms._ID, Mms.MESSAGE_BOX, Mms.Addr.ADDRESS});
        cursor.addRow(new Object[] {BluetoothMapContentObserver.DELETED_THREAD_ID, 1L,
                Mms.MESSAGE_BOX_INBOX, TEST_ADDRESS});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverUpdate(any(), any(),
                any(), any(), any());
        doReturn(TEST_OLD_THREAD_ID).when(mMapMethodProxy).telephonyGetOrCreateThreadId(any(),
                any());

        Assert.assertTrue(mObserver.unDeleteMessageMms(TEST_HANDLE));

        Assert.assertEquals(msg.threadId, TEST_OLD_THREAD_ID);
        Assert.assertEquals(msg.type, Mms.MESSAGE_BOX_INBOX);
    }

    @Test
    public void testUnDeleteMessageMms_withDeletedThreadId_andMessageBoxSent() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Mms.MESSAGE_BOX_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Mms.MESSAGE_BOX_ALL);

        MatrixCursor cursor = new MatrixCursor(
                new String[] {Mms.THREAD_ID, Mms._ID, Mms.MESSAGE_BOX, Mms.Addr.ADDRESS});
        cursor.addRow(new Object[] {BluetoothMapContentObserver.DELETED_THREAD_ID, 1L,
                Mms.MESSAGE_BOX_SENT, TEST_ADDRESS});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverUpdate(any(), any(),
                any(), any(), any());
        doReturn(TEST_OLD_THREAD_ID).when(mMapMethodProxy).telephonyGetOrCreateThreadId(any(),
                any());

        Assert.assertTrue(mObserver.unDeleteMessageMms(TEST_HANDLE));

        Assert.assertEquals(msg.threadId, TEST_OLD_THREAD_ID);
        Assert.assertEquals(msg.type, Mms.MESSAGE_BOX_INBOX);
    }

    @Test
    public void testUnDeleteMessageMms_withoutDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Mms.MESSAGE_BOX_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListMms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Mms.MESSAGE_BOX_ALL);

        MatrixCursor cursor = new MatrixCursor(
                new String[] {Mms.THREAD_ID, Mms._ID, Mms.MESSAGE_BOX, Mms.Addr.ADDRESS,});
        cursor.addRow(new Object[] {TEST_THREAD_ID, 1L, Mms.MESSAGE_BOX_SENT, TEST_ADDRESS});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_OLD_THREAD_ID).when(mMapMethodProxy).telephonyGetOrCreateThreadId(any(),
                any());

        Assert.assertTrue(mObserver.unDeleteMessageMms(TEST_HANDLE));

        // Nothing changes when thread id is not BluetoothMapContentObserver.DELETED_THREAD_ID
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Sms.MESSAGE_TYPE_ALL);
    }

    @Test
    public void testUnDeleteMessageSms_withDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Sms.MESSAGE_TYPE_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListSms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Sms.MESSAGE_TYPE_ALL);

        MatrixCursor cursor = new MatrixCursor(
                new String[] {Sms.THREAD_ID, Sms.ADDRESS});
        cursor.addRow(new Object[] {BluetoothMapContentObserver.DELETED_THREAD_ID, TEST_ADDRESS});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_PLACEHOLDER_INT).when(mMapMethodProxy).contentResolverUpdate(any(), any(),
                any(), any(), any());
        doReturn(TEST_OLD_THREAD_ID).when(mMapMethodProxy).telephonyGetOrCreateThreadId(any(),
                any());

        Assert.assertTrue(mObserver.unDeleteMessageSms(TEST_HANDLE));

        Assert.assertEquals(msg.threadId, TEST_OLD_THREAD_ID);
        Assert.assertEquals(msg.type, Sms.MESSAGE_TYPE_INBOX);
    }

    @Test
    public void testUnDeleteMessageSms_withoutDeletedThreadId() {
        Map<Long, BluetoothMapContentObserver.Msg> map = new HashMap<>();
        BluetoothMapContentObserver.Msg msg = createMsgWithTypeAndThreadId(Sms.MESSAGE_TYPE_ALL,
                TEST_THREAD_ID);
        map.put(TEST_HANDLE, msg);
        mObserver.setMsgListSms(map, true);
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Sms.MESSAGE_TYPE_ALL);

        MatrixCursor cursor = new MatrixCursor(
                new String[] {Sms.THREAD_ID, Sms.ADDRESS});
        cursor.addRow(new Object[] {TEST_THREAD_ID, TEST_ADDRESS});
        doReturn(cursor).when(mMapMethodProxy).contentResolverQuery(any(), any(), any(), any(),
                any(), any());
        doReturn(TEST_OLD_THREAD_ID).when(mMapMethodProxy).telephonyGetOrCreateThreadId(any(),
                any());

        Assert.assertTrue(mObserver.unDeleteMessageSms(TEST_HANDLE));

        // Nothing changes when thread id is not BluetoothMapContentObserver.DELETED_THREAD_ID
        Assert.assertEquals(msg.threadId, TEST_THREAD_ID);
        Assert.assertEquals(msg.type, Sms.MESSAGE_TYPE_ALL);
    }

    @Test
    public void testPushMsgInfo() {
        long id = 1;
        int transparent = 1;
        int retry = 1;
        String phone = "test_phone";
        Uri uri = mock(Uri.class);

        BluetoothMapContentObserver.PushMsgInfo msgInfo =
                new BluetoothMapContentObserver.PushMsgInfo(id, transparent, retry, phone, uri);

        Assert.assertEquals(msgInfo.id, id);
        Assert.assertEquals(msgInfo.transparent, transparent);
        Assert.assertEquals(msgInfo.retry, retry);
        Assert.assertEquals(msgInfo.phone, phone);
        Assert.assertEquals(msgInfo.uri, uri);
    }

    private BluetoothMapContentObserver.Msg createSimpleMsg() {
        return new BluetoothMapContentObserver.Msg(1, 1L, 1);
    }

    private BluetoothMapContentObserver.Msg createMsgWithTypeAndThreadId(int type, int threadId) {
        return new BluetoothMapContentObserver.Msg(1, type, threadId, 1);
    }
}
