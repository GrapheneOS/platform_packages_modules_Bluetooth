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

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.os.UserManager;
import android.provider.Telephony.Mms;
import android.provider.Telephony.Sms;
import android.telephony.TelephonyManager;
import android.test.mock.MockContentProvider;
import android.test.mock.MockContentResolver;

import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.obex.ResponseCodes;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothMapContentObserverTest {
    static final String TEST_NUMBER_ONE = "5551212";
    static final String TEST_NUMBER_TWO = "5551234";
    static final int TEST_MAS_ID = 1;
    static final long TEST_HANDLE = 1;

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
        message.addRecipient("One", new String[] {TEST_NUMBER_ONE}, null);
        message.addRecipient("Two", new String[] {TEST_NUMBER_TWO}, null);
        BluetoothMapbMessageMime.MimePart body =  message.addMimePart();
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
}
