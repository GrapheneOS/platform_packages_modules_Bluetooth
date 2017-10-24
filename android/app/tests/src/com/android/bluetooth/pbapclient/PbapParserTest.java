/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.bluetooth.pbapclient;

import android.accounts.Account;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.database.Cursor;
import android.provider.CallLog.Calls;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.util.TimeZone;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class PbapParserTest {
    private Account mAccount;
    private Resources mTestResources;
    private Context mTargetContext;
    private static final String TEST_ACCOUNT_NAME = "PBAPTESTACCOUNT";
    private static final String TEST_PACKAGE_NAME = "com.android.bluetooth.tests";

    @Before
    public void setUp() {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        mAccount = new Account(TEST_ACCOUNT_NAME,
                mTargetContext.getString(com.android.bluetooth.R.string.pbap_account_type));
        try {
            mTestResources = mTargetContext.getPackageManager()
                    .getResourcesForApplication(TEST_PACKAGE_NAME);
        } catch (PackageManager.NameNotFoundException e) {
            Assert.fail("Setup Failure Unable to get resources" + e.toString());
        }
        cleanupCallLog();
    }

    // testNoTimestamp should parse 1 poorly formed vcard and not crash.
    @Test
    public void testNoTimestamp() throws IOException {
        InputStream fileStream;
        fileStream = mTestResources.openRawResource(
                com.android.bluetooth.tests.R.raw.no_timestamp_call_log);
        BluetoothPbapVcardList pbapVCardList = new BluetoothPbapVcardList(mAccount, fileStream,
                PbapClientConnectionHandler.VCARD_TYPE_30);
        Assert.assertEquals(1, pbapVCardList.getCount());
        CallLogPullRequest processor =
                new CallLogPullRequest(mTargetContext, PbapClientConnectionHandler.MCH_PATH);
        processor.setResults(pbapVCardList.getList());

        // Verify that these entries aren't in the call log to start.
        Assert.assertFalse(verifyCallLog("555-0001", null, "3"));

        // Finish processing the data and verify entries were added to the call log.
        processor.onPullComplete();
        Assert.assertTrue(verifyCallLog("555-0001", null, "3"));
    }

    // testMissedCall should parse one phonecall correctly.
    @Test
    public void testMissedCall() throws IOException {
        InputStream fileStream;
        fileStream = mTestResources.openRawResource(
                com.android.bluetooth.tests.R.raw.single_missed_call);
        BluetoothPbapVcardList pbapVCardList = new BluetoothPbapVcardList(mAccount, fileStream,
                PbapClientConnectionHandler.VCARD_TYPE_30);
        Assert.assertEquals(1, pbapVCardList.getCount());
        CallLogPullRequest processor =
                new CallLogPullRequest(mTargetContext, PbapClientConnectionHandler.MCH_PATH);
        processor.setResults(pbapVCardList.getList());

        // Verify that these entries aren't in the call log to start.
        Assert.assertFalse(verifyCallLog("555-0002", "1483232460000", "3"));
        // Finish processing the data and verify entries were added to the call log.
        processor.onPullComplete();
        Assert.assertTrue(verifyCallLog("555-0002", "1483232460000", "3"));
    }

    // testUnknownCall should parse two calls with no phone number.
    @Test
    public void testUnknownCall() throws IOException {
        InputStream fileStream;
        fileStream = mTestResources.openRawResource(
                com.android.bluetooth.tests.R.raw.unknown_number_call);
        BluetoothPbapVcardList pbapVCardList = new BluetoothPbapVcardList(mAccount, fileStream,
                PbapClientConnectionHandler.VCARD_TYPE_30);
        Assert.assertEquals(2, pbapVCardList.getCount());
        CallLogPullRequest processor =
                new CallLogPullRequest(mTargetContext, PbapClientConnectionHandler.MCH_PATH);
        processor.setResults(pbapVCardList.getList());

        // Verify that these entries aren't in the call log to start.
        Assert.assertFalse(verifyCallLog("", "1483232520000", "3"));
        Assert.assertFalse(verifyCallLog("", "1483232580000", "3"));

        // Finish processing the data and verify entries were added to the call log.
        processor.onPullComplete();
        Assert.assertTrue(verifyCallLog("", "1483232520000", "3"));
        Assert.assertTrue(verifyCallLog("", "1483232580000", "3"));
    }

    private void cleanupCallLog() {
        mTargetContext.getContentResolver().delete(Calls.CONTENT_URI, null, null);
    }

    // Find Entries in call log with type matching number and date.
    // If number or date is null it will match any number or date respectively.
    private boolean verifyCallLog(String number, String date, String type) {
        String[] query = new String[]{Calls.NUMBER, Calls.DATE, Calls.TYPE};
        Cursor cursor = mTargetContext.getContentResolver()
                .query(Calls.CONTENT_URI, query, Calls.TYPE + "= " + type, null,
                        Calls.DATE + ", " + Calls.NUMBER);
        if (date != null) {
            date = adjDate(date);
        }
        if (cursor != null) {
            while (cursor.moveToNext()) {
                String foundNumber = cursor.getString(cursor.getColumnIndex(Calls.NUMBER));
                String foundDate = cursor.getString(cursor.getColumnIndex(Calls.DATE));
                if ((number == null || number.equals(foundNumber)) && (date == null || date.equals(
                        foundDate))) {
                    return true;
                }
            }
            cursor.close();
        }
        return false;
    }

    // Get time zone from device and adjust date to the device's time zone.
    private static String adjDate(String date) {
        TimeZone tz = TimeZone.getDefault();
        long dt = Long.valueOf(date) - tz.getRawOffset();
        return Long.toString(dt);
    }
}
