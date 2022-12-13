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

package com.android.bluetooth.opp;

import static android.content.pm.PackageManager.DONT_KILL_APP;
import static android.service.pm.PackageProto.UserInfoProto.COMPONENT_ENABLED_STATE_DEFAULT;
import static android.service.pm.PackageProto.UserInfoProto.COMPONENT_ENABLED_STATE_ENABLED;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.RootMatchers.isDialog;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withText;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import android.app.Activity;
import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.test.ActivityInstrumentationTestCase2;

import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.R;

import com.google.common.base.Objects;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.util.ArrayList;
import java.util.List;

@RunWith(AndroidJUnit4.class)
public class BluetoothOppIncomingFileConfirmActivityTest extends
        ActivityInstrumentationTestCase2<BluetoothOppIncomingFileConfirmActivity> {
    @Mock
    Cursor mCursor;
    @Spy
    BluetoothMethodProxy mBluetoothMethodProxy;

    List<BluetoothOppTestUtils.CursorMockData> mCursorMockDataList;

    Intent mIntent;
    Context mTargetContext;

    boolean mDestroyed;

    public BluetoothOppIncomingFileConfirmActivityTest() {
        super(BluetoothOppIncomingFileConfirmActivity.class);
    }

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        mBluetoothMethodProxy = Mockito.spy(BluetoothMethodProxy.getInstance());
        BluetoothMethodProxy.setInstanceForTesting(mBluetoothMethodProxy);

        Uri dataUrl = Uri.parse("content://com.android.bluetooth.opp.test/random");

        mTargetContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        mIntent = new Intent();
        mIntent.setClass(mTargetContext, BluetoothOppIncomingFileConfirmActivity.class);
        mIntent.setData(dataUrl);
        setActivityIntent(mIntent);
        injectInstrumentation(InstrumentationRegistry.getInstrumentation());

        doReturn(mCursor).when(mBluetoothMethodProxy).contentResolverQuery(any(), eq(dataUrl),
                eq(null), eq(null),
                eq(null), eq(null));

        doReturn(1).when(mBluetoothMethodProxy).contentResolverUpdate(any(), eq(dataUrl),
                any(), eq(null), eq(null));

        int idValue = 1234;
        Long timestampValue = 123456789L;
        String destinationValue = "AA:BB:CC:00:11:22";
        String fileTypeValue = "text/plain";

        mCursorMockDataList = new ArrayList<>(List.of(
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.STATUS, 1,
                        BluetoothShare.STATUS_PENDING),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.DIRECTION, 2,
                        BluetoothShare.DIRECTION_OUTBOUND),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 0),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare._ID, 0, idValue),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.MIMETYPE, 5, fileTypeValue),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.TIMESTAMP, 6,
                        timestampValue),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.DESTINATION, 7,
                        destinationValue),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare._DATA, 8, null),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.FILENAME_HINT, 9, null),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.URI, 10,
                        "content://textfile.txt"),
                new BluetoothOppTestUtils.CursorMockData(BluetoothShare.USER_CONFIRMATION, 11,
                        BluetoothShare.USER_CONFIRMATION_HANDOVER_CONFIRMED)
        ));

        enableActivity(true);
    }

    @After
    public void tearDown() {
        BluetoothMethodProxy.setInstanceForTesting(null);
        enableActivity(false);
    }

    @Test
    public void onCreate_clickConfirmCancel_saveUSER_CONFIRMAMTION_DENIED()
            throws InterruptedException {
        BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

        BluetoothOppIncomingFileConfirmActivity activity = getActivity();

        // To work around (possibly) Epresso's bug. The dialog button is clicked (no error throw)
        // but onClick() is not triggered. It works normally if sleep for a few seconds
        Thread.sleep(3_000);
        onView(withText(mTargetContext.getText(R.string.incoming_file_confirm_cancel).toString()))
                .inRoot(isDialog()).check(matches(isDisplayed())).perform(click());

        verify(mBluetoothMethodProxy).contentResolverUpdate(any(), any(), argThat(
                argument -> Objects.equal(
                        BluetoothShare.USER_CONFIRMATION_DENIED,
                        argument.get(BluetoothShare.USER_CONFIRMATION))
        ), nullable(String.class), nullable(String[].class));
    }

    @Test
    public void onCreate_clickConfirmOk_saveUSER_CONFIRMATION_CONFIRMED()
            throws InterruptedException {
        BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

        BluetoothOppIncomingFileConfirmActivity activity = getActivity();

        // To work around (possibly) Espresso's bug. The dialog button is clicked (no error throw)
        // but onClick() is not triggered. It works normally if sleep for a few seconds
        Thread.sleep(3_000);
        onView(withText(mTargetContext.getText(R.string.incoming_file_confirm_ok).toString()))
                .inRoot(isDialog()).check(matches(isDisplayed())).perform(click());

        verify(mBluetoothMethodProxy).contentResolverUpdate(any(), any(), argThat(
                argument -> Objects.equal(
                        BluetoothShare.USER_CONFIRMATION_CONFIRMED,
                        argument.get(BluetoothShare.USER_CONFIRMATION))
        ), nullable(String.class), nullable(String[].class));
    }

    @Test
    public void onTimeout_sendIntentWithUSER_CONFIRMATION_TIMEOUT_ACTION_finish() throws Exception {
        BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

        mDestroyed = false;
        BluetoothOppIncomingFileConfirmActivity activity = getActivity();

        activity.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            }

            @Override
            public void onActivityStarted(Activity activity) {
            }

            @Override
            public void onActivityResumed(Activity activity) {
            }

            @Override
            public void onActivityPaused(Activity activity) {
            }

            @Override
            public void onActivityStopped(Activity activity) {
            }

            @Override
            public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
            }

            @Override
            public void onActivityDestroyed(Activity activity) {
                mDestroyed = true;
            }
        });
        assertThat(mDestroyed).isFalse();
        Intent in = new Intent(BluetoothShare.USER_CONFIRMATION_TIMEOUT_ACTION);
        mTargetContext.sendBroadcast(in);

        // To work around (possibly) Espresso's bug. The dialog button is clicked (no error throw)
        // but onClick() is not triggered. It works normally if sleep for a few seconds
        Thread.sleep(3_000);
        assertThat(mDestroyed).isTrue();
    }

    private void enableActivity(boolean enable) {
        int enabledState = enable ? COMPONENT_ENABLED_STATE_ENABLED
                : COMPONENT_ENABLED_STATE_DEFAULT;

        mTargetContext.getPackageManager().setApplicationEnabledSetting(
                mTargetContext.getPackageName(), enabledState, DONT_KILL_APP);

        ComponentName activityName = new ComponentName(mTargetContext,
                BluetoothOppIncomingFileConfirmActivity.class);
        mTargetContext.getPackageManager().setComponentEnabledSetting(
                activityName, enabledState, DONT_KILL_APP);
    }
}
