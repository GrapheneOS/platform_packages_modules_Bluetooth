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

import static com.android.bluetooth.opp.BluetoothOppTestUtils.CursorMockData;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_RECEIVE_COMPLETE_FAIL;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_RECEIVE_COMPLETE_SUCCESS;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_RECEIVE_ONGOING;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_SEND_COMPLETE_FAIL;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_SEND_COMPLETE_SUCCESS;
import static com.android.bluetooth.opp.BluetoothOppTransferActivity.DIALOG_SEND_ONGOING;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.eq;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;

import androidx.test.core.app.ActivityScenario;
import androidx.test.filters.MediumTest;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.pbap.BluetoothPbapActivity;

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

@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothOppTransferActivityTest {
  @Mock
  Cursor mCursor;
  @Spy
  BluetoothMethodProxy mBluetoothMethodProxy;

  List<CursorMockData> mCursorMockDataList;

  Intent mIntent;
  Context mTargetContext;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    mBluetoothMethodProxy = Mockito.spy(BluetoothMethodProxy.getInstance());
    BluetoothMethodProxy.setInstanceForTesting(mBluetoothMethodProxy);

    Uri dataUrl = Uri.parse("content://com.android.bluetooth.opp.test/random");

    mTargetContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

    mIntent = new Intent();
    mIntent.setClass(mTargetContext, BluetoothOppTransferActivity.class);
    mIntent.setData(dataUrl);

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
            new CursorMockData(BluetoothShare._ID, 0, idValue),
            new CursorMockData(BluetoothShare.MIMETYPE, 5, fileTypeValue),
            new CursorMockData(BluetoothShare.TIMESTAMP, 6, timestampValue),
            new CursorMockData(BluetoothShare.DESTINATION, 7, destinationValue),
            new CursorMockData(BluetoothShare._DATA, 8, null),
            new CursorMockData(BluetoothShare.FILENAME_HINT, 9, null),
            new CursorMockData(BluetoothShare.URI, 10, "content://textfile.txt"),
            new CursorMockData(BluetoothShare.USER_CONFIRMATION, 11,
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
  public void onCreate_showSendOnGoingDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_PENDING));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_OUTBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 0));
    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(activity -> {
      assertThat(activity.mWhichDialog).isEqualTo(DIALOG_SEND_ONGOING);
    });
  }

  @Test
  public void onCreate_showSendCompleteSuccessDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_SUCCESS)
    );
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_OUTBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 100));
    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(activity -> {
      assertThat(activity.mWhichDialog).isEqualTo(DIALOG_SEND_COMPLETE_SUCCESS);
    });
  }

  @Test
  public void onCreate_showSendCompleteFailDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_FORBIDDEN));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_OUTBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 42));
    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(
            activity -> assertThat(activity.mWhichDialog).isEqualTo(DIALOG_SEND_COMPLETE_FAIL));
  }

  @Test
  public void onCreate_showReceiveOnGoingDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_PENDING));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_INBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 0));
    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);

    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(
            activity -> assertThat(activity.mWhichDialog).isEqualTo(DIALOG_RECEIVE_ONGOING));
  }

  @Test
  public void onCreate_showReceiveCompleteSuccessDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_SUCCESS));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_INBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 100)
    );

    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);
    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(activity -> assertThat(activity.mWhichDialog).isEqualTo(
            DIALOG_RECEIVE_COMPLETE_SUCCESS));
  }

  @Test
  public void onCreate_showReceiveCompleteFailDialog() {
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.STATUS, 1, BluetoothShare.STATUS_FORBIDDEN));
    mCursorMockDataList.add(
            new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_INBOUND)
    );
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.TOTAL_BYTES, 3, 100));
    mCursorMockDataList.add(new CursorMockData(BluetoothShare.CURRENT_BYTES, 4, 42));

    BluetoothOppTestUtils.setUpMockCursor(mCursor, mCursorMockDataList);
    ActivityScenario<BluetoothOppTransferActivity> activityScenario = ActivityScenario.launch(
            mIntent);

    activityScenario.onActivity(activity -> assertThat(activity.mWhichDialog).isEqualTo(
            DIALOG_RECEIVE_COMPLETE_FAIL));
  }

  private void enableActivity(boolean enable) {
    int enabledState = enable ? COMPONENT_ENABLED_STATE_ENABLED
            : COMPONENT_ENABLED_STATE_DEFAULT;

    mTargetContext.getPackageManager().setApplicationEnabledSetting(
            mTargetContext.getPackageName(), enabledState, DONT_KILL_APP);

    ComponentName activityName = new ComponentName(mTargetContext,
            BluetoothOppTransferActivity.class);
    mTargetContext.getPackageManager().setComponentEnabledSetting(
            activityName, enabledState, DONT_KILL_APP);
  }
}
