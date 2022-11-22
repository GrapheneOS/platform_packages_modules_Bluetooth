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

import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
import static android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED;
import static android.content.pm.PackageManager.DONT_KILL_APP;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.intent.Intents.intended;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent;
import static androidx.test.espresso.matcher.RootMatchers.isDialog;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withText;

import static com.google.common.truth.Truth.assertThat;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import android.bluetooth.BluetoothDevicePicker;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.net.Uri;

import androidx.lifecycle.Lifecycle;
import androidx.test.core.app.ActivityScenario;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.espresso.intent.Intents;
import androidx.test.filters.MediumTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.BluetoothMethodProxy;
import com.android.bluetooth.R;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockitoAnnotations;

import java.io.File;


@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothOppLauncherActivityTest {
    Context mTargetContext;
    Intent mIntent;

    BluetoothMethodProxy mMethodProxy;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        mTargetContext = spy(new ContextWrapper(
                ApplicationProvider.getApplicationContext()));
        mMethodProxy = spy(BluetoothMethodProxy.getInstance());
        BluetoothMethodProxy.setInstanceForTesting(mMethodProxy);

        mIntent = new Intent();
        mIntent.setClass(mTargetContext, BluetoothOppLauncherActivity.class);

        enableActivity(true);
        Intents.init();
    }

    @After
    public void tearDown() {
        BluetoothMethodProxy.setInstanceForTesting(null);
        Intents.release();
        enableActivity(false);
    }

    @Test
    public void onCreate_withNoAction_returnImmediately() throws Exception {
        ActivityScenario<BluetoothOppLauncherActivity> activityScenario = ActivityScenario.launch(
                mIntent);
        assertActivityState(activityScenario, Lifecycle.State.DESTROYED);
    }

    @Test
    public void onCreate_withActionSend_withoutMetadata_finishImmediately() throws Exception {
        mIntent.setAction(Intent.ACTION_SEND);
        ActivityScenario<BluetoothOppLauncherActivity> activityScenario = ActivityScenario.launch(
                mIntent);
        assertActivityState(activityScenario, Lifecycle.State.DESTROYED);
    }

    @Test
    public void onCreate_withActionSendMultiple_withoutMetadata_finishImmediately()
            throws Exception {
        mIntent.setAction(Intent.ACTION_SEND_MULTIPLE);
        ActivityScenario<BluetoothOppLauncherActivity> activityScenario = ActivityScenario.launch(
                mIntent);
        assertActivityState(activityScenario, Lifecycle.State.DESTROYED);
    }

    @Test
    public void onCreate_withActionOpen_sendBroadcast() throws Exception {
        mIntent.setAction(Constants.ACTION_OPEN);
        mIntent.setData(Uri.EMPTY);
        ActivityScenario.launch(mIntent);
        ArgumentCaptor<Intent> argument = ArgumentCaptor.forClass(Intent.class);

        verify(mMethodProxy).contextSendBroadcast(any(), argument.capture());

        assertThat(argument.getValue().getAction()).isEqualTo(Constants.ACTION_OPEN);
        assertThat(argument.getValue().getComponent().getClassName())
                .isEqualTo(BluetoothOppReceiver.class.getName());
        assertThat(argument.getValue().getData()).isEqualTo(Uri.EMPTY);
    }

    @Test
    public void launchDevicePicker_bluetoothNotEnabled_launchEnableActivity() throws Exception {
        doReturn(false).when(mMethodProxy).bluetoothAdapterIsEnabled(any());
        // Unsupported action, the activity will stay without being finished right the way
        mIntent.setAction("unsupported-action");
        ActivityScenario<BluetoothOppLauncherActivity> scenario = ActivityScenario.launch(mIntent);

        scenario.onActivity(BluetoothOppLauncherActivity::launchDevicePicker);

        onView(withText(mTargetContext.getText(R.string.bt_enable_cancel).toString())).inRoot(
                isDialog()).check(matches(isDisplayed())).perform(click());
        intended(hasComponent(BluetoothOppBtEnableActivity.class.getName()));
    }

    @Test
    public void launchDevicePicker_bluetoothEnabled_launchActivity() throws Exception {
        doReturn(true).when(mMethodProxy).bluetoothAdapterIsEnabled(any());
        // Unsupported action, the activity will stay without being finished right the way
        mIntent.setAction("unsupported-action");
        ActivityScenario<BluetoothOppLauncherActivity> scenario = ActivityScenario.launch(mIntent);

        scenario.onActivity(BluetoothOppLauncherActivity::launchDevicePicker);

        intended(hasAction(BluetoothDevicePicker.ACTION_LAUNCH));
    }

    @Test
    public void createFileForSharedContent_returnFile() throws Exception {
        doReturn(true).when(mMethodProxy).bluetoothAdapterIsEnabled(any());
        // Unsupported action, the activity will stay without being finished right the way
        mIntent.setAction("unsupported-action");
        ActivityScenario<BluetoothOppLauncherActivity> scenario = ActivityScenario.launch(mIntent);

        final Uri[] fileUri = new Uri[1];
        final String shareContent =
                "a string to trigger pattern match with url: www.google.com, phone number: "
                        + "+821023456798, and email: abc@test.com";
        scenario.onActivity(activity -> {
            fileUri[0] = activity.createFileForSharedContent(activity, shareContent);

        });
        assertThat(fileUri[0].toString().endsWith(".html")).isTrue();

        File file = new File(fileUri[0].getPath());
        // new file is in html format that include the shared content, so length should increase
        assertThat(file.length()).isGreaterThan(shareContent.length());
    }

    private void assertActivityState(ActivityScenario activityScenario, Lifecycle.State state)
            throws Exception {
        Thread.sleep(2_000);
        assertThat(activityScenario.getState()).isEqualTo(state);
    }


    private void enableActivity(boolean enable) {
        int enabledState = enable ? COMPONENT_ENABLED_STATE_ENABLED
                : COMPONENT_ENABLED_STATE_DEFAULT;

        mTargetContext.getPackageManager().setApplicationEnabledSetting(
                mTargetContext.getPackageName(), enabledState, DONT_KILL_APP);

        ComponentName activityName = new ComponentName(mTargetContext,
                BluetoothOppLauncherActivity.class);
        mTargetContext.getPackageManager().setComponentEnabledSetting(
                activityName, enabledState, DONT_KILL_APP);
    }
}
