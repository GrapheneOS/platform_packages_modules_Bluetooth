/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.bluetooth.cts;

import static com.android.compatibility.common.util.SystemUtil.runShellCommandOrThrow;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.pm.PackageManager;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.BeforeAfterRule;

import org.junit.runner.Description;
import org.junit.runners.model.Statement;

/**
 * This is a test rule that, when used in a test, will enable Bluetooth before the test starts.
 * When the test is done, Bluetooth will be disabled if and only if it was disabled before the test
 * started.  If setTestMode is set to true, the Bluetooth scanner will return a hardcoded set of
 * Bluetooth scan results while the test runs .
 */
public class EnableBluetoothRule extends BeforeAfterRule {
    private final Context mContext = InstrumentationRegistry.getInstrumentation().getContext();
    private final BluetoothManager mBluetoothManager =
            mContext.getSystemService(BluetoothManager.class);
    private final BluetoothAdapter mBluetoothAdapter = mBluetoothManager.getAdapter();
    private final boolean mEnableTestMode;

    private boolean mWasBluetoothAdapterEnabled = true;

    public EnableBluetoothRule() {
        mEnableTestMode = false;
    }

    public EnableBluetoothRule(boolean enableTestMode) {
        mEnableTestMode = enableTestMode;
    }

    private boolean supportsBluetooth() {
        return mContext.getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH);
    }

    private boolean isBluetoothEnabled() {
        return mBluetoothAdapter.isEnabled();
    }

    private void enableBluetoothAdapter() {
        assertTrue(BTAdapterUtils.enableAdapter(mBluetoothAdapter, mContext));
    }

    private void disableBluetoothAdapter() {
        assertTrue(BTAdapterUtils.disableAdapter(mBluetoothAdapter, mContext));
    }

    private void enableBluetoothTestMode() {
        runShellCommandOrThrow("dumpsys activity service"
                + " com.android.bluetooth.btservice.AdapterService set-test-mode enabled");
    }

    private void disableBluetoothTestMode() {
        runShellCommandOrThrow("dumpsys activity service"
                + " com.android.bluetooth.btservice.AdapterService set-test-mode disabled");
    }

    @Override
    protected void onBefore(Statement base, Description description) {
        assumeTrue(supportsBluetooth());
        mWasBluetoothAdapterEnabled = isBluetoothEnabled();
        if (!mWasBluetoothAdapterEnabled) {
            enableBluetoothAdapter();
        }
        if (mEnableTestMode) {
            enableBluetoothTestMode();
        }
    }

    @Override
    protected void onAfter(Statement base, Description description) {
        assumeTrue(supportsBluetooth());
        disableBluetoothTestMode();
        if (!mWasBluetoothAdapterEnabled) {
            disableBluetoothAdapter();
        }
    }
}
