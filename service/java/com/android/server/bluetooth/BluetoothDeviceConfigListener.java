/*
 * Copyright 2020 The Android Open Source Project
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

package com.android.server.bluetooth;

import static com.android.server.bluetooth.BluetoothAirplaneModeListener.APM_ENHANCEMENT;
import static com.android.server.bluetooth.BluetoothAirplaneModeListener.BT_DEFAULT_APM_STATE;

import android.content.Context;
import android.provider.DeviceConfig;
import android.provider.Settings;
import android.util.Log;

import java.util.ArrayList;

/**
 * The BluetoothDeviceConfigListener handles system device config change callback and checks
 * whether we need to inform BluetoothManagerService on this change.
 *
 * The information of device config change would not be passed to the BluetoothManagerService
 * when Bluetooth is on and Bluetooth is in one of the following situations:
 *   1. Bluetooth A2DP is connected.
 *   2. Bluetooth Hearing Aid profile is connected.
 */
public class BluetoothDeviceConfigListener {
    private static final String TAG = "BluetoothDeviceConfigListener";

    private final BluetoothManagerService mService;
    private final boolean mLogDebug;
    private final Context mContext;
    private static final int DEFAULT_APM_ENHANCEMENT = 0;
    private static final int DEFAULT_BT_APM_STATE = 0;

    private boolean mPrevApmEnhancement;
    private boolean mPrevBtApmState;

    BluetoothDeviceConfigListener(BluetoothManagerService service, boolean logDebug,
            Context context) {
        mService = service;
        mLogDebug = logDebug;
        mContext = context;
        mPrevApmEnhancement = Settings.Global.getInt(mContext.getContentResolver(),
                APM_ENHANCEMENT, DEFAULT_APM_ENHANCEMENT) == 1;
        mPrevBtApmState = Settings.Global.getInt(mContext.getContentResolver(),
                BT_DEFAULT_APM_STATE, DEFAULT_BT_APM_STATE) == 1;
        DeviceConfig.addOnPropertiesChangedListener(
                DeviceConfig.NAMESPACE_BLUETOOTH,
                (Runnable r) -> r.run(),
                mDeviceConfigChangedListener);
    }

    private final DeviceConfig.OnPropertiesChangedListener mDeviceConfigChangedListener =
            new DeviceConfig.OnPropertiesChangedListener() {
                @Override
                public void onPropertiesChanged(DeviceConfig.Properties properties) {
                    if (!properties.getNamespace().equals(DeviceConfig.NAMESPACE_BLUETOOTH)) {
                        return;
                    }
                    if (mLogDebug) {
                        ArrayList<String> flags = new ArrayList<>();
                        for (String name : properties.getKeyset()) {
                            flags.add(name + "='" + properties.getString(name, "") + "'");
                        }
                        Log.d(TAG, "onPropertiesChanged: " + String.join(",", flags));
                    }

                    boolean apmEnhancement = properties.getBoolean(
                            APM_ENHANCEMENT, mPrevApmEnhancement);
                    if (apmEnhancement != mPrevApmEnhancement) {
                        mPrevApmEnhancement = apmEnhancement;
                        Settings.Global.putInt(mContext.getContentResolver(),
                                APM_ENHANCEMENT, apmEnhancement ? 1 : 0);
                    }

                    boolean btApmState = properties.getBoolean(
                            BT_DEFAULT_APM_STATE, mPrevBtApmState);
                    if (btApmState != mPrevBtApmState) {
                        mPrevBtApmState = btApmState;
                        Settings.Global.putInt(mContext.getContentResolver(),
                                BT_DEFAULT_APM_STATE, btApmState ? 1 : 0);
                    }
                    boolean foundInit = false;
                    for (String name : properties.getKeyset()) {
                        if (name.startsWith("INIT_")) {
                            foundInit = true;
                            break;
                        }
                    }
                    if (!foundInit) {
                        return;
                    }
                    mService.onInitFlagsChanged();
                }
            };
}
