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

package com.android.bluetooth.btservice.activityattribution;

import static java.util.Objects.requireNonNull;

import android.util.Log;

/**
 * Service used for attributes wakeup, wakelock and Bluetooth traffic into per-app and per-device
 * based activities.
 */
public class ActivityAttributionService {
    private static final String TAG = ActivityAttributionService.class.getSimpleName();

    private final ActivityAttributionNativeInterface mActivityAttributionNativeInterface =
            requireNonNull(
                    ActivityAttributionNativeInterface.getInstance(),
                    "ActivityAttributionNativeInterface cannot be null");

    /** Notify the UID and package name of the app, and the address of associated active device */
    public void notifyActivityAttributionInfo(int uid, String packageName, String deviceAddress) {
        Log.d(
                TAG,
                "notifyActivityAttributionInfo()"
                        + (" UID=" + uid)
                        + (" packageName=" + packageName)
                        + (" deviceAddress=" + deviceAddress));
        mActivityAttributionNativeInterface.notifyActivityAttributionInfo(
                uid, packageName, deviceAddress);
    }
}
