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

package com.android.settings.bluetooth;

import androidx.preference.Preference;

/**
 * Callback to add or remove {@link Preference} in Ble broadcast source info
 * entries.
 */
public interface BleBroadcastSourceInfoPreferenceCallback {
    /**
     * Called when a Ble broadcast sourc Information is added
     * @param preference present the device
     */
    void onBroadcastSourceInfoAdded(Preference preference);

    /**
     * Called when a Ble broadast source Information is removed
     * @param preference present the device
     */
    void onBroadcastSourceInfoRemoved(Preference preference);
}
