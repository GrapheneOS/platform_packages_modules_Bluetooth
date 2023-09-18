/*
 * Copyright 2023 The Android Open Source Project
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

package com.android.bluetooth;

import android.provider.DeviceConfig;

/**
 * Device config flags for Bluetooth app.
 *
 * @hide
 */
// TODO: Use aconfig flag when available
public final class Flags {
    /** A flag for centralizing audio routing of Bluetooth module. (b/299023147) */
    public static boolean audioRoutingCentralization() {
        return DeviceConfig.getBoolean(
                DeviceConfig.NAMESPACE_BLUETOOTH,
                "com.android.bluetooth.audio_routing_centalization",
                false);
    }
}
