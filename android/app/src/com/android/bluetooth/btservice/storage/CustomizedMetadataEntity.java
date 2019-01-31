/*
 * Copyright 2019 The Android Open Source Project
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

package com.android.bluetooth.btservice.storage;

import androidx.room.Entity;

@Entity
class CustomizedMetadataEntity {
    public String manufacturer_name;
    public String model_name;
    public String software_version;
    public String hardware_version;
    public String companion_app;
    public String main_icon;
    public String is_unthethered_headset;
    public String unthethered_left_icon;
    public String unthethered_right_icon;
    public String unthethered_case_icon;
    public String unthethered_left_battery;
    public String unthethered_right_battery;
    public String unthethered_case_battery;
    public String unthethered_left_charging;
    public String unthethered_right_charging;
    public String unthethered_case_charging;
    public String enhanced_settings_ui_uri;
}
