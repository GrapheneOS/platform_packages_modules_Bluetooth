/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
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

package com.android.bluetooth.pc;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothCodecConfig;


/**
 * Stack event sent via a callback from JNI to Java, or generated
 * internally by the Pacs Cleint State Machine.
 */
public class PacsClientStackEvent {
    // Event types for STACK_EVENT message (coming from native)
    private static final int EVENT_TYPE_NONE = 0;
    public static final int EVENT_TYPE_INITIALIZED = 1;
    public static final int EVENT_TYPE_CONNECTION_STATE_CHANGED = 2;
    public static final int EVENT_TYPE_SERVICE_DISCOVERY = 3;
    public static final int EVENT_TYPE_AUDIO_CONTEXT_AVAIL = 4;

    // Do not modify without updating the HAL bt_pacs_client.h files.
    // Match up with enum class ConnectionState of bt_pacs_client.h.
    static final int CONNECTION_STATE_DISCONNECTED = 0;
    static final int CONNECTION_STATE_CONNECTING = 1;
    static final int CONNECTION_STATE_CONNECTED = 2;
    static final int CONNECTION_STATE_DISCONNECTING = 3;

    public int type;
    public BluetoothDevice device;
    public BluetoothCodecConfig[] sinkCodecConfig;
    public BluetoothCodecConfig[] srcCodecConfig;
    public int valueInt1;
    public int valueInt2;
    public int valueInt3;
    public int valueInt4;

    PacsClientStackEvent(int type) {
        this.type = type;
    }

    @Override
    public String toString() {
        // event dump
        StringBuilder result = new StringBuilder();
        result.append("PacsClientStackEvent {type:" + eventTypeToString(type));
        result.append(", device:" + device);
        result.append(", value1:" + valueInt1);
        result.append(", value2:" + valueInt2);
        result.append(", value3:" + valueInt3);
        result.append(", value4:" + valueInt4);
        if (sinkCodecConfig != null) {
            result.append(", sinkCodecConfig:" + sinkCodecConfig);
        }
        if (srcCodecConfig != null) {
            result.append(", srcCodecConfig:" + srcCodecConfig);
        }
        result.append("}");
        return result.toString();
    }

    private static String eventTypeToString(int type) {
        switch (type) {
            case EVENT_TYPE_NONE:
                return "EVENT_TYPE_NONE";
            case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                return "EVENT_TYPE_CONNECTION_STATE_CHANGED";
            case EVENT_TYPE_INITIALIZED:
                return "EVENT_TYPE_INITIALIZED";
            case EVENT_TYPE_AUDIO_CONTEXT_AVAIL:
                return "EVENT_TYPE_AUDIO_CONTEXT_AVAIL";
            case EVENT_TYPE_SERVICE_DISCOVERY:
                return "EVENT_TYPE_SERVICE_DISCOVERY";
            default:
                return "EVENT_TYPE_UNKNOWN:" + type;
        }
    }
}
