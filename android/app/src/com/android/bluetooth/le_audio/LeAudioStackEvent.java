/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package com.android.bluetooth.le_audio;

import android.bluetooth.BluetoothDevice;

/**
 * Stack event sent via a callback from JNI to Java, or generated
 * internally by the LeAudio State Machine.
 */
public class LeAudioStackEvent {
    // Event types for STACK_EVENT message (coming from native in bt_le_audio.h)
    private static final int EVENT_TYPE_NONE = 0;
    public static final int EVENT_TYPE_CONNECTION_STATE_CHANGED = 1;
    public static final int EVENT_TYPE_GROUP_STATUS_CHANGED = 2;
    public static final int EVENT_TYPE_GROUP_NODE_STATUS_CHANGED = 3;
    public static final int EVENT_TYPE_AUDIO_CONF_CHANGED = 4;
        // -------- DO NOT PUT ANY NEW UNICAST EVENTS BELOW THIS LINE-------------
    public static final int EVENT_TYPE_UNICAST_MAX = 5;

    // Broadcast related events
    public static final int EVENT_TYPE_BROADCAST_CREATED = EVENT_TYPE_UNICAST_MAX + 1;
    public static final int EVENT_TYPE_BROADCAST_DESTROYED = EVENT_TYPE_UNICAST_MAX + 2;
    public static final int EVENT_TYPE_BROADCAST_STATE = EVENT_TYPE_UNICAST_MAX + 3;
    public static final int EVENT_TYPE_BROADCAST_ID = EVENT_TYPE_UNICAST_MAX + 4;

    // Do not modify without updating the HAL bt_le_audio.h files.
    // Match up with GroupStatus enum of bt_le_audio.h
    static final int CONNECTION_STATE_DISCONNECTED = 0;
    static final int CONNECTION_STATE_CONNECTING = 1;
    static final int CONNECTION_STATE_CONNECTED = 2;
    static final int CONNECTION_STATE_DISCONNECTING = 3;

    static final int GROUP_STATUS_INACTIVE = 0;
    static final int GROUP_STATUS_ACTIVE = 1;

    static final int GROUP_NODE_ADDED = 1;
    static final int GROUP_NODE_REMOVED = 2;

    // Do not modify without updating the HAL bt_le_audio.h files.
    // Match up with BroadcastState enum of bt_le_audio.h
    static final int BROADCAST_STATE_STOPPED = 0;
    static final int BROADCAST_STATE_CONFIGURING = 1;
    static final int BROADCAST_STATE_PAUSED = 2;
    static final int BROADCAST_STATE_STOPPING = 3;
    static final int BROADCAST_STATE_STREAMING = 4;

    public int type = EVENT_TYPE_NONE;
    public BluetoothDevice device;
    public int valueInt1 = 0;
    public int valueInt2 = 0;
    public int valueInt3 = 0;
    public int valueInt4 = 0;
    public int valueInt5 = 0;
    public boolean valueBool1 = false;
    public byte[] valueByte1;

    LeAudioStackEvent(int type) {
        this.type = type;
    }

    @Override
    public String toString() {
        // event dump
        StringBuilder result = new StringBuilder();
        result.append("LeAudioStackEvent {type:" + eventTypeToString(type));
        result.append(", device:" + device);
        result.append(", value1:" + eventTypeValue1ToString(type, valueInt1));
        result.append(", value2:" + eventTypeValue2ToString(type, valueInt2));
        result.append(", value3:" + eventTypeValue3ToString(type, valueInt3));
        result.append(", value4:" + eventTypeValue4ToString(type, valueInt4));
        result.append(", value5:" + eventTypeValue5ToString(type, valueInt5));
        result.append(", valueBool1:" + eventTypeValueBool1ToString(type, valueBool1));
        result.append(", " + eventTypeValueByte1ToString(type, valueByte1));
        result.append("}");
        return result.toString();
    }

    private static String eventTypeToString(int type) {
        switch (type) {
            case EVENT_TYPE_NONE:
                return "EVENT_TYPE_NONE";
            case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                return "EVENT_TYPE_CONNECTION_STATE_CHANGED";
            case EVENT_TYPE_GROUP_STATUS_CHANGED:
                return "EVENT_TYPE_GROUP_STATUS_CHANGED";
            case EVENT_TYPE_GROUP_NODE_STATUS_CHANGED:
                return "EVENT_TYPE_GROUP_NODE_STATUS_CHANGED";
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                return "EVENT_TYPE_AUDIO_CONF_CHANGED";
            case EVENT_TYPE_BROADCAST_CREATED:
                return "EVENT_TYPE_BROADCAST_CREATED";
            case EVENT_TYPE_BROADCAST_DESTROYED:
                return "EVENT_TYPE_BROADCAST_DESTROYED";
            case EVENT_TYPE_BROADCAST_STATE:
                return "EVENT_TYPE_BROADCAST_STATE";
            case EVENT_TYPE_BROADCAST_ID:
                return "EVENT_TYPE_BROADCAST_ID";
            default:
                return "EVENT_TYPE_UNKNOWN:" + type;
        }
    }

    private static String eventTypeValue1ToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                switch (value) {
                    case CONNECTION_STATE_DISCONNECTED:
                        return  "CONNECTION_STATE_DISCONNECTED";
                    case CONNECTION_STATE_CONNECTING:
                        return  "CONNECTION_STATE_CONNECTING";
                    case CONNECTION_STATE_CONNECTED:
                        return  "CONNECTION_STATE_CONNECTED";
                    case CONNECTION_STATE_DISCONNECTING:
                        return  "CONNECTION_STATE_DISCONNECTING";
                    default:
                        return "UNKNOWN";
                }
            case EVENT_TYPE_GROUP_NODE_STATUS_CHANGED:
                // same as EVENT_TYPE_GROUP_STATUS_CHANGED
            case EVENT_TYPE_GROUP_STATUS_CHANGED:
                return "{group_id:" + Integer.toString(value) + "}";
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                // FIXME: It should have proper direction names here
                return "{direction:" + value + "}";
            case EVENT_TYPE_BROADCAST_CREATED:
                return "{instance_id:" + value + "}";
            case EVENT_TYPE_BROADCAST_DESTROYED:
                return "{instance_id:" + value + "}";
            case EVENT_TYPE_BROADCAST_STATE:
                return "{instance_id:" + value + "}";
            case EVENT_TYPE_BROADCAST_ID:
                return "{instance_id:" + value + "}";
            default:
                break;
        }
        return Integer.toString(value);
    }

    private static String eventTypeValue2ToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_GROUP_STATUS_CHANGED:
                switch (value) {
                    case GROUP_STATUS_ACTIVE:
                        return "GROUP_STATUS_ACTIVE";
                    case GROUP_STATUS_INACTIVE:
                        return "GROUP_STATUS_INACTIVE";
                    default:
                        break;
                }
                break;
            case EVENT_TYPE_GROUP_NODE_STATUS_CHANGED:
                switch (value) {
                    case GROUP_NODE_ADDED:
                        return "GROUP_NODE_ADDED";
                    case GROUP_NODE_REMOVED:
                        return "GROUP_NODE_REMOVED";
                    default:
                        return "UNKNOWN";
                }
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                return "{group_id:" + Integer.toString(value) + "}";
            case EVENT_TYPE_BROADCAST_STATE:
                return "{state:" + broadcastStateToString(value) + "}";
            case EVENT_TYPE_BROADCAST_ID:
                return "{addr_type:" + addrTypeToString(value) + "}";
            default:
                break;
        }
        return Integer.toString(value);
    }

    private static String eventTypeValue3ToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                // FIXME: It should have proper location names here
                return "{snk_audio_loc:" + value + "}";
            default:
                break;
        }
        return Integer.toString(value);
    }

    private static String eventTypeValue4ToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                // FIXME: It should have proper location names here
                return "{src_audio_loc:" + value + "}";
            default:
                break;
        }
        return Integer.toString(value);
    }

    private static String eventTypeValue5ToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_AUDIO_CONF_CHANGED:
                return "{available_contexts:" + Integer.toBinaryString(value) + "}";
            default:
                break;
        }
        return Integer.toString(value);
    }

    private static String eventTypeValueByte1ToString(int type, byte[] value) {
        switch (type) {
            case EVENT_TYPE_BROADCAST_ID:
                if (value == null) {
                    return "empty";
                }
                return "broadcast_id: [" + encodeHexString(value) + "]";
            default:
                return "<unused>";
        }
    }

    private static String eventTypeValueBool1ToString(int type, boolean value) {
        switch (type) {
            case EVENT_TYPE_BROADCAST_CREATED:
                return "{success:" + value + "}";
            default:
                return "<unused>";
        }
    }

    private static String broadcastStateToString(int state) {
        switch (state) {
            case BROADCAST_STATE_STOPPED:
                return "BROADCAST_STATE_STOPPED";
            case BROADCAST_STATE_CONFIGURING:
                return "BROADCAST_STATE_CONFIGURING";
            case BROADCAST_STATE_PAUSED:
                return "BROADCAST_STATE_PAUSED";
            case BROADCAST_STATE_STOPPING:
                return "BROADCAST_STATE_STOPPING";
            case BROADCAST_STATE_STREAMING:
                return "BROADCAST_STATE_STREAMING";
            default:
                return "UNKNOWN";
        }
    }

    private static String addrTypeToString(int value) {
        switch (value) {
            case 0:
                return "Static";
            case 1:
                return "Random";
            default:
                return "Unknown {" + value + "}";
        }
    }

    protected static String encodeHexString(byte[] pduData) {
        StringBuilder out = new StringBuilder(pduData.length * 2);
        for (int i = 0; i < pduData.length; i++) {
            // MS-nibble first
            out.append(Integer.toString((pduData[i] >> 4) & 0x0f, 16));
            out.append(Integer.toString(pduData[i] & 0x0f, 16));
        }
        return out.toString();
    }
}
