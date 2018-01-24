/*
 * Copyright 2017 The Android Open Source Project
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

package com.android.bluetooth.hfp;

import android.bluetooth.BluetoothDevice;

import java.util.Objects;

/**
 * Callback events from native layer
 */
public class HeadsetStackEvent {
    public static final int EVENT_TYPE_NONE = 0;
    public static final int EVENT_TYPE_CONNECTION_STATE_CHANGED = 1;
    public static final int EVENT_TYPE_AUDIO_STATE_CHANGED = 2;
    public static final int EVENT_TYPE_VR_STATE_CHANGED = 3;
    public static final int EVENT_TYPE_ANSWER_CALL = 4;
    public static final int EVENT_TYPE_HANGUP_CALL = 5;
    public static final int EVENT_TYPE_VOLUME_CHANGED = 6;
    public static final int EVENT_TYPE_DIAL_CALL = 7;
    public static final int EVENT_TYPE_SEND_DTMF = 8;
    public static final int EVENT_TYPE_NOICE_REDUCTION = 9;
    public static final int EVENT_TYPE_AT_CHLD = 10;
    public static final int EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST = 11;
    public static final int EVENT_TYPE_AT_CIND = 12;
    public static final int EVENT_TYPE_AT_COPS = 13;
    public static final int EVENT_TYPE_AT_CLCC = 14;
    public static final int EVENT_TYPE_UNKNOWN_AT = 15;
    public static final int EVENT_TYPE_KEY_PRESSED = 16;
    public static final int EVENT_TYPE_WBS = 17;
    public static final int EVENT_TYPE_BIND = 18;
    public static final int EVENT_TYPE_BIEV = 19;

    public int type = EVENT_TYPE_NONE;
    public int valueInt = 0;
    public int valueInt2 = 0;
    public String valueString = null;
    public BluetoothDevice device = null;

    /**
     * Create a headset stack event
     *
     * @param type type of the event
     * @param device device of interest
     */
    public HeadsetStackEvent(int type, BluetoothDevice device) {
        this.type = type;
        this.device = Objects.requireNonNull(device);
    }

    /**
     * Create a headset stack event
     *
     * @param type type of the event
     * @param valueInt an integer value in the event
     * @param device device of interest
     */
    public HeadsetStackEvent(int type, int valueInt, BluetoothDevice device) {
        this.type = type;
        this.valueInt = valueInt;
        this.device = Objects.requireNonNull(device);
    }

    /**
     * Create a headset stack event
     *
     * @param type type of the event
     * @param valueInt an integer value in the event
     * @param valueInt2 another integer value in the event
     * @param device device of interest
     */
    public HeadsetStackEvent(int type, int valueInt, int valueInt2, BluetoothDevice device) {
        this.type = type;
        this.valueInt = valueInt;
        this.valueInt2 = valueInt2;
        this.device = Objects.requireNonNull(device);
    }

    /**
     * Create a headset stack event
     *
     * @param type type of the event
     * @param valueString an integer value in the event
     * @param device device of interest
     */
    public HeadsetStackEvent(int type, String valueString, BluetoothDevice device) {
        this.type = type;
        this.valueString = valueString;
        this.device = Objects.requireNonNull(device);
    }

    /**
     * Get a string that represents this event
     *
     * @return String that represents this event
     */
    public String getTypeString() {
        String eventName = "UNKNOWN";
        switch (type) {
            case EVENT_TYPE_NONE:
                eventName = "EVENT_TYPE_NONE";
                break;
            case EVENT_TYPE_CONNECTION_STATE_CHANGED:
                eventName = "EVENT_TYPE_CONNECTION_STATE_CHANGED";
                break;
            case EVENT_TYPE_AUDIO_STATE_CHANGED:
                eventName = "EVENT_TYPE_AUDIO_STATE_CHANGED";
                break;
            case EVENT_TYPE_VR_STATE_CHANGED:
                eventName = "EVENT_TYPE_VR_STATE_CHANGED";
                break;
            case EVENT_TYPE_ANSWER_CALL:
                eventName = "EVENT_TYPE_ANSWER_CALL";
                break;
            case EVENT_TYPE_HANGUP_CALL:
                eventName = "EVENT_TYPE_HANGUP_CALL";
                break;
            case EVENT_TYPE_VOLUME_CHANGED:
                eventName = "EVENT_TYPE_VOLUME_CHANGED";
                break;
            case EVENT_TYPE_DIAL_CALL:
                eventName = "EVENT_TYPE_DIAL_CALL";
                break;
            case EVENT_TYPE_SEND_DTMF:
                eventName = "EVENT_TYPE_SEND_DTMF";
                break;
            case EVENT_TYPE_NOICE_REDUCTION:
                eventName = "EVENT_TYPE_NOICE_REDUCTION";
                break;
            case EVENT_TYPE_AT_CHLD:
                eventName = "EVENT_TYPE_AT_CHLD";
                break;
            case EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST:
                eventName = "EVENT_TYPE_SUBSCRIBER_NUMBER_REQUEST";
                break;
            case EVENT_TYPE_AT_CIND:
                eventName = "EVENT_TYPE_AT_CIND";
                break;
            case EVENT_TYPE_AT_COPS:
                eventName = "EVENT_TYPE_AT_COPS";
                break;
            case EVENT_TYPE_AT_CLCC:
                eventName = "EVENT_TYPE_AT_CLCC";
                break;
            case EVENT_TYPE_UNKNOWN_AT:
                eventName = "EVENT_TYPE_UNKNOWN_AT";
                break;
            case EVENT_TYPE_KEY_PRESSED:
                eventName = "EVENT_TYPE_KEY_PRESSED";
                break;
            case EVENT_TYPE_WBS:
                eventName = "EVENT_TYPE_WBS";
                break;
            case EVENT_TYPE_BIND:
                eventName = "EVENT_TYPE_BIND";
                break;
            case EVENT_TYPE_BIEV:
                eventName = "EVENT_TYPE_BIEV";
                break;
            // do nothing by default
        }
        return eventName;
    }

    @Override
    public String toString() {
        return String.format("%s[%d], valInt=%d, valInt2=%d, valString=%s, device=%s",
                getTypeString(), type, valueInt, valueInt2, valueString, device);
    }
}
