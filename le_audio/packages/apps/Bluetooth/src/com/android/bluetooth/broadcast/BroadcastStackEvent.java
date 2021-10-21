/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

package com.android.bluetooth.broadcast;

import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothBroadcast;
/**
 * Stack event sent via a callback from JNI to Java, or generated.
 */
public class BroadcastStackEvent {
    // Event types for STACK_EVENT message (coming from native)
    private static final int EVENT_TYPE_NONE = 0;
    public static final int EVENT_TYPE_BROADCAST_STATE_CHANGED = 1;
    public static final int EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED = 2;
    public static final int EVENT_TYPE_ENC_KEY_GENERATED = 3;
    public static final int EVENT_TYPE_CODEC_CONFIG_CHANGED = 4;
    public static final int EVENT_TYPE_SETUP_BIG = 5;
    public static final int EVENT_TYPE_BROADCAST_ID_GENERATED = 6;

    public static final int STATE_IDLE = 0;
    public static final int STATE_CONFIGURED = 1;
    public static final int STATE_STREAMING = 2;

    public static final int STATE_STOPPED = 0;
    public static final int STATE_STARTED = 1;

    public int type = EVENT_TYPE_NONE;
    public int advHandle = 0;
    public int valueInt = 0;
    public int bigHandle = 0;
    public int NumBises = 0;
    public int[] BisHandles;
    public byte[] BroadcastId = new byte[3];
    public String key;
    public BluetoothCodecStatus codecStatus;

    BroadcastStackEvent(int type) {
        this.type = type;
    }

    @Override
    public String toString() {
        // event dump
        StringBuilder result = new StringBuilder();
        result.append("BroadcastStackEvent {type:" + eventTypeToString(type));
        result.append(", value1:" + eventTypeValueIntToString(type, valueInt));
        if (codecStatus != null) {
            result.append(", codecStatus:" + codecStatus);
        }
        result.append("}");
        return result.toString();
    }

    private static String eventTypeToString(int type) {
        switch (type) {
            case EVENT_TYPE_NONE:
                return "EVENT_TYPE_NONE";
            case EVENT_TYPE_BROADCAST_STATE_CHANGED:
                return "EVENT_TYPE_BROADCAST_STATE_CHANGED";
            case EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED:
                return "EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED";
            case EVENT_TYPE_ENC_KEY_GENERATED:
                return "EVENT_TYPE_ENC_KEY_GENERATED";
            case EVENT_TYPE_CODEC_CONFIG_CHANGED:
                return "EVENT_TYPE_CODEC_CONFIG_CHANGED";
            case EVENT_TYPE_SETUP_BIG:
                return "EVENT_TYPE_SETUP_BIG";
            default:
                return "EVENT_TYPE_UNKNOWN:" + type;
        }
    }

    private static String eventTypeValueIntToString(int type, int value) {
        switch (type) {
            case EVENT_TYPE_BROADCAST_STATE_CHANGED:
                switch (value) {
                    case BluetoothBroadcast.STATE_DISABLED:
                        return "DISABLED";
                    case BluetoothBroadcast.STATE_ENABLING:
                        return "ENABLING";
                    case BluetoothBroadcast.STATE_ENABLED:
                        return "CONFIGURED";
                    case BluetoothBroadcast.STATE_STREAMING:
                        return "STREAMING";
                    default:
                        break;
                }
                break;
            case EVENT_TYPE_BROADCAST_AUDIO_STATE_CHANGED:
                switch(value) {
                  case BluetoothBroadcast.STATE_PLAYING:
                      return "PLAYING";
                  case BluetoothBroadcast.STATE_NOT_PLAYING:
                      return "NOT PLAYING";
                  default:
                      break;
                }
            default:
                break;
        }
        return Integer.toString(value);
    }
}

