/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


package com.android.bluetooth.apm;

public class ApmConst {

    private static boolean leAudioEnabled = false;
    public static final String groupAddress = "9E:8B:00:00:00";

    public static boolean getLeAudioEnabled() {
        return leAudioEnabled;
    }

    protected static void setLeAudioEnabled(boolean leAudioSupport) {
        leAudioEnabled = leAudioSupport;
    }

    public static class AudioFeatures {

        public static final int CALL_AUDIO = 0;
        public static final int MEDIA_AUDIO = 1;
        public static final int CALL_CONTROL = 2;
        public static final int MEDIA_CONTROL = 3;
        public static final int MEDIA_VOLUME_CONTROL = 4;
        public static final int CALL_VOLUME_CONTROL = 5;
        public static final int BROADCAST_AUDIO = 6;
        public static final int HEARING_AID = 7;
        public static final int MAX_AUDIO_FEATURES = 8;

    }

    public static class AudioProfiles {

        public static final int NONE            = 0x0000;
        public static final int A2DP            = 0x0001;
        public static final int HFP             = 0x0002;
        public static final int AVRCP           = 0x0004;
        public static final int TMAP_MEDIA      = 0x0008;
        public static final int BAP_MEDIA       = 0x0010;
        public static final int MCP             = 0x0020;
        public static final int CCP             = 0x0040;
        public static final int VCP             = 0x0080;
        public static final int HAP_BREDR       = 0x0100;
        public static final int HAP_LE          = 0x0200;
        public static final int BROADCAST_BREDR = 0x0400;
        public static final int BROADCAST_LE    = 0x0800;
        public static final int TMAP_CALL       = 0x1000;
        public static final int BAP_CALL        = 0x2000;
        public static final int BAP_GCP         = 0x4000;
        public static final int BAP_RECORDING   = 0x8000;

    }
}
