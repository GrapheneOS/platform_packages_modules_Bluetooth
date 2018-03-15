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

package com.android.bluetooth.avrcp;

/**
 * Carries the playback status information in a custom object.
 */
// TODO(apanicke): Send the current active song ID along with this object so that all information
// is carried by our custom types.
class PlayStatus {
    static final byte STOPPED = 0;
    static final byte PLAYING = 1;
    static final byte PAUSED = 2;
    static final byte FWD_SEEK = 3;
    static final byte REV_SEEK = 4;
    static final byte ERROR = -1;

    public long position = 0xFFFFFFFFFFFFFFFFL;
    public long duration = 0x00L;
    public byte state = STOPPED;
}
