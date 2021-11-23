/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
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

import java.util.SortedSet;
import java.util.TreeSet;

/**
 * This class keeps Content Control Ids for LE Audio profiles.
 */
public class ContentControlIdKeeper {

    public static final int CCID_INVALID = 0;
    public static final int CCID_MIN = 0x01;
    public static final int CCID_MAX = 0xFF;

    private static SortedSet<Integer> sAssignedCcidList = new TreeSet();

    public static synchronized int acquireCcid() {
        int ccid = CCID_INVALID;

        if (sAssignedCcidList.size() == 0) {
            ccid = CCID_MIN;
        } else if (sAssignedCcidList.last() < CCID_MAX) {
            ccid = sAssignedCcidList.last() + 1;
        } else if (sAssignedCcidList.first() > CCID_MIN) {
            ccid = sAssignedCcidList.first() - 1;
        } else {
            int first_ccid_avail = sAssignedCcidList.first() + 1;
            while (first_ccid_avail < CCID_MAX - 1) {
                if (!sAssignedCcidList.contains(first_ccid_avail)) {
                    ccid = first_ccid_avail;
                    break;
                }
                first_ccid_avail++;
            }
        }

        if (ccid != CCID_INVALID) sAssignedCcidList.add(ccid);
        return ccid;
    }

    public static synchronized void releaseCcid(int value) {
        sAssignedCcidList.remove(value);
    }
}
