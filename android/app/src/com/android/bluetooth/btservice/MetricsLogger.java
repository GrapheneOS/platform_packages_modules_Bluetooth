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
package com.android.bluetooth.btservice;

import android.app.AlarmManager;
import android.content.Context;
import android.os.SystemClock;
import android.util.Log;

import com.android.bluetooth.BluetoothMetricsProto.BluetoothLog;
import com.android.bluetooth.BluetoothMetricsProto.ProfileConnectionStats;
import com.android.bluetooth.BluetoothMetricsProto.ProfileId;
import com.android.bluetooth.BluetoothStatsLog;

import java.util.HashMap;

/**
 * Class of Bluetooth Metrics
 */
public class MetricsLogger {
    private static final String TAG = "BluetoothMetricsLogger";

    public static final boolean DEBUG = false;

    // 6 hours timeout for counter metrics
    private static final long BLUETOOTH_COUNTER_METRICS_ACTION_DURATION_MILLIS = 6L * 3600L * 1000L;

    private static final HashMap<ProfileId, Integer> sProfileConnectionCounts = new HashMap<>();

    HashMap<Integer, Long> mCounters = new HashMap<>();
    private static MetricsLogger sInstance = null;
    private Context mContext = null;
    private AlarmManager mAlarmManager = null;
    private boolean mInitialized = false;
    static final private Object mLock = new Object();

    private AlarmManager.OnAlarmListener mOnAlarmListener = new AlarmManager.OnAlarmListener () {
        @Override
        public void onAlarm() {
            drainBufferedCounters();
            scheduleDrains();
        }
    };

    public static MetricsLogger getInstance() {
        if (sInstance == null) {
            synchronized (mLock) {
                if (sInstance == null) {
                    sInstance = new MetricsLogger();
                }
            }
        }
        return sInstance;
    }

    public boolean isInitialized() {
        return mInitialized;
    }

    public boolean init(Context context) {
        if (mInitialized) {
            return false;
        }
        mInitialized = true;
        mContext = context;
        scheduleDrains();
        return true;
    }

    public boolean cacheCount(int key, long count) {
        if (!mInitialized) {
            Log.w(TAG, "MetricsLogger isn't initialized");
            return false;
        }
        if (count <= 0) {
            Log.w(TAG, "count is not larger than 0. count: " + count + " key: " + key);
            return false;
        }
        long total = 0;

        synchronized (mLock) {
            if (mCounters.containsKey(key)) {
                total = mCounters.get(key);
            }
            if (Long.MAX_VALUE - total < count) {
                Log.w(TAG, "count overflows. count: " + count + " current total: " + total);
                mCounters.put(key, Long.MAX_VALUE);
                return false;
            }
            mCounters.put(key, total + count);
        }
        return true;
    }

    /**
     * Log profile connection event by incrementing an internal counter for that profile.
     * This log persists over adapter enable/disable and only get cleared when metrics are
     * dumped or when Bluetooth process is killed.
     *
     * @param profileId Bluetooth profile that is connected at this event
     */
    public static void logProfileConnectionEvent(ProfileId profileId) {
        synchronized (sProfileConnectionCounts) {
            sProfileConnectionCounts.merge(profileId, 1, Integer::sum);
        }
    }

    /**
     * Dump collected metrics into proto using a builder.
     * Clean up internal data after the dump.
     *
     * @param metricsBuilder proto builder for {@link BluetoothLog}
     */
    public static void dumpProto(BluetoothLog.Builder metricsBuilder) {
        synchronized (sProfileConnectionCounts) {
            sProfileConnectionCounts.forEach(
                    (key, value) -> metricsBuilder.addProfileConnectionStats(
                            ProfileConnectionStats.newBuilder()
                                    .setProfileId(key)
                                    .setNumTimesConnected(value)
                                    .build()));
            sProfileConnectionCounts.clear();
        }
    }

    protected void scheduleDrains() {
        Log.i(TAG, "setCounterMetricsAlarm()");
        if (mAlarmManager == null) {
            mAlarmManager = mContext.getSystemService(AlarmManager.class);
        }
        mAlarmManager.set(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + BLUETOOTH_COUNTER_METRICS_ACTION_DURATION_MILLIS,
                TAG,
                mOnAlarmListener,
                null);
    }

    public boolean count(int key, long count) {
        if (!mInitialized) {
            Log.w(TAG, "MetricsLogger isn't initialized");
            return false;
        }
        if (count <= 0) {
            Log.w(TAG, "count is not larger than 0. count: " + count + " key: " + key);
            return false;
        }
        BluetoothStatsLog.write(
                BluetoothStatsLog.BLUETOOTH_CODE_PATH_COUNTER, key, count);
        return true;
    }

    protected void drainBufferedCounters() {
        Log.i(TAG, "drainBufferedCounters().");
        synchronized (mLock) {
            // send mCounters to statsd
            for (int key : mCounters.keySet()) {
                count(key, mCounters.get(key));
            }
            mCounters.clear();
        }
    }

    public boolean close() {
        if (!mInitialized) {
            return false;
        }
        if (DEBUG) {
            Log.d(TAG, "close()");
        }
        cancelPendingDrain();
        drainBufferedCounters();
        mAlarmManager = null;
        mContext = null;
        mInitialized = false;
        return true;
    }
    protected void cancelPendingDrain() {
        mAlarmManager.cancel(mOnAlarmListener);
    }
}
