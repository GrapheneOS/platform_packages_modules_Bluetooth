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

package com.android.bluetooth.gatt;

import com.android.internal.annotations.VisibleForTesting;

/**
 * Distance Measurement Native Interface to/from JNI.
 *
 * @hide
 */
@VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
public class DistanceMeasurementNativeInterface {
    private static DistanceMeasurementNativeInterface sInterface;
    private static final Object INSTANCE_LOCK = new Object();
    private DistanceMeasurementManager mDistanceMeasurementManager;

    private DistanceMeasurementNativeInterface() {}

    /**
     * This class is a singleton because native library should only be loaded once
     *
     * @return default instance
     */
    public static DistanceMeasurementNativeInterface getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInterface == null) {
                sInterface = new DistanceMeasurementNativeInterface();
            }
        }
        return sInterface;
    }

    void init(DistanceMeasurementManager manager) {
        mDistanceMeasurementManager = manager;
        initializeNative();
    }

    void cleanup() {
        cleanupNative();
    }

    void startDistanceMeasurement(String address, int frequency, int method) {
        startDistanceMeasurementNative(address, frequency, method);
    }

    void stopDistanceMeasurement(String address, int method) {
        stopDistanceMeasurementNative(address, method);
    }

    void onDistanceMeasurementStarted(String address, int method) {
        mDistanceMeasurementManager.onDistanceMeasurementStarted(address, method);
    }

    void onDistanceMeasurementStartFail(String address, int reason, int method) {
        mDistanceMeasurementManager.onDistanceMeasurementStartFail(address, reason, method);
    }

    void onDistanceMeasurementStopped(String address, int reason, int method) {
        mDistanceMeasurementManager.onDistanceMeasurementStopped(address, reason, method);
    }

    void onDistanceMeasurementResult(String address, int centimeter, int errorCentimeter,
            int azimuthAngle, int errorAzimuthAngle, int altitudeAngle, int errorAltitudeAngle,
            int method) {
        mDistanceMeasurementManager.onDistanceMeasurementResult(address, centimeter,
                errorCentimeter, azimuthAngle, errorAzimuthAngle, altitudeAngle, errorAltitudeAngle,
                method);
    }

    static {
        classInitNative();
    }

    private static native void classInitNative();

    private native void initializeNative();

    private native void cleanupNative();

    private native void startDistanceMeasurementNative(String address, int frequency, int method);

    private native void stopDistanceMeasurementNative(String address, int method);
}
