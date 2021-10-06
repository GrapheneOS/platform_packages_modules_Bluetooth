/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.bluetooth.hfpclient.connserv;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothHeadsetClientCall;
import android.os.Bundle;

import com.android.internal.annotations.VisibleForTesting;

import java.util.List;

/**
 * A mockable proxy class that facilitates testing of the {@code hfpclient.connserv} package.
 *
 * <p>This is necessary due to the "final" attribute of the BluetoothHeadsetClient class.
 */
public class BluetoothHeadsetClientProxy {

    private final BluetoothHeadsetClient mBluetoothHeadsetClient;

    private BluetoothHeadsetClientProxy(BluetoothHeadsetClient bluetoothHeadsetClient) {
        mBluetoothHeadsetClient = bluetoothHeadsetClient;
    }

    public BluetoothHeadsetClient getProxiedBluetoothHeadsetClient() {
        return mBluetoothHeadsetClient;
    }

    /** @see BluetoothHeadsetClient#dial(BluetoothDevice, String) */
    public BluetoothHeadsetClientCall dial(BluetoothDevice device, String number) {
        return mBluetoothHeadsetClient.dial(device, number);
    }

    /** @see BluetoothHeadsetClient#enterPrivateMode(BluetoothDevice, int) */
    public boolean enterPrivateMode(BluetoothDevice device, int index) {
        return mBluetoothHeadsetClient.enterPrivateMode(device, index);
    }

    /** @see BluetoothHeadsetClient#sendDTMF(BluetoothDevice, byte) */
    public boolean sendDTMF(BluetoothDevice device, byte code) {
        return mBluetoothHeadsetClient.sendDTMF(device, code);
    }

    /** @see BluetoothHeadsetClient#terminateCall(BluetoothDevice, BluetoothHeadsetClientCall) */
    public boolean terminateCall(BluetoothDevice device, BluetoothHeadsetClientCall call) {
        return mBluetoothHeadsetClient.terminateCall(device, call);
    }

    /** @see BluetoothHeadsetClient#holdCall(BluetoothDevice) */
    public boolean holdCall(BluetoothDevice device) {
        return mBluetoothHeadsetClient.holdCall(device);
    }

    /** @see BluetoothHeadsetClient#acceptCall(BluetoothDevice, int) */
    public boolean acceptCall(BluetoothDevice device, int flag) {
        return mBluetoothHeadsetClient.acceptCall(device, flag);
    }

    /** @see BluetoothHeadsetClient#rejectCall(BluetoothDevice) */
    public boolean rejectCall(BluetoothDevice device) {
        return mBluetoothHeadsetClient.rejectCall(device);
    }

    /** @see BluetoothHeadsetClient#connectAudio(BluetoothDevice) */
    public boolean connectAudio(BluetoothDevice device) {
        return mBluetoothHeadsetClient.connectAudio(device);
    }

    /** @see BluetoothHeadsetClient#disconnectAudio(BluetoothDevice) */
    public boolean disconnectAudio(BluetoothDevice device) {
        return mBluetoothHeadsetClient.disconnectAudio(device);
    }

    /** @see BluetoothHeadsetClient#getCurrentAgEvents(BluetoothDevice) */
    public Bundle getCurrentAgEvents(BluetoothDevice device) {
        return mBluetoothHeadsetClient.getCurrentAgEvents(device);
    }

    /** @see BluetoothHeadsetClient#getConnectedDevices() */
    public List<BluetoothDevice> getConnectedDevices() {
        return mBluetoothHeadsetClient.getConnectedDevices();
    }

    /** @see BluetoothHeadsetClient#getCurrentCalls(BluetoothDevice) */
    public List<BluetoothHeadsetClientCall> getCurrentCalls(BluetoothDevice device) {
        return mBluetoothHeadsetClient.getCurrentCalls(device);
    }

    /**
     * Factory class for {@link BluetoothHeadsetClientProxy}
     */
    public static class Factory {
        private static Factory sInstance = new Factory();

        @VisibleForTesting
        static void setInstance(Factory instance) {
            sInstance = instance;
        }

        /**
         * Returns an instance of {@link BluetoothHeadsetClientProxy}
         */
        public static BluetoothHeadsetClientProxy build(BluetoothHeadsetClient proxy) {
            return sInstance.buildInternal(proxy);
        }

        protected BluetoothHeadsetClientProxy buildInternal(BluetoothHeadsetClient proxy) {
            return  new BluetoothHeadsetClientProxy(proxy);
        }

    }
}
