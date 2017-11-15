/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.bluetooth.a2dp;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothA2dp;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.HandlerThread;
import android.os.ParcelUuid;
import android.provider.Settings;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.bluetooth.avrcp.Avrcp;
import com.android.bluetooth.btservice.ProfileService;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Provides Bluetooth A2DP profile, as a service in the Bluetooth application.
 * @hide
 */
public class A2dpService extends ProfileService {
    private static final boolean DBG = true;
    private static final String TAG = "A2dpService";

    private HandlerThread mStateMachinesThread = null;
    private A2dpStateMachine mStateMachine;
    private Avrcp mAvrcp;
    private A2dpNativeInterface mA2dpNativeInterface = null;

    private BroadcastReceiver mConnectionStateChangedReceiver = null;

    public A2dpService() {
        mA2dpNativeInterface = A2dpNativeInterface.getInstance();
    }

    private class CodecSupportReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            int state = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            if (state != BluetoothProfile.STATE_CONNECTED || device == null) {
                return;
            }
            // Each time a device connects, we want to re-check if it supports optional
            // codecs (perhaps it's had a firmware update, etc.) and save that state if
            // it differs from what we had saved before.
            int previousSupport = getSupportsOptionalCodecs(device);
            boolean supportsOptional = false;
            for (BluetoothCodecConfig config : mStateMachine.getCodecStatus()
                    .getCodecsSelectableCapabilities()) {
                if (!config.isMandatoryCodec()) {
                    supportsOptional = true;
                    break;
                }
            }
            if (previousSupport == BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN
                    || supportsOptional != (previousSupport
                    == BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED)) {
                setSupportsOptionalCodecs(device, supportsOptional);
            }
            if (supportsOptional) {
                int enabled = getOptionalCodecsEnabled(device);
                if (enabled == BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED) {
                    enableOptionalCodecs();
                } else if (enabled == BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED) {
                    disableOptionalCodecs();
                }
            }
        }
    }

    ;

    private static A2dpService sA2dpService;
    static final ParcelUuid[] A2DP_SOURCE_UUID = {
            BluetoothUuid.AudioSource
    };
    static final ParcelUuid[] A2DP_SOURCE_SINK_UUIDS = {
            BluetoothUuid.AudioSource, BluetoothUuid.AudioSink
    };

    @Override
    protected String getName() {
        return TAG;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothA2dpBinder(this);
    }

    @Override
    protected boolean start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }

        mStateMachinesThread = new HandlerThread("A2dpService.StateMachines");
        mStateMachinesThread.start();

        mAvrcp = Avrcp.make(this);
        mStateMachine = A2dpStateMachine.make(this, this, mA2dpNativeInterface,
                                              mStateMachinesThread.getLooper());
        setA2dpService(this);
        if (mConnectionStateChangedReceiver == null) {
            IntentFilter filter = new IntentFilter();
            filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
            mConnectionStateChangedReceiver = new CodecSupportReceiver();
            registerReceiver(mConnectionStateChangedReceiver, filter);
        }
        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }

        if (mStateMachine != null) {
            mStateMachine.doQuit();
        }
        if (mAvrcp != null) {
            mAvrcp.doQuit();
        }
        if (mStateMachinesThread != null) {
            mStateMachinesThread.quit();
            mStateMachinesThread = null;
        }
        return true;
    }

    @Override
    protected boolean cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }

        if (mConnectionStateChangedReceiver != null) {
            unregisterReceiver(mConnectionStateChangedReceiver);
            mConnectionStateChangedReceiver = null;
        }
        if (mStateMachine != null) {
            mStateMachine.cleanup();
            mStateMachine = null;
        }
        if (mAvrcp != null) {
            mAvrcp.cleanup();
            mAvrcp = null;
        }
        clearA2dpService();
        return true;
    }

    //API Methods

    public static synchronized A2dpService getA2dpService() {
        if (sA2dpService != null && sA2dpService.isAvailable()) {
            if (DBG) {
                Log.d(TAG, "getA2DPService(): returning " + sA2dpService);
            }
            return sA2dpService;
        }
        if (DBG) {
            if (sA2dpService == null) {
                Log.d(TAG, "getA2dpService(): service is NULL");
            } else if (!(sA2dpService.isAvailable())) {
                Log.d(TAG, "getA2dpService(): service is not available");
            }
        }
        return null;
    }

    private static synchronized void setA2dpService(A2dpService instance) {
        if (instance != null && instance.isAvailable()) {
            if (DBG) {
                Log.d(TAG, "setA2dpService(): set to: " + instance);
            }
            sA2dpService = instance;
        } else {
            if (DBG) {
                if (sA2dpService == null) {
                    Log.d(TAG, "setA2dpService(): service not available");
                } else if (!sA2dpService.isAvailable()) {
                    Log.d(TAG, "setA2dpService(): service is cleaning up");
                }
            }
        }
    }

    private static synchronized void clearA2dpService() {
        sA2dpService = null;
    }

    public boolean connect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "connect(): " + device);
        }

        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");

        if (getPriority(device) == BluetoothProfile.PRIORITY_OFF) {
            return false;
        }
        ParcelUuid[] featureUuids = device.getUuids();
        if ((BluetoothUuid.containsAnyUuid(featureUuids, A2DP_SOURCE_UUID))
                && !(BluetoothUuid.containsAllUuids(featureUuids, A2DP_SOURCE_SINK_UUIDS))) {
            Log.e(TAG, "Remote does not have A2dp Sink UUID");
            return false;
        }

        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState == BluetoothProfile.STATE_CONNECTED
                || connectionState == BluetoothProfile.STATE_CONNECTING) {
            return false;
        }

        mStateMachine.sendMessage(A2dpStateMachine.CONNECT, device);
        return true;
    }

    boolean disconnect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device);
        }

        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        int connectionState = mStateMachine.getConnectionState(device);
        if (connectionState != BluetoothProfile.STATE_CONNECTED
                && connectionState != BluetoothProfile.STATE_CONNECTING) {
            return false;
        }

        mStateMachine.sendMessage(A2dpStateMachine.DISCONNECT, device);
        return true;
    }

    public List<BluetoothDevice> getConnectedDevices() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getConnectedDevices();
    }

    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getDevicesMatchingConnectionStates(states);
    }

    public int getConnectionState(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        return mStateMachine.getConnectionState(device);
    }

    public boolean setPriority(BluetoothDevice device, int priority) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        Settings.Global.putInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpSinkPriorityKey(device.getAddress()), priority);
        if (DBG) {
            Log.d(TAG, "Saved priority " + device + " = " + priority);
        }
        return true;
    }

    public int getPriority(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        int priority = Settings.Global.getInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpSinkPriorityKey(device.getAddress()),
                BluetoothProfile.PRIORITY_UNDEFINED);
        return priority;
    }

    /* Absolute volume implementation */
    public boolean isAvrcpAbsoluteVolumeSupported() {
        return mAvrcp.isAbsoluteVolumeSupported();
    }

    public void adjustAvrcpAbsoluteVolume(int direction) {
        mAvrcp.adjustVolume(direction);
    }

    public void setAvrcpAbsoluteVolume(int volume) {
        mAvrcp.setAbsoluteVolume(volume);
    }

    public void setAvrcpAudioState(int state) {
        mAvrcp.setA2dpAudioState(state);
    }

    public void resetAvrcpBlacklist(BluetoothDevice device) {
        if (mAvrcp != null) {
            mAvrcp.resetBlackList(device.getAddress());
        }
    }

    synchronized boolean isA2dpPlaying(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (DBG) {
            Log.d(TAG, "isA2dpPlaying(" + device + ")");
        }
        return mStateMachine.isPlaying(device);
    }

    public BluetoothCodecStatus getCodecStatus() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (DBG) {
            Log.d(TAG, "getCodecStatus()");
        }
        return mStateMachine.getCodecStatus();
    }

    public void setCodecConfigPreference(BluetoothCodecConfig codecConfig) {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (DBG) {
            Log.d(TAG, "setCodecConfigPreference(): " + Objects.toString(codecConfig));
        }
        mStateMachine.setCodecConfigPreference(codecConfig);
    }

    public void enableOptionalCodecs() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (DBG) {
            Log.d(TAG, "enableOptionalCodecs()");
        }
        mStateMachine.enableOptionalCodecs();
    }

    public void disableOptionalCodecs() {
        enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        if (DBG) {
            Log.d(TAG, "disableOptionalCodecs()");
        }
        mStateMachine.disableOptionalCodecs();
    }

    public int getSupportsOptionalCodecs(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        int support = Settings.Global.getInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpSupportsOptionalCodecsKey(device.getAddress()),
                BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN);
        return support;
    }

    public void setSupportsOptionalCodecs(BluetoothDevice device, boolean doesSupport) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        int value = doesSupport ? BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED
                : BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED;
        Settings.Global.putInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpSupportsOptionalCodecsKey(device.getAddress()),
                value);
    }

    public int getOptionalCodecsEnabled(BluetoothDevice device) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        return Settings.Global.getInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpOptionalCodecsEnabledKey(device.getAddress()),
                BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN);
    }

    public void setOptionalCodecsEnabled(BluetoothDevice device, int value) {
        enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if (value != BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN
                && value != BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED
                && value != BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED) {
            Log.w(TAG, "Unexpected value passed to setOptionalCodecsEnabled:" + value);
            return;
        }
        Settings.Global.putInt(getContentResolver(),
                Settings.Global.getBluetoothA2dpOptionalCodecsEnabledKey(device.getAddress()),
                value);
    }

    // Handle messages from native (JNI) to Java
    void messageFromNative(A2dpStackEvent stackEvent) {
        mStateMachine.sendMessage(A2dpStateMachine.STACK_EVENT, stackEvent);
    }

    // Binder object: Must be static class or memory leak may occur
    private static class BluetoothA2dpBinder extends IBluetoothA2dp.Stub
            implements IProfileServiceBinder {
        private A2dpService mService;

        private A2dpService getService() {
            if (!Utils.checkCaller()) {
                Log.w(TAG, "A2dp call not allowed for non-active user");
                return null;
            }

            if (mService != null && mService.isAvailable()) {
                return mService;
            }
            return null;
        }

        BluetoothA2dpBinder(A2dpService svc) {
            mService = svc;
        }

        @Override
        public boolean cleanup() {
            mService = null;
            return true;
        }

        @Override
        public boolean connect(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return false;
            }
            return service.connect(device);
        }

        @Override
        public boolean disconnect(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return false;
            }
            return service.disconnect(device);
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            A2dpService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getConnectedDevices();
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            A2dpService service = getService();
            if (service == null) {
                return new ArrayList<BluetoothDevice>(0);
            }
            return service.getDevicesMatchingConnectionStates(states);
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return service.getConnectionState(device);
        }

        @Override
        public boolean setPriority(BluetoothDevice device, int priority) {
            A2dpService service = getService();
            if (service == null) {
                return false;
            }
            return service.setPriority(device, priority);
        }

        @Override
        public int getPriority(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return BluetoothProfile.PRIORITY_UNDEFINED;
            }
            return service.getPriority(device);
        }

        @Override
        public boolean isAvrcpAbsoluteVolumeSupported() {
            A2dpService service = getService();
            if (service == null) {
                return false;
            }
            return service.isAvrcpAbsoluteVolumeSupported();
        }

        @Override
        public void adjustAvrcpAbsoluteVolume(int direction) {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.adjustAvrcpAbsoluteVolume(direction);
        }

        @Override
        public void setAvrcpAbsoluteVolume(int volume) {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.setAvrcpAbsoluteVolume(volume);
        }

        @Override
        public boolean isA2dpPlaying(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return false;
            }
            return service.isA2dpPlaying(device);
        }

        @Override
        public BluetoothCodecStatus getCodecStatus() {
            A2dpService service = getService();
            if (service == null) {
                return null;
            }
            return service.getCodecStatus();
        }

        @Override
        public void setCodecConfigPreference(BluetoothCodecConfig codecConfig) {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.setCodecConfigPreference(codecConfig);
        }

        @Override
        public void enableOptionalCodecs() {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.enableOptionalCodecs();
        }

        @Override
        public void disableOptionalCodecs() {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.disableOptionalCodecs();
        }

        public int supportsOptionalCodecs(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN;
            }
            return service.getSupportsOptionalCodecs(device);
        }

        public int getOptionalCodecsEnabled(BluetoothDevice device) {
            A2dpService service = getService();
            if (service == null) {
                return BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN;
            }
            return service.getOptionalCodecsEnabled(device);
        }

        public void setOptionalCodecsEnabled(BluetoothDevice device, int value) {
            A2dpService service = getService();
            if (service == null) {
                return;
            }
            service.setOptionalCodecsEnabled(device, value);
        }
    }

    ;

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);
        if (mStateMachine != null) {
            mStateMachine.dump(sb);
        }
        if (mAvrcp != null) {
            mAvrcp.dump(sb);
        }
    }
}
