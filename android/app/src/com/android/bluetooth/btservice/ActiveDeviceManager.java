/*
 * Copyright (C) 2018 The Android Open Source Project
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

import android.annotation.RequiresPermission;
import android.annotation.SuppressLint;
import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHapClient;
import android.bluetooth.BluetoothHeadset;
import android.bluetooth.BluetoothHearingAid;
import android.bluetooth.BluetoothLeAudio;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioDeviceCallback;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.util.Log;

import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.btservice.storage.DatabaseManager;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;

/**
 * The active device manager is responsible for keeping track of the
 * connected A2DP/HFP/AVRCP/HearingAid/LE audio devices and select which device is
 * active (for each profile).
 * The active device manager selects a fallback device when the currently active device
 * is disconnected, and it selects BT devices that are lastly activated one.
 *
 * Current policy (subject to change):
 * 1) If the maximum number of connected devices is one, the manager doesn't
 *    do anything. Each profile is responsible for automatically selecting
 *    the connected device as active. Only if the maximum number of connected
 *    devices is more than one, the rules below will apply.
 * 2) The selected A2DP active device is the one used for AVRCP as well.
 * 3) The HFP active device might be different from the A2DP active device.
 * 4) The Active Device Manager always listens for ACTION_ACTIVE_DEVICE_CHANGED
 *    broadcasts for each profile:
 *    - BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED for A2DP
 *    - BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED for HFP
 *    - BluetoothHearingAid.ACTION_ACTIVE_DEVICE_CHANGED for HearingAid
 *    - BluetoothLeAudio.ACTION_LE_AUDIO_ACTIVE_DEVICE_CHANGED for LE audio
 *    If such broadcast is received (e.g., triggered indirectly by user
 *    action on the UI), the device in the received broadcast is marked
 *    as the current active device for that profile.
 * 5) If there is a HearingAid active device, then A2DP, HFP and LE audio active devices
 *    must be set to null (i.e., A2DP, HFP and LE audio cannot have active devices).
 *    The reason is that A2DP, HFP or LE audio cannot be used together with HearingAid.
 * 6) If there are no connected devices (e.g., during startup, or after all
 *    devices have been disconnected, the active device per profile
 *    (A2DP/HFP/HearingAid/LE audio) is selected as follows:
 * 6.1) The last connected HearingAid device is selected as active.
 *      If there is an active A2DP, HFP or LE audio device, those must be set to null.
 * 6.2) The last connected A2DP, HFP or LE audio device is selected as active.
 *      However, if there is an active HearingAid device, then the
 *      A2DP, HFP, or LE audio active device is not set (must remain null).
 * 7) If the currently active device (per profile) is disconnected, the
 *    Active Device Manager just marks that the profile has no active device,
 *    and the lastly activated BT device that is still connected would be selected.
 * 8) If there is already an active device, and the corresponding
 *    ACTION_ACTIVE_DEVICE_CHANGED broadcast is received, the device
 *    contained in the broadcast is marked as active. However, if
 *    the contained device is null, the corresponding profile is marked
 *    as having no active device.
 * 9) If a wired audio device is connected, the audio output is switched
 *    by the Audio Framework itself to that device. We detect this here,
 *    and the active device for each profile (A2DP/HFP/HearingAid/LE audio) is set
 *    to null to reflect the output device state change. However, if the
 *    wired audio device is disconnected, we don't do anything explicit
 *    and apply the default behavior instead:
 * 9.1) If the wired headset is still the selected output device (i.e. the
 *      active device is set to null), the Phone itself will become the output
 *      device (i.e., the active device will remain null). If music was
 *      playing, it will stop.
 * 9.2) If one of the Bluetooth devices is the selected active device
 *      (e.g., by the user in the UI), disconnecting the wired audio device
 *      will have no impact. E.g., music will continue streaming over the
 *      active Bluetooth device.
 */
class ActiveDeviceManager {
    private static final boolean DBG = true;
    private static final String TAG = "BluetoothActiveDeviceManager";

    // Message types for the handler
    private static final int MESSAGE_ADAPTER_ACTION_STATE_CHANGED = 1;
    private static final int MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED = 2;
    private static final int MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED = 3;
    private static final int MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED = 4;
    private static final int MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED = 5;
    private static final int MESSAGE_HEARING_AID_ACTION_CONNECTION_STATE_CHANGED = 6;
    private static final int MESSAGE_HEARING_AID_ACTION_ACTIVE_DEVICE_CHANGED = 7;
    private static final int MESSAGE_LE_AUDIO_ACTION_CONNECTION_STATE_CHANGED = 8;
    private static final int MESSAGE_LE_AUDIO_ACTION_ACTIVE_DEVICE_CHANGED = 9;
    private static final int MESSAGE_HAP_ACTION_CONNECTION_STATE_CHANGED = 10;
    private static final int MESSAGE_HAP_ACTION_ACTIVE_DEVICE_CHANGED = 11;

    // Used when it is needed to find a fallback device
    private static final int PROFILE_NOT_DECIDED_YET = -1;
    // Used for built-in audio device
    private static final int PROFILE_USE_BUILTIN_AUDIO_DEVICE = 0;

    private final AdapterService mAdapterService;
    private final ServiceFactory mFactory;
    private HandlerThread mHandlerThread = null;
    private Handler mHandler = null;
    private final AudioManager mAudioManager;
    private final AudioManagerAudioDeviceCallback mAudioManagerAudioDeviceCallback;
    private final AudioManagerOnModeChangedListener mAudioManagerOnModeChangedListener;

    private final List<BluetoothDevice> mA2dpConnectedDevices = new ArrayList<>();
    private final List<BluetoothDevice> mHfpConnectedDevices = new ArrayList<>();
    private final List<BluetoothDevice> mHearingAidConnectedDevices = new ArrayList<>();
    private final List<BluetoothDevice> mLeAudioConnectedDevices = new ArrayList<>();
    private final List<BluetoothDevice> mLeHearingAidConnectedDevices = new ArrayList<>();
    private final List<BluetoothDevice> mPendingLeHearingAidActiveDevice = new ArrayList<>();
    private BluetoothDevice mA2dpActiveDevice = null;
    private BluetoothDevice mHfpActiveDevice = null;
    private BluetoothDevice mHearingAidActiveDevice = null;
    private BluetoothDevice mLeAudioActiveDevice = null;
    private BluetoothDevice mLeHearingAidActiveDevice = null;
    private int mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
    private int mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;

    // Broadcast receiver for all changes
    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) {
                Log.e(TAG, "Received intent with null action");
                return;
            }
            switch (action) {
                case BluetoothAdapter.ACTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_ADAPTER_ACTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HEARING_AID_ACTION_CONNECTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHearingAid.ACTION_ACTIVE_DEVICE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HEARING_AID_ACTION_ACTIVE_DEVICE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothLeAudio.ACTION_LE_AUDIO_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_LE_AUDIO_ACTION_CONNECTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothLeAudio.ACTION_LE_AUDIO_ACTIVE_DEVICE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_LE_AUDIO_ACTION_ACTIVE_DEVICE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED:
                    mHandler.obtainMessage(MESSAGE_HAP_ACTION_CONNECTION_STATE_CHANGED,
                            intent).sendToTarget();
                    break;
                case BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE:
                    mHandler.obtainMessage(MESSAGE_HAP_ACTION_ACTIVE_DEVICE_CHANGED,
                            intent).sendToTarget();
                    break;
                default:
                    Log.e(TAG, "Received unexpected intent, action=" + action);
                    break;
            }
        }
    };

    class ActiveDeviceManagerHandler extends Handler {
        ActiveDeviceManagerHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            boolean isMediaMode = isMediaMode(mAudioManager.getMode());
            switch (msg.what) {
                case MESSAGE_ADAPTER_ACTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    int newState = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_ADAPTER_ACTION_STATE_CHANGED): newState="
                                + newState);
                    }
                    if (newState == BluetoothAdapter.STATE_ON) {
                        resetState();
                    }
                }
                break;

                case MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (prevState == nextState) {
                        // Nothing has changed
                        break;
                    }
                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " connected");
                        }
                        if (mA2dpConnectedDevices.contains(device)) {
                            break;      // The device is already connected
                        }
                        // New connected A2DP device
                        mA2dpConnectedDevices.add(device);
                        if (mActiveMediaProfile != BluetoothProfile.HEARING_AID
                                && mActiveMediaProfile != BluetoothProfile.HAP_CLIENT) {
                            if (isMediaMode || mActiveCallProfile == BluetoothProfile.HEADSET) {
                                // select the device as active if not lazy active
                                setA2dpActiveDevice(device);
                                setLeAudioActiveDevice(null, true);
                                mActiveMediaProfile = BluetoothProfile.A2DP;
                            } else {
                                // Lazy active A2DP if it is not being used.
                                mActiveMediaProfile = PROFILE_NOT_DECIDED_YET;
                            }
                        }
                        break;
                    }
                    if (prevState == BluetoothProfile.STATE_CONNECTED) {
                        // A2DP device disconnected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_A2DP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " disconnected");
                        }
                        mA2dpConnectedDevices.remove(device);
                        if (Objects.equals(mA2dpActiveDevice, device)) {
                            mActiveMediaProfile = PROFILE_NOT_DECIDED_YET;
                            if (isMediaMode) {
                                if (!setFallbackDeviceActive()) {
                                    mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                    setA2dpActiveDevice(null);
                                }
                            } else {
                                mA2dpActiveDevice = null;
                            }
                        }
                    }
                }
                break;

                case MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_A2DP_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    if (device != null) {
                        mActiveMediaProfile = BluetoothProfile.A2DP;
                        if (!Objects.equals(mA2dpActiveDevice, device)) {
                            setHearingAidActiveDevice(null, true);
                            setLeAudioActiveDevice(null, true);
                        }
                    }
                    // Just assign locally the new value
                    mA2dpActiveDevice = device;
                }
                break;

                case MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (prevState == nextState) {
                        // Nothing has changed
                        break;
                    }
                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " connected");
                        }
                        if (mHfpConnectedDevices.contains(device)) {
                            break;      // The device is already connected
                        }
                        // New connected HFP device.
                        mHfpConnectedDevices.add(device);
                        if (mActiveCallProfile != BluetoothProfile.HEARING_AID
                                && mActiveCallProfile != BluetoothProfile.HAP_CLIENT) {
                            if (!isMediaMode || mActiveMediaProfile == BluetoothProfile.A2DP) {
                                // select the device as active if not lazy active
                                setHfpActiveDevice(device);
                                setLeAudioActiveDevice(null);
                                mActiveCallProfile = BluetoothProfile.HEADSET;
                            } else {
                                // Lazy active HFP if it is not being used.
                                mActiveCallProfile = PROFILE_NOT_DECIDED_YET;
                            }
                        }
                        break;
                    }
                    if (prevState == BluetoothProfile.STATE_CONNECTED) {
                        // HFP device disconnected
                        if (DBG) {
                            Log.d(TAG,
                                    "handleMessage(MESSAGE_HFP_ACTION_CONNECTION_STATE_CHANGED): "
                                    + "device " + device + " disconnected");
                        }
                        mHfpConnectedDevices.remove(device);
                        if (Objects.equals(mHfpActiveDevice, device)) {
                            mActiveCallProfile = PROFILE_NOT_DECIDED_YET;
                            if (!isMediaMode) {
                                if (!setFallbackDeviceActive()) {
                                    mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                    setHfpActiveDevice(null);
                                }
                            } else {
                                mHfpActiveDevice = null;
                            }
                        }
                    }
                }
                break;

                case MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_HFP_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    if (device != null) {
                        mActiveCallProfile = BluetoothProfile.HEADSET;
                        if (!Objects.equals(mHfpActiveDevice, device)) {
                            setHearingAidActiveDevice(null, true);
                            setLeAudioActiveDevice(null, true);
                        }
                    }
                    // Just assign locally the new value
                    mHfpActiveDevice = device;
                }
                break;

                case MESSAGE_HEARING_AID_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (prevState == nextState) {
                        // Nothing has changed
                        break;
                    }
                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_HEARING_AID_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " connected");
                        }
                        if (mHearingAidConnectedDevices.contains(device)) {
                            break;      // The device is already connected
                        }
                        mHearingAidConnectedDevices.add(device);
                        // New connected hearing aid device: select it as active
                        mActiveMediaProfile = BluetoothProfile.HEARING_AID;
                        mActiveCallProfile = BluetoothProfile.HEARING_AID;
                        setHearingAidActiveDevice(device);
                        setA2dpActiveDevice(null, true);
                        setHfpActiveDevice(null);
                        setLeAudioActiveDevice(null, true);
                        break;
                    }
                    if (prevState == BluetoothProfile.STATE_CONNECTED) {
                        // Hearing aid device disconnected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_HEARING_AID_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " disconnected");
                        }
                        mHearingAidConnectedDevices.remove(device);
                        if (Objects.equals(mHearingAidActiveDevice, device)) {
                            if (mActiveMediaProfile == BluetoothProfile.HEARING_AID) {
                                mActiveMediaProfile = PROFILE_NOT_DECIDED_YET;
                            }
                            if (mActiveCallProfile == BluetoothProfile.HEARING_AID) {
                                mActiveCallProfile = PROFILE_NOT_DECIDED_YET;
                            }
                            if (!setFallbackDeviceActive()) {
                                setHearingAidActiveDevice(null);
                                if (mActiveMediaProfile == PROFILE_NOT_DECIDED_YET) {
                                    mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                }
                                if (mActiveCallProfile == PROFILE_NOT_DECIDED_YET) {
                                    mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                }
                            }
                        }
                    }
                }
                break;

                case MESSAGE_HEARING_AID_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_HA_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    if (device != null && !Objects.equals(mHearingAidActiveDevice, device)) {
                        setA2dpActiveDevice(null, true);
                        setHfpActiveDevice(null);
                        setLeAudioActiveDevice(null, true);
                        if (isMediaMode) {
                            mActiveMediaProfile = BluetoothProfile.HEARING_AID;
                        } else {
                            mActiveCallProfile = BluetoothProfile.HEARING_AID;
                        }
                    }
                    // Just assign locally the new value
                    mHearingAidActiveDevice = device;
                }
                break;

                case MESSAGE_LE_AUDIO_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (prevState == nextState) {
                        // Nothing has changed
                        break;
                    }
                    final LeAudioService leAudioService = mFactory.getLeAudioService();

                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_LE_AUDIO_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " connected");
                        }
                        if (leAudioService != null && device != null) {
                            leAudioService.deviceConnected(device);
                        }
                        if (mLeAudioConnectedDevices.contains(device)) {
                            break;      // The device is already connected
                        }
                        mLeAudioConnectedDevices.add(device);
                        if (mPendingLeHearingAidActiveDevice.contains(device)) {
                            // LE hearing aid connected
                            mActiveMediaProfile = BluetoothProfile.HAP_CLIENT;
                            mActiveCallProfile = BluetoothProfile.HAP_CLIENT;
                            setLeHearingAidActiveDevice(device);
                            setHearingAidActiveDevice(null, true);
                            setA2dpActiveDevice(null, true);
                            setHfpActiveDevice(null);
                        } else {
                            boolean setLeAudioActive = false;
                            if (mActiveMediaProfile != BluetoothProfile.HEARING_AID
                                    && mActiveMediaProfile != BluetoothProfile.HAP_CLIENT) {
                                mActiveMediaProfile = BluetoothProfile.LE_AUDIO;
                                setLeAudioActive |= isMediaMode;
                            }
                            if (mActiveCallProfile != BluetoothProfile.HEARING_AID
                                    && mActiveCallProfile != BluetoothProfile.HAP_CLIENT) {
                                mActiveCallProfile = BluetoothProfile.LE_AUDIO;
                                setLeAudioActive |= !isMediaMode;
                            }
                            if (setLeAudioActive) {
                                setLeAudioActiveDevice(device);
                                setA2dpActiveDevice(null, true);
                                setHfpActiveDevice(null);
                                setHearingAidActiveDevice(null, true);
                            }
                        }
                        break;
                    }
                    if (prevState == BluetoothProfile.STATE_CONNECTED) {
                        // LE audio device disconnected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_LE_AUDIO_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " disconnected");
                        }
                        mLeAudioConnectedDevices.remove(device);
                        mLeHearingAidConnectedDevices.remove(device);
                        boolean hasFallbackDevice = false;
                        if (Objects.equals(mLeAudioActiveDevice, device)) {
                            if (mActiveMediaProfile == BluetoothProfile.LE_AUDIO
                                    || mActiveMediaProfile == BluetoothProfile.HAP_CLIENT) {
                                mActiveMediaProfile = PROFILE_NOT_DECIDED_YET;
                            }
                            if (mActiveCallProfile == BluetoothProfile.LE_AUDIO
                                    || mActiveCallProfile == BluetoothProfile.HAP_CLIENT) {
                                mActiveCallProfile = PROFILE_NOT_DECIDED_YET;
                            }
                            if (!setFallbackDeviceActive()) {
                                setLeAudioActiveDevice(null);
                                if (mActiveMediaProfile == PROFILE_NOT_DECIDED_YET) {
                                    mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                }
                                if (mActiveCallProfile == PROFILE_NOT_DECIDED_YET) {
                                    mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                                }
                            }
                        }
                        if (leAudioService != null && device != null) {
                            leAudioService.deviceDisconnected(device, hasFallbackDevice);
                        }
                    }
                }
                break;

                case MESSAGE_LE_AUDIO_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (device != null && !mLeAudioConnectedDevices.contains(device)) {
                        mLeAudioConnectedDevices.add(device);
                    }
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_LE_AUDIO_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }

                    if (device != null && !Objects.equals(mLeAudioActiveDevice, device)) {
                        setA2dpActiveDevice(null, true);
                        setHfpActiveDevice(null);
                        setHearingAidActiveDevice(null, true);
                        int profile = mLeHearingAidConnectedDevices.contains(device)
                                ? BluetoothProfile.HAP_CLIENT : BluetoothProfile.LE_AUDIO;
                        if (isMediaMode) {
                            mActiveMediaProfile = profile;
                        } else {
                            mActiveCallProfile = profile;
                        }
                    }
                    // Just assign locally the new value
                    mLeAudioActiveDevice = device;
                }
                break;

                case MESSAGE_HAP_ACTION_CONNECTION_STATE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    int prevState = intent.getIntExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, -1);
                    int nextState = intent.getIntExtra(BluetoothProfile.EXTRA_STATE, -1);
                    if (prevState == nextState) {
                        // Nothing has changed
                        break;
                    }
                    if (nextState == BluetoothProfile.STATE_CONNECTED) {
                        // Device connected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_HAP_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " connected");
                        }
                        if (mLeHearingAidConnectedDevices.contains(device)) {
                            break;      // The device is already connected
                        }
                        mLeHearingAidConnectedDevices.add(device);
                        if (!mLeAudioConnectedDevices.contains(device)) {
                            mPendingLeHearingAidActiveDevice.add(device);
                        } else {
                            mActiveMediaProfile = BluetoothProfile.HAP_CLIENT;
                            mActiveCallProfile = BluetoothProfile.HAP_CLIENT;
                            if (Objects.equals(mLeAudioActiveDevice, device)) {
                                mLeHearingAidActiveDevice = device;
                            } else {
                                setLeHearingAidActiveDevice(device);
                                setHearingAidActiveDevice(null, true);
                                setA2dpActiveDevice(null, true);
                                setHfpActiveDevice(null);
                            }
                        }
                        break;
                    }
                    if (prevState == BluetoothProfile.STATE_CONNECTED) {
                        // LE hearing aid device disconnected
                        if (DBG) {
                            Log.d(TAG, "handleMessage(MESSAGE_HAP_ACTION_CONNECTION_STATE"
                                    + "_CHANGED): device " + device + " disconnected");
                        }
                        mLeHearingAidConnectedDevices.remove(device);
                        mPendingLeHearingAidActiveDevice.remove(device);
                        if (Objects.equals(mLeHearingAidActiveDevice, device)) {
                            mLeHearingAidActiveDevice = null;
                        }
                    }
                }
                break;

                case MESSAGE_HAP_ACTION_ACTIVE_DEVICE_CHANGED: {
                    Intent intent = (Intent) msg.obj;
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (device != null && !mLeHearingAidConnectedDevices.contains(device)) {
                        mLeHearingAidConnectedDevices.add(device);
                    }
                    if (DBG) {
                        Log.d(TAG, "handleMessage(MESSAGE_HAP_ACTION_ACTIVE_DEVICE_CHANGED): "
                                + "device= " + device);
                    }
                    // Just assign locally the new value
                    if (device != null && !Objects.equals(mLeHearingAidActiveDevice, device)) {
                        if (isMediaMode) {
                            mActiveMediaProfile = BluetoothProfile.HAP_CLIENT;
                        } else {
                            mActiveCallProfile = BluetoothProfile.HAP_CLIENT;
                        }
                        setHearingAidActiveDevice(null, true);
                        setA2dpActiveDevice(null, true);
                        setHfpActiveDevice(null);
                    }
                    mLeHearingAidActiveDevice = mLeAudioActiveDevice = device;
                }
                break;
            }
        }
    }

    private class AudioManagerOnModeChangedListener implements AudioManager.OnModeChangedListener {
        public void onModeChanged(int mode) {
            if (isMediaMode(mode)) {
                setMediaProfileActive();
            } else {
                setCallProfileActive();
            }
        }

        private void setMediaProfileActive() {
            BluetoothDevice device = null;
            switch (mActiveMediaProfile) {
                case PROFILE_NOT_DECIDED_YET: {
                    if (!setFallbackDeviceActive()) {
                        mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                    }
                    break;
                }

                case BluetoothProfile.A2DP: {
                    if (mA2dpActiveDevice == null) {
                        A2dpService a2dpService = mFactory.getA2dpService();
                        if (a2dpService != null) {
                            device = a2dpService.getFallbackDevice();
                        }
                        if (device != null) {
                            setA2dpActiveDevice(device);
                            setHearingAidActiveDevice(null, true);
                            setLeAudioActiveDevice(null, true);
                        } else {
                            mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }

                case BluetoothProfile.HEARING_AID: {
                    if (mHearingAidActiveDevice == null) {
                        DatabaseManager dbManager = mAdapterService.getDatabase();
                        if (dbManager != null) {
                            device = dbManager.getMostRecentlyConnectedDevicesInList(
                                    mHearingAidConnectedDevices);
                        }
                        if (device != null) {
                            setHearingAidActiveDevice(device);
                            setA2dpActiveDevice(null, true);
                            setLeAudioActiveDevice(null, true);
                        } else {
                            mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }

                case BluetoothProfile.LE_AUDIO: {
                    if (mLeAudioActiveDevice == null) {
                        DatabaseManager dbManager = mAdapterService.getDatabase();
                        if (dbManager != null) {
                            device = dbManager.getMostRecentlyConnectedDevicesInList(
                                    mLeAudioConnectedDevices);
                        }
                        if (device != null) {
                            setLeAudioActiveDevice(device);
                            setA2dpActiveDevice(null, true);
                            setHfpActiveDevice(null);
                            setHearingAidActiveDevice(null, true);
                        } else {
                            mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }

                case BluetoothProfile.HAP_CLIENT: {
                    if (mLeHearingAidActiveDevice == null) {
                        DatabaseManager dbManager = mAdapterService.getDatabase();
                        if (dbManager != null) {
                            device = dbManager.getMostRecentlyConnectedDevicesInList(
                                    mLeHearingAidConnectedDevices);
                        }
                        if (device != null) {
                            setLeHearingAidActiveDevice(device);
                            setA2dpActiveDevice(null, true);
                            setHfpActiveDevice(null);
                            setHearingAidActiveDevice(null, true);
                        } else {
                            mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }
            }
        }

        private void setCallProfileActive() {
            BluetoothDevice device = null;
            switch (mActiveCallProfile) {
                case PROFILE_NOT_DECIDED_YET: {
                    if (!setFallbackDeviceActive()) {
                        mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                    }
                    break;
                }

                case BluetoothProfile.HEADSET: {
                    if (mHfpActiveDevice == null) {
                        HeadsetService headsetService = mFactory.getHeadsetService();
                        if (headsetService != null) {
                            device = headsetService.getFallbackDevice();
                        }
                        if (device != null) {
                            setHfpActiveDevice(device);
                            setHearingAidActiveDevice(null, true);
                            setLeAudioActiveDevice(null, true);
                        } else {
                            mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }

                case BluetoothProfile.HEARING_AID: {
                    if (mHearingAidActiveDevice == null) {
                        DatabaseManager dbManager = mAdapterService.getDatabase();
                        if (dbManager != null) {
                            device = dbManager.getMostRecentlyConnectedDevicesInList(
                                    mHearingAidConnectedDevices);
                        }
                        if (device != null) {
                            setHearingAidActiveDevice(device);
                            setHfpActiveDevice(null);
                            setLeAudioActiveDevice(null);
                        } else {
                            mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }

                case BluetoothProfile.LE_AUDIO: {
                    if (mLeAudioActiveDevice == null) {
                        DatabaseManager dbManager = mAdapterService.getDatabase();
                        if (dbManager != null) {
                            device = dbManager.getMostRecentlyConnectedDevicesInList(
                                    mLeAudioConnectedDevices);
                        }
                        if (device != null) {
                            setLeAudioActiveDevice(device);
                            setA2dpActiveDevice(null, true);
                            setHfpActiveDevice(null);
                            setHearingAidActiveDevice(null, true);
                        } else {
                            mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
                        }
                    }
                    break;
                }
            }
        }
    }

    /** Notifications of audio device connection and disconnection events. */
    @SuppressLint("AndroidFrameworkRequiresPermission")
    private class AudioManagerAudioDeviceCallback extends AudioDeviceCallback {
        private boolean isWiredAudioHeadset(AudioDeviceInfo deviceInfo) {
            switch (deviceInfo.getType()) {
                case AudioDeviceInfo.TYPE_WIRED_HEADSET:
                case AudioDeviceInfo.TYPE_WIRED_HEADPHONES:
                case AudioDeviceInfo.TYPE_USB_HEADSET:
                    return true;
                default:
                    break;
            }
            return false;
        }

        @Override
        public void onAudioDevicesAdded(AudioDeviceInfo[] addedDevices) {
            if (DBG) {
                Log.d(TAG, "onAudioDevicesAdded");
            }
            boolean hasAddedWiredDevice = false;
            for (AudioDeviceInfo deviceInfo : addedDevices) {
                if (DBG) {
                    Log.d(TAG, "Audio device added: " + deviceInfo.getProductName() + " type: "
                            + deviceInfo.getType());
                }
                if (isWiredAudioHeadset(deviceInfo)) {
                    hasAddedWiredDevice = true;
                    break;
                }
            }
            if (hasAddedWiredDevice) {
                wiredAudioDeviceConnected();
            }
        }

        @Override
        public void onAudioDevicesRemoved(AudioDeviceInfo[] removedDevices) {
        }
    }

    ActiveDeviceManager(AdapterService service, ServiceFactory factory) {
        mAdapterService = service;
        mFactory = factory;
        mAudioManager = service.getSystemService(AudioManager.class);
        mAudioManagerAudioDeviceCallback = new AudioManagerAudioDeviceCallback();
        mAudioManagerOnModeChangedListener = new AudioManagerOnModeChangedListener();
    }

    void start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }

        mHandlerThread = new HandlerThread("BluetoothActiveDeviceManager");
        mHandlerThread.start();
        mHandler = new ActiveDeviceManagerHandler(mHandlerThread.getLooper());

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        filter.addAction(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED);
        filter.addAction(BluetoothHearingAid.ACTION_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHearingAid.ACTION_ACTIVE_DEVICE_CHANGED);
        filter.addAction(BluetoothLeAudio.ACTION_LE_AUDIO_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothLeAudio.ACTION_LE_AUDIO_ACTIVE_DEVICE_CHANGED);
        filter.addAction(BluetoothHapClient.ACTION_HAP_CONNECTION_STATE_CHANGED);
        filter.addAction(BluetoothHapClient.ACTION_HAP_DEVICE_AVAILABLE);
        mAdapterService.registerReceiver(mReceiver, filter);

        mAudioManager.registerAudioDeviceCallback(mAudioManagerAudioDeviceCallback, mHandler);
        mAudioManager.addOnModeChangedListener(command -> {
            if (!mHandler.post(command)) {
                throw new RejectedExecutionException(mHandler + " is shutting down");
            }
        }, mAudioManagerOnModeChangedListener);
    }

    void cleanup() {
        if (DBG) {
            Log.d(TAG, "cleanup()");
        }

        mAudioManager.unregisterAudioDeviceCallback(mAudioManagerAudioDeviceCallback);
        mAudioManager.removeOnModeChangedListener(mAudioManagerOnModeChangedListener);
        mAdapterService.unregisterReceiver(mReceiver);
        if (mHandlerThread != null) {
            mHandlerThread.quit();
            mHandlerThread = null;
        }
        resetState();
    }

    /**
     * Get the {@link Looper} for the handler thread. This is used in testing and helper
     * objects
     *
     * @return {@link Looper} for the handler thread
     */
    @VisibleForTesting
    public Looper getHandlerLooper() {
        if (mHandlerThread == null) {
            return null;
        }
        return mHandlerThread.getLooper();
    }

    private void setA2dpActiveDevice(BluetoothDevice device) {
        setA2dpActiveDevice(device, false);
    }

    private void setA2dpActiveDevice(BluetoothDevice device, boolean hasFallbackDevice) {
        if (DBG) {
            Log.d(TAG, "setA2dpActiveDevice(" + device + ")");
        }
        final A2dpService a2dpService = mFactory.getA2dpService();
        if (a2dpService == null) {
            return;
        }
        if (!a2dpService.setActiveDevice(device, hasFallbackDevice)) {
            return;
        }
        mA2dpActiveDevice = device;
    }

    @RequiresPermission(android.Manifest.permission.MODIFY_PHONE_STATE)
    private void setHfpActiveDevice(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "setHfpActiveDevice(" + device + ")");
        }
        final HeadsetService headsetService = mFactory.getHeadsetService();
        if (headsetService == null) {
            return;
        }
        if (!headsetService.setActiveDevice(device)) {
            return;
        }
        mHfpActiveDevice = device;
    }

    private void setHearingAidActiveDevice(BluetoothDevice device) {
        setHearingAidActiveDevice(device, false);
    }

    private void setHearingAidActiveDevice(BluetoothDevice device, boolean hasFallbackDevice) {
        if (DBG) {
            Log.d(TAG, "setHearingAidActiveDevice(" + device + ")");
        }
        final HearingAidService hearingAidService = mFactory.getHearingAidService();
        if (hearingAidService == null) {
            return;
        }
        if (!hearingAidService.setActiveDevice(device, hasFallbackDevice)) {
            return;
        }
        mHearingAidActiveDevice = device;
    }
    private void setLeAudioActiveDevice(BluetoothDevice device) {
        setLeAudioActiveDevice(device, false);
    }

    private void setLeAudioActiveDevice(BluetoothDevice device, boolean hasFallbackDevice) {
        if (DBG) {
            Log.d(TAG, "setLeAudioActiveDevice(" + device + ")");
        }
        final LeAudioService leAudioService = mFactory.getLeAudioService();
        if (leAudioService == null) {
            return;
        }
        if (!leAudioService.setActiveDevice(device, hasFallbackDevice)) {
            return;
        }
        mLeAudioActiveDevice = device;
        if (device == null) {
            mLeHearingAidActiveDevice = null;
            mPendingLeHearingAidActiveDevice.remove(device);
        }
    }

    private void setLeHearingAidActiveDevice(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "setLeHearingAidActiveDevice(" + device + ")");
        }
        if (!Objects.equals(mLeAudioActiveDevice, device)) {
            setLeAudioActiveDevice(device);
        }
        if (Objects.equals(mLeAudioActiveDevice, device)) {
            // setLeAudioActiveDevice succeed
            mLeHearingAidActiveDevice = device;
            mPendingLeHearingAidActiveDevice.remove(device);
        }
    }

    private boolean isMediaMode(int mode) {
        switch (mode) {
            case AudioManager.MODE_RINGTONE:
                final HeadsetService headsetService = mFactory.getHeadsetService();
                if (headsetService != null && headsetService.isInbandRingingEnabled()) {
                    return false;
                }
                return true;
            case AudioManager.MODE_IN_CALL:
            case AudioManager.MODE_IN_COMMUNICATION:
            case AudioManager.MODE_CALL_SCREENING:
            case AudioManager.MODE_CALL_REDIRECT:
            case AudioManager.MODE_COMMUNICATION_REDIRECT:
                return false;
            default:
                return true;
        }
    }

    private boolean setFallbackDeviceActive() {
        if (DBG) {
            Log.d(TAG, "setFallbackDeviceActive");
        }
        DatabaseManager dbManager = mAdapterService.getDatabase();
        if (dbManager == null) {
            return false;
        }
        List<BluetoothDevice> connectedHearingAidDevices = new ArrayList<>();
        if (!mHearingAidConnectedDevices.isEmpty()) {
            connectedHearingAidDevices.addAll(mHearingAidConnectedDevices);
        }
        if (!mLeHearingAidConnectedDevices.isEmpty()) {
            connectedHearingAidDevices.addAll(mLeHearingAidConnectedDevices);
        }
        if (!connectedHearingAidDevices.isEmpty()) {
            BluetoothDevice device =
                    dbManager.getMostRecentlyConnectedDevicesInList(connectedHearingAidDevices);
            if (device != null) {
                if (mHearingAidConnectedDevices.contains(device)) {
                    if (DBG) {
                        Log.d(TAG, "set hearing aid device active: " + device);
                    }
                    setHearingAidActiveDevice(device);
                    setA2dpActiveDevice(null, true);
                    setHfpActiveDevice(null);
                    setLeAudioActiveDevice(null, true);
                    if (mActiveMediaProfile == PROFILE_NOT_DECIDED_YET) {
                        mActiveMediaProfile = BluetoothProfile.HEARING_AID;
                    }
                    if (mActiveCallProfile == PROFILE_NOT_DECIDED_YET) {
                        mActiveCallProfile = BluetoothProfile.HEARING_AID;
                    }
                } else {
                    if (DBG) {
                        Log.d(TAG, "set LE hearing aid device active: " + device);
                    }
                    setLeHearingAidActiveDevice(device);
                    setHearingAidActiveDevice(null, true);
                    setA2dpActiveDevice(null, true);
                    setHfpActiveDevice(null);
                    if (mActiveMediaProfile == PROFILE_NOT_DECIDED_YET) {
                        mActiveMediaProfile = BluetoothProfile.HAP_CLIENT;
                    }
                    if (mActiveCallProfile == PROFILE_NOT_DECIDED_YET) {
                        mActiveCallProfile = BluetoothProfile.HAP_CLIENT;
                    }
                }
                return true;
            }
        }

        A2dpService a2dpService = mFactory.getA2dpService();
        BluetoothDevice a2dpFallbackDevice = null;
        if (a2dpService != null) {
            a2dpFallbackDevice = a2dpService.getFallbackDevice();
        }

        HeadsetService headsetService = mFactory.getHeadsetService();
        BluetoothDevice headsetFallbackDevice = null;
        if (headsetService != null) {
            headsetFallbackDevice = headsetService.getFallbackDevice();
        }

        List<BluetoothDevice> connectedDevices = new ArrayList<>();
        connectedDevices.addAll(mLeAudioConnectedDevices);
        boolean isMediaMode = isMediaMode(mAudioManager.getMode());
        if (isMediaMode) {
            if (a2dpFallbackDevice != null) {
                connectedDevices.add(a2dpFallbackDevice);
            }
        } else {
            if (headsetFallbackDevice != null) {
                connectedDevices.add(headsetFallbackDevice);
            }
        }

        BluetoothDevice device = dbManager.getMostRecentlyConnectedDevicesInList(connectedDevices);
        if (device != null) {
            if (isMediaMode) {
                if (Objects.equals(a2dpFallbackDevice, device)) {
                    if (DBG) {
                        Log.d(TAG, "set A2DP device active: " + device);
                    }
                    setA2dpActiveDevice(device);
                    setLeAudioActiveDevice(null, true);
                    mActiveMediaProfile = BluetoothProfile.A2DP;
                } else {
                    if (DBG) {
                        Log.d(TAG, "set LE audio device active: " + device);
                    }
                    setLeAudioActiveDevice(device);
                    setA2dpActiveDevice(null, true);
                    setHfpActiveDevice(null);
                    mActiveMediaProfile = BluetoothProfile.LE_AUDIO;
                }
            } else {
                if (Objects.equals(headsetFallbackDevice, device)) {
                    if (DBG) {
                        Log.d(TAG, "set HFP device active: " + device);
                    }
                    setHfpActiveDevice(device);
                    setLeAudioActiveDevice(null);
                    mActiveCallProfile = BluetoothProfile.HEADSET;
                } else {
                    if (DBG) {
                        Log.d(TAG, "set LE audio device active: " + device);
                    }
                    setLeAudioActiveDevice(device);
                    setA2dpActiveDevice(null, true);
                    setHfpActiveDevice(null);
                    mActiveCallProfile = BluetoothProfile.LE_AUDIO;
                }
            }
            return true;
        }
        return false;
    }

    private void resetState() {
        mA2dpConnectedDevices.clear();
        mA2dpActiveDevice = null;

        mHfpConnectedDevices.clear();
        mHfpActiveDevice = null;

        mHearingAidConnectedDevices.clear();
        mHearingAidActiveDevice = null;

        mLeAudioConnectedDevices.clear();
        mLeAudioActiveDevice = null;

        mLeHearingAidConnectedDevices.clear();
        mLeHearingAidActiveDevice = null;
        mPendingLeHearingAidActiveDevice.clear();
    }

    @VisibleForTesting
    BroadcastReceiver getBroadcastReceiver() {
        return mReceiver;
    }

    @VisibleForTesting
    BluetoothDevice getA2dpActiveDevice() {
        return mA2dpActiveDevice;
    }

    @VisibleForTesting
    BluetoothDevice getHfpActiveDevice() {
        return mHfpActiveDevice;
    }

    @VisibleForTesting
    BluetoothDevice getHearingAidActiveDevice() {
        return mHearingAidActiveDevice;
    }

    @VisibleForTesting
    BluetoothDevice getLeAudioActiveDevice() {
        return mLeAudioActiveDevice;
    }

    /**
     * Called when a wired audio device is connected.
     * It might be called multiple times each time a wired audio device is connected.
     */
    @VisibleForTesting
    @RequiresPermission(android.Manifest.permission.MODIFY_PHONE_STATE)
    void wiredAudioDeviceConnected() {
        if (DBG) {
            Log.d(TAG, "wiredAudioDeviceConnected");
        }
        mActiveMediaProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
        mActiveCallProfile = PROFILE_USE_BUILTIN_AUDIO_DEVICE;
        setA2dpActiveDevice(null);
        setHfpActiveDevice(null);
        setHearingAidActiveDevice(null);
        setLeAudioActiveDevice(null);
    }
}
