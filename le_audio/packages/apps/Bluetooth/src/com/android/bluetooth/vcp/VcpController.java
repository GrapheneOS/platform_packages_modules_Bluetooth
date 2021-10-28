/*
 *Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

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

package com.android.bluetooth.vcp;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.BluetoothVcp;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemProperties;
import android.os.UserManager;
import android.util.Log;

import com.android.bluetooth.apm.ApmConst;
import com.android.bluetooth.apm.DeviceProfileMap;
import com.android.bluetooth.apm.VolumeManager;
import com.android.bluetooth.acm.AcmService;
import com.android.bluetooth.BluetoothMetricsProto;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.MetricsLogger;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.bluetooth.groupclient.GroupService;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.ArrayUtils;

import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

public class VcpController {
    private static final String TAG = "VcpController";
    private static final boolean DBG = true;
    private static final int MAX_VCP_STATE_MACHINES = 50;
    private static final int VCP_MIN_VOL = 0;
    private static final int VCP_MAX_VOL = 255;
    private static final String ACTION_CONNECT_DEVICE =
                "com.android.bluetooth.vcp.test.action.CONNECT_DEVICE";
    private static final String ACTION_DISCONNECT_DEVICE =
                "com.android.bluetooth.vcp.test.action.DISCONNECT_DEVICE";

    private HandlerThread mStateMachinesThread;
    private final HashMap<BluetoothDevice, VcpControllerStateMachine> mStateMachines =
                new HashMap<>();
    private HashMap<BluetoothDevice, Integer> mConnectionMode = new HashMap();
    private BroadcastReceiver mBondStateChangedReceiver;

    private AdapterService mAdapterService;
    private VcpControllerNativeInterface mNativeInterface;
    private DeviceProfileMap mDpm;
    private AcmService mAcmService;
    private static VcpController sInstance = null;
    private Context mContext;
    private boolean mPtsTest = false;
    private final BroadcastReceiver mVcpControllerTestReceiver = new VcpControllerTestReceiver();

    private VcpController(Context context) {
        if (DBG) {
            Log.d(TAG, "Create VcpController Instance");
        }

        mContext = context;
        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when VcpController starts");
        mNativeInterface = Objects.requireNonNull(VcpControllerNativeInterface.getInstance(),
                "VcpControllerNativeInterface cannot be null when VcpController starts");

        // Start handler thread for state machines
        mStateMachines.clear();
        mStateMachinesThread = new HandlerThread("VcpController.StateMachines");
        mStateMachinesThread.start();
        mNativeInterface.init();

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        mBondStateChangedReceiver = new BondStateChangedReceiver();
        mContext.registerReceiver(mBondStateChangedReceiver, filter);

        if (mAdapterService.isAdvBCAAudioFeatEnabled()) {
            Log.d(TAG, "Adv BCA Audio supported, enable VCP for broadcast");
            SystemProperties.set("persist.vendor.service.bt.vcpForBroadcast", "true");
        } else {
            SystemProperties.set("persist.vendor.service.bt.vcpForBroadcast", "false");
        }
        mPtsTest = SystemProperties.getBoolean("persist.vendor.service.bt.vcp_controller.pts", false);
        if (mPtsTest) {
            Log.d(TAG, "Register for VcpControllerTestReceiver");
            IntentFilter filter2 = new IntentFilter();
            filter2.addAction(ACTION_CONNECT_DEVICE);
            filter2.addAction(ACTION_DISCONNECT_DEVICE);
            context.registerReceiver(mVcpControllerTestReceiver, filter2);
        }
    }

    /**
     * Make VcpController instance and Initialize
     *
     * @param context: application context
     * @return VcpController instance
     */
    public static VcpController make(Context context) {
        Log.v(TAG, "make");

        if(sInstance == null) {
            sInstance = new VcpController(context);
        }
        Log.v(TAG, "Exit make");
        return sInstance;
    }

    /**
     * Get the VcpController instance, which provides the public APIs
     * to volume control operation via VCP connection
     *
     * @return VcpController instance
     */
    public static synchronized VcpController getVcpController() {
        if (sInstance == null) {
            Log.w(TAG, "getVcpController(): service is NULL");
            return null;
        }

        return sInstance;
    }

    public static void clearVcpInstance () {
        Log.v(TAG, "clearing VCP instatnce");
        sInstance = null;
        Log.v(TAG, "After clearing VCP instatnce ");
    }

    public synchronized void doQuit() {
        if (DBG) {
            Log.d(TAG, "doQuit()");
        }
        if (sInstance == null) {
            Log.w(TAG, "doQuit() called before make()");
            return;
        }

        // Cleanup native interface
        mNativeInterface.cleanup();
        mNativeInterface = null;
        mContext.unregisterReceiver(mBondStateChangedReceiver);
        if (mPtsTest) {
            mContext.unregisterReceiver(mVcpControllerTestReceiver);
        }

        // Mark service as stopped
        sInstance = null;

        // Destroy state machines and stop handler thread
        synchronized (mStateMachines) {
            for (VcpControllerStateMachine sm : mStateMachines.values()) {
                sm.doQuit();
                sm.cleanup();
            }
            mStateMachines.clear();
        }

        if (mStateMachinesThread != null) {
            mStateMachinesThread.quitSafely();
            mStateMachinesThread = null;
        }

        // Clear AdapterService
        mAdapterService = null;
    }

    /**
     * Connect with the remote device for unicast or broadcast mode.
     *
     * @param device: the remote device to connect
     * @param mode: connection mode: can be any of
     * {@link #BluetoothVcp.MODE_UNICAST} or {@link #BluetoothVcp.MODE_BROADCAST}
     *
     * @return true if connect is accepted, false if connect request is rejected.
     */
    public boolean connect(BluetoothDevice device, int mode) {
        if (DBG) {
            Log.d(TAG, "connect(): " + device + ", mode: " + mode);
        }
        if (device == null) {
            return false;
        }

        synchronized (mStateMachines) {
            VcpControllerStateMachine smConnect = getOrCreateStateMachine(device);
            if (smConnect == null) {
                Log.e(TAG, "Cannot connect to " + device + " : no state machine");
            }

            int preConnMode;
            if (mConnectionMode.containsKey(device)) {
                preConnMode = mConnectionMode.get(device);
                if ((preConnMode & mode) == 0) {
                    int connMode = preConnMode | mode;
                    mConnectionMode.put(device, connMode);
                    broadcastConnectionModeChanged(device, connMode);
                }
            } else {
                preConnMode = BluetoothVcp.MODE_NONE;
                mConnectionMode.put(device, mode);
                broadcastConnectionModeChanged(device, mode);
            }

            if (smConnect.getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
                smConnect.sendMessage(VcpControllerStateMachine.CONNECT, device);
            } else {
                if (preConnMode == BluetoothVcp.MODE_BROADCAST &&
                        mode == BluetoothVcp.MODE_UNICAST) {
                    Log.d(TAG, "VCP connection from BROADCAST-ONLY to UNICAST_BROADCAST: " + device);
                }
            }
        }

        return true;
    }

    /**
     * Disconnect with the remote device for unicast or broadcast mode.
     *
     * @param device: the remote device to connect
     * @param mode: connection mode: can be any of
     * {@link #BluetoothVcp.MODE_UNICAST} or {@link #BluetoothVcp.MODE_BROADCAST}
     *
     * @return true if disconnect is accepted, false if disconnect is rejected.
     */
    public boolean disconnect(BluetoothDevice device, int mode) {
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device + ", mode: " + mode);
        }
        if (device == null) {
            return false;
        }

        synchronized (mStateMachines) {
            int preConnMode = getConnectionMode(device);
            int connMode = BluetoothVcp.MODE_NONE;

            if ((preConnMode & mode) != 0) {
                connMode = preConnMode & ~mode;
                broadcastConnectionModeChanged(device, connMode);
            } else {
                Log.d(TAG, "disconnect ignore as Vcp is not connected for mode: " + mode);
                return false;
            }

            if (connMode == BluetoothVcp.MODE_NONE) {
                mConnectionMode.remove(device);
                VcpControllerStateMachine stateMachine = mStateMachines.get(device);
                if (stateMachine == null) {
                    Log.w(TAG, "disconnect: device " + device + " not ever connected/connecting");
                    return false;
                }
                int connectionState = stateMachine.getConnectionState();
                if (connectionState != BluetoothProfile.STATE_CONNECTED
                        && connectionState != BluetoothProfile.STATE_CONNECTING) {
                    Log.w(TAG, "disconnect: device " + device
                            + " not connected/connecting, connectionState=" + connectionState);
                    return false;
                }
                stateMachine.sendMessage(VcpControllerStateMachine.DISCONNECT, device);
            } else {
                mConnectionMode.put(device, connMode);
            }
        }
        return true;
    }

    /**
     * Set absolute volume to remote device via VCP connection
     *
     * @param device: remote device instance
     * @param volume: requested volume settings for remote device
     * @return true if set abs volume requst is accepted, false if set
     * abs volume request is rejected
     */
    public boolean setAbsoluteVolume(BluetoothDevice device, int volume, int audioType) {
        synchronized (mStateMachines) {
            Log.i(TAG, "setAbsVolume: device=" + device + ", " + Utils.getUidPidString());
            final VcpControllerStateMachine stateMachine = mStateMachines.get(device);

            if (stateMachine == null) {
                Log.w(TAG, "setAbsVolume: device " + device + " was never connected/connecting");
                return false;
            }

            if (stateMachine.getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
                Log.w(TAG, "setAbsVolume: profile not connected");
                return false;
            }

            stateMachine.sendMessage(VcpControllerStateMachine.SET_VOLUME, volume, audioType, device);
        }
        return true;
    }

    /**
     * Mute or unmute remote device via VCP connection
     *
     * @param device: remote device instance
     * @param enableMute: true if mute, false if unmute
     * @return true if mute requst is accepted, false if mute
     * request is rejected
     */
    public boolean setMute(BluetoothDevice device, boolean enableMute) {
        synchronized (mStateMachines) {
            Log.i(TAG, "setMute: device=" + device + ", " + "enableMute: " + enableMute);
            final VcpControllerStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                Log.w(TAG, "setMute: device " + device + " was never connected/connecting");
                return false;
            }
            if (stateMachine.getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
                Log.w(TAG, "setMute: profile not connected");
                return false;
            }
            if (enableMute) {
                stateMachine.sendMessage(VcpControllerStateMachine.MUTE, device);
            } else {
                stateMachine.sendMessage(VcpControllerStateMachine.UNMUTE, device);
            }
        }
        return true;
    }

    /**
     * Get current absolute volume of the remote device
     *
     * @param device: remote device instance
     * @return current absolute volume of the remote device
     */
    public int getAbsoluteVolume(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final VcpControllerStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                return -1;
            }
            return stateMachine.getVolume();
        }
    }

    /**
     * Get mute status of remote device
     *
     * @param device: remote device instance
     * @return current mute status of the remote device:
     * true if mute status, false if unmute status
     */
    public boolean isMute(BluetoothDevice device) {
        synchronized (mStateMachines) {
            final VcpControllerStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine == null) {
                return false;
            }
            return stateMachine.isMute();
        }
    }

    /**
     * Get the current connection state of the VCP
     *
     * @param device is the remote bluetooth device
     * @return {@link BluetoothProfile#STATE_DISCONNECTED} if VCP is disconnected,
     * {@link BluetoothProfile#STATE_CONNECTING} if VCP is being connected,
     * {@link BluetoothProfile#STATE_CONNECTED} if VCP is connected, or
     * {@link BluetoothProfile#STATE_DISCONNECTING} if VCP is being disconnected
     */
    public int getConnectionState(BluetoothDevice device) {
        synchronized (mStateMachines) {
            VcpControllerStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return sm.getConnectionState();
        }
    }

    /**
     * Get current VCP Connection mode
     *
     * @param device: remote device instance
     * @return current connection mode of VCP:
     * {@link #BluetoothVcp.MODE_NONE} if none VCP connection
     * {@link #BluetoothVcp.MODE_UNICAST} if VCP is connected for unicast
     * {@link #BluetoothVcp.MODE_BROADCAST} if VCP is connected for broadcast
     * {@link #BluetoothVcp.MODE_UNICAST_BROADCAST} if VCP is connected
     * for both unicast and broadcast
     */
    public int getConnectionMode(BluetoothDevice device) {
        synchronized (mStateMachines) {
            if (mConnectionMode.containsKey(device)) {
                return mConnectionMode.get(device);
            }
            return BluetoothVcp.MODE_NONE;
        }
    }

    /**
     * Check if VCP is connected for broadcast mode
     *
     * @param device: remote device instance
     * @return true if VCP is connected for broadcast or uncast-broadcast
     * return false if VCP is connected for unicast-only
     */
    public boolean isBroadcastDevice(BluetoothDevice device) {
        if (device == null)
            return false;

        synchronized (mStateMachines) {
            if (mConnectionMode.containsKey(device)) {
                if ((mConnectionMode.get(device) & BluetoothVcp.MODE_BROADCAST) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean okToConnect(BluetoothDevice device) {
        // Check if this is an incoming connection in Quiet mode.
        if (mAdapterService.isQuietModeEnabled()) {
            Log.e(TAG, "okToConnect: cannot connect to " + device + " : quiet mode enabled");
            return false;
        }

        int bondState = mAdapterService.getBondState(device);
        if (bondState != BluetoothDevice.BOND_BONDED) {
            Log.w(TAG, "okToConnect: return false, bondState=" + bondState);
            return false;
         }
        return true;
    }

    void messageFromNative(VcpStackEvent stackEvent) {
        Objects.requireNonNull(stackEvent.device,
                "Device should never be null, event: " + stackEvent);

        synchronized (mStateMachines) {
            BluetoothDevice device = stackEvent.device;
            VcpControllerStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                if (stackEvent.type == VcpStackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED) {
                    switch (stackEvent.valueInt1) {
                        case VcpStackEvent.CONNECTION_STATE_CONNECTED:
                        case VcpStackEvent.CONNECTION_STATE_CONNECTING:
                            sm = getOrCreateStateMachine(device);
                            break;
                        default:
                            break;
                    }
                }
            }
            if (sm == null) {
                Log.e(TAG, "Cannot process stack event: no state machine: " + stackEvent);
                return;
            }
            sm.sendMessage(VcpControllerStateMachine.STACK_EVENT, stackEvent);
        }
    }

    int getCsipSetId(BluetoothDevice device, ParcelUuid uuid) {
        GroupService csipService = GroupService.getGroupService();
        if (csipService != null) {
            return csipService.getRemoteDeviceGroupId(device, uuid);
        } else {
            return -1;
        }
    }

    void onConnectionStateChangedFromStateMachine(BluetoothDevice device,
            int newState, int prevState) {
        Log.d(TAG, "onConnectionStateChangedFromStateMachine for device: " + device
                    + " newState: " + newState);

        if (device == null) {
            Log.d(TAG, "device is null ");
            return;
        }

        mDpm = DeviceProfileMap.getDeviceProfileMapInstance();
        mAcmService = AcmService.getAcmService();
        BluetoothDevice grpDevice;
        if (mAcmService != null) {
            grpDevice = mAcmService.getGroup(device);
        } else {
            Log.w(TAG, "AcmService is null");
            grpDevice = device;
        }

        synchronized (mStateMachines) {
            if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                int bondState = mAdapterService.getBondState(device);
                if (bondState == BluetoothDevice.BOND_NONE) {
                    removeStateMachine(device);
                }

                if (mAcmService != null &&
                    (mAcmService.isVcpPeerDeviceConnected(device, getCsipSetId(device, null)))) {
                    Log.d(TAG, "VCP Peer device connected, this is not last member, skip update to APM ");
                } else {
                    ///* Update VCP profile disconnected to APM/ACM
                    Log.d(TAG, "All group members are disconnected, update to APM");
                    if (mDpm != null) {
                        mDpm.profileConnectionUpdate(grpDevice,
                            ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL, ApmConst.AudioProfiles.VCP, false);

                        mDpm.profileConnectionUpdate(grpDevice,
                            ApmConst.AudioFeatures.CALL_VOLUME_CONTROL, ApmConst.AudioProfiles.VCP, false);
                    }
                }
                setAbsVolumeSupport(device, false, -1);
                updateConnState(device, newState);
                //*/
                Log.d(TAG, "VCP get disconnected with renderer device: " + device);
            } else if (newState == BluetoothProfile.STATE_CONNECTED) {
                Log.d(TAG, "VCP get connected with renderer device: " + device);

                if (mAcmService != null &&
                    (mAcmService.isVcpPeerDeviceConnected(device, getCsipSetId(device, null)))) {
                    Log.d(TAG, "VCP Peer device connected, this is not first connected member, skip update to APM ");
                } else {
                    ///* Update VCP profile connected to APM/ACM
                    Log.d(TAG, "The first connected memeber, update to APM");
                    if (mDpm != null) {
                        mDpm.profileConnectionUpdate(grpDevice,
                            ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL, ApmConst.AudioProfiles.VCP, true);

                        mDpm.profileConnectionUpdate(grpDevice,
                            ApmConst.AudioFeatures.CALL_VOLUME_CONTROL, ApmConst.AudioProfiles.VCP, true);
                    }
                }
                // Set Abs Volume Support with true until get initial volume of remote
                //*/
            }
        }
    }

    void setAbsVolumeSupport(BluetoothDevice device, boolean isAbsVolSupported, int initial_volume) {
        mAcmService = AcmService.getAcmService();
        if (mAcmService != null) {
            Log.d(TAG, "Update Abs Volume Support to upper layer ");
            mAcmService.setAbsVolSupport(device, isAbsVolSupported, initial_volume);
        }
    }

    void notifyVolumeChanged(BluetoothDevice device, int volume, int audioType) {
        Log.d(TAG, "notify volume changed for renderer device: " + device + " audioType: " + audioType);
        // Notify ACM volume changed for device
        mAcmService = AcmService.getAcmService();
        if (mAcmService != null) {
            mAcmService.onVolumeStateChanged(device, volume, audioType);
        }
        Intent intent = new Intent(BluetoothVcp.ACTION_VOLUME_CHANGED);
        intent.putExtra(BluetoothVcp.EXTRA_VOLUME, volume);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mContext.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
    }

    void notifyMuteChanged(BluetoothDevice device, boolean mute) {
        Log.d(TAG, "notify mute changed for renderer device: " + device + " mute: " + mute);
        // Notify ACM mute changed
        mAcmService = AcmService.getAcmService();
        if (mAcmService != null) {
            mAcmService.onMuteStatusChanged (device, mute);
        }
        Intent intent = new Intent(BluetoothVcp.ACTION_MUTE_CHANGED);
        intent.putExtra(BluetoothVcp.EXTRA_MUTE, mute);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mContext.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
    }

    void broadcastConnectionModeChanged(BluetoothDevice device, int mode) {
        Log.d(TAG, "broadccast connection mode changed for device: " + device + ", mode: " + mode);
        Intent intent = new Intent(BluetoothVcp.ACTION_CONNECTION_MODE_CHANGED);
        intent.putExtra(BluetoothVcp.EXTRA_MODE, mode);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mContext.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
    }

    public void updateConnState(BluetoothDevice device, int newState) {
        Log.d(TAG, "updateConnState: device: " + device + ", state: " + newState);
        VolumeManager mVolumeManager = VolumeManager.get();
        mVolumeManager.onConnStateChange(device, newState, ApmConst.AudioProfiles.VCP);
    }

    private class BondStateChangedReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) {
                return;
            }
            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                                           BluetoothDevice.ERROR);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            Objects.requireNonNull(device, "ACTION_BOND_STATE_CHANGED with no EXTRA_DEVICE");
            bondStateChanged(device, state);
        }
    }

    /**
     * Process a change in the bonding state for a device.
     *
     * @param device the device whose bonding state has changed
     * @param bondState the new bond state for the device. Possible values are:
     * {@link BluetoothDevice#BOND_NONE},
     * {@link BluetoothDevice#BOND_BONDING},
     * {@link BluetoothDevice#BOND_BONDED}.
     */
    @VisibleForTesting
    void bondStateChanged(BluetoothDevice device, int bondState) {
        if (DBG) {
            Log.d(TAG, "Bond state changed for device: " + device + " state: " + bondState);
        }
        // Remove state machine if the bonding for a device is removed
        if (bondState != BluetoothDevice.BOND_NONE) {
            return;
        }

        synchronized (mStateMachines) {
             VcpControllerStateMachine sm = mStateMachines.get(device);
             if (sm == null) {
                 return;
             }
             if (sm.getConnectionState() != BluetoothProfile.STATE_DISCONNECTED) {
                 return;
             }
             mConnectionMode.remove(device);
             removeStateMachine(device);
        }
    }

    private void removeStateMachine(BluetoothDevice device) {
        synchronized (mStateMachines) {
            VcpControllerStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                Log.w(TAG, "removeStateMachine: device " + device
                        + " does not have a state machine");
                return;
            }
            Log.i(TAG, "removeStateMachine: removing state machine for device: " + device);
            sm.doQuit();
            sm.cleanup();
            mStateMachines.remove(device);
        }
    }

    private VcpControllerStateMachine getOrCreateStateMachine(BluetoothDevice device) {
        if (device == null) {
            Log.e(TAG, "getOrCreateStateMachine failed: device cannot be null");
            return null;
        }
        synchronized (mStateMachines) {
            VcpControllerStateMachine sm = mStateMachines.get(device);
            if (sm != null) {
                return sm;
            }
            if (mStateMachines.size() >= MAX_VCP_STATE_MACHINES) {
                Log.e(TAG, "Maximum number of VCP state machines reached: "
                        + MAX_VCP_STATE_MACHINES);
                return null;
            }
            if (DBG) {
                Log.d(TAG, "Creating a new state machine for " + device);
            }
            sm = VcpControllerStateMachine.make(device, this, mContext,
                    mNativeInterface, mStateMachinesThread.getLooper());
            mStateMachines.put(device, sm);
            return sm;
        }
    }

    private class VcpControllerTestReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(ACTION_CONNECT_DEVICE)) {
                Log.d(TAG, "Receive ACTION_CONNECT_DEVICE");
                int mode = intent.getIntExtra(BluetoothVcp.EXTRA_MODE, 0);
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                connect(device, mode);
            } else if (action.equals(ACTION_DISCONNECT_DEVICE)) {
                Log.d(TAG, "Receive ACTION_DISCONNECT_DEVICE");
                int mode = intent.getIntExtra(BluetoothVcp.EXTRA_MODE, 0);
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                disconnect(device, mode);
            }
        }
    }
}

