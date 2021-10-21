/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.

 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package android.bluetooth;

import android.Manifest;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SdkConstant;
import android.annotation.SystemApi;
import android.annotation.SdkConstant.SdkConstantType;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.IBluetoothGatt;
import android.bluetooth.IBluetoothManager;
import android.bluetooth.IBleBroadcastAudioScanAssistCallback;
import android.bluetooth.IBluetoothSyncHelper;
import android.bluetooth.BluetoothAdapter.LeScanCallback;
import android.os.Binder;
import android.os.IBinder;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import android.content.Context;

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;

import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.PeriodicAdvertisingCallback;
import android.bluetooth.le.PeriodicAdvertisingManager;
import android.bluetooth.le.PeriodicAdvertisingReport;
import android.bluetooth.le.BluetoothLeScanner;
import android.os.SystemProperties;
import java.util.IdentityHashMap;

/**
 * This class provides methods to perform Broadcast Scan Assistance client Profile related
 * operations.
 * It uses Bluetooth GATT APIs to achieve Braodcast Scan assistance client operations. Application should ensure
 * BASS profile is connected with the given remote device before performing the operations using
 * {@link BleBroadcastAudioScanAssistManager} interface operations
 *
 * <p>BluetoothSyncHelper is a proxy object for controlling the Bluetooth Scan Offloader (BASS client)
 * Service via IPC.
 *
 * <p> Use {@link BluetoothAdapter#getProfileProxy} to get
 * the BluetoothScanOfflaoder proxy object. Use
 * {@link BluetoothAdapter#closeProfileProxy} to close the service connection.
 *
 * <p> Use {@link BluetoothAdapter#getProfileProxy} to get
 * the BluetoothSyncHelper proxy object. Use
 * {@link BluetoothAdapter#closeProfileProxy} to close the service connection.
 *
 * <b>Note:</b> Most of the methods here require
 * {@link android.Manifest.permission#BLUETOOTH_ADMIN} permission.
 *
 * @hide
 */
public final class BluetoothSyncHelper implements BluetoothProfile {

    private static final String TAG = "BluetoothSyncHelper";
    private static final boolean DBG = true;

    private BluetoothAdapter mBluetoothAdapter;
    /* maps callback, to callback wrapper and sync handle */
    private Map<BleBroadcastAudioScanAssistCallback,
             IBleBroadcastAudioScanAssistCallback /* callbackWrapper */> mAppCallbackWrappers;

    private Map<BluetoothDevice,
                 BleBroadcastAudioScanAssistManager> sBleAssistManagers = null;
    private Context mContext = null;

   /**
     * Intent used to broadcast the change in connection state of the Bass client
     * profile.
     *
     * <p>This intent will have 3 extras:
     * <ul>
     * <li> {@link #EXTRA_STATE} - The current state of the profile. </li>
     * <li> {@link #EXTRA_PREVIOUS_STATE}- The previous state of the profile.</li>
     * <li> {@link BluetoothDevice#EXTRA_DEVICE} - The remote device. </li>
     * </ul>
     *
     * <p>{@link #EXTRA_STATE} or {@link #EXTRA_PREVIOUS_STATE} can be any of
     * {@link #STATE_DISCONNECTED}, {@link #STATE_CONNECTING},
     * {@link #STATE_CONNECTED}, {@link #STATE_DISCONNECTING}.
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH} permission to
     * receive.
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ACTION_CONNECTION_STATE_CHANGED =
            "android.bluetooth.bc.profile.action.CONNECTION_STATE_CHANGED";


    private final BluetoothProfileConnector<IBluetoothSyncHelper> mProfileConnector =
            new BluetoothProfileConnector(this, BluetoothProfile.BC_PROFILE,
                    "BluetoothSyncHelper", IBluetoothSyncHelper.class.getName()) {
                @Override
                public IBluetoothSyncHelper getServiceInterface(IBinder service) {
                    return IBluetoothSyncHelper.Stub.asInterface(Binder.allowBlocking(service));
                }
    };

    /*package*/ void close() {
        mProfileConnector.disconnect();
        mAppCallbackWrappers.clear();
    }

    /*package*/ IBluetoothSyncHelper getService() {
        return mProfileConnector.getService();
    }

    static boolean isSupported() {
        boolean isSupported = SystemProperties.getBoolean("persist.vendor.service.bt.bc", true);
        log("BluetoothSyncHelper: isSupported returns " + isSupported);
        return isSupported;
    }
    /**
     * Create a BluetoothHeadset proxy object.
     */
    /*package*/ BluetoothSyncHelper(Context context, ServiceListener listener) {
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        mProfileConnector.connect(context, listener);
        BluetoothManager bluetoothManager = context.getSystemService(
                 BluetoothManager.class);
        mAppCallbackWrappers = new IdentityHashMap<BleBroadcastAudioScanAssistCallback, IBleBroadcastAudioScanAssistCallback>();
        sBleAssistManagers = new IdentityHashMap<BluetoothDevice, BleBroadcastAudioScanAssistManager>();
        mContext = context;
    }

    /**
     * Interface to get Broadcast Audio Scan assistance for LE Audio usecases.This is instantiated per BluetoothDevice
     * which is Scan delegator
     * Application will get an Instance of the  {@link BleBroadcastAudioScanAssistManager} for the given
     * scan delegator device
     *
     * @param BluetoothDevice Scan Delegator device for which BLE Broadcast SCAN Assistance operations will
     * be performed
     * @param {@link #BleBroadcastAudioScanAssistCallback} where callbacks related to BLE Broadcast Scan
     * assistance will be deliverd
     * @hide
     */
    public BleBroadcastAudioScanAssistManager getBleBroadcastAudioScanAssistManager(
                                                  BluetoothDevice device,
                                                  BleBroadcastAudioScanAssistCallback callback) {
        if (isSupported() == false) {
            Log.e(TAG, "Broadcast scan assistance not supported");
            return null;
        }

        BleBroadcastAudioScanAssistManager assistMgr = null;
        if (sBleAssistManagers != null) {
            assistMgr = sBleAssistManagers.get(device);
        }
        if (assistMgr == null) {
            assistMgr = new BleBroadcastAudioScanAssistManager(this, device,
                                                  callback);
        } else {
            //object already exists, just registers the callback and retrun the same object
            log("calling registerAppCb only");
        }
        registerAppCallback(device, callback);
        return assistMgr;
    }


   /**
     * Initiate connection to a BASS server profile of the remote bluetooth device.
     *
     * <p> This API returns false in scenarios like the profile on the
     * device is already connected or Bluetooth is not turned on.
     * When this API returns true, it is guaranteed that
     * connection state intent for the profile will be broadcasted with
     * the state. Users can get the connection state of the profile
     * from this intent.
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH_ADMIN}
     * permission.
     *
     * @param device Remote Bluetooth Device
     * @return false on immediate error, true otherwise
     * @hide
     */
    public boolean connect(BluetoothDevice device) {
        log("connect(" + device + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled() && isValidDevice(device)) {
                return service.connect(device);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
    }

    /**
     * Initiate disconnection from a profile
     *
     * <p> This API will return false in scenarios like the profile on the
     * Bluetooth device is not in connected state etc. When this API returns,
     * true, it is guaranteed that the connection state change
     * intent will be broadcasted with the state. Users can get the
     * disconnection state of the profile from this intent.
     *
     * <p> If the disconnection is initiated by a remote device, the state
     * will transition from {@link #STATE_CONNECTED} to
     * {@link #STATE_DISCONNECTED}. If the disconnect is initiated by the
     * host (local) device the state will transition from
     * {@link #STATE_CONNECTED} to state {@link #STATE_DISCONNECTING} to
     * state {@link #STATE_DISCONNECTED}. The transition to
     * {@link #STATE_DISCONNECTING} can be used to distinguish between the
     * two scenarios.
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH_ADMIN}
     * permission.
     *
     * @param device Remote Bluetooth Device
     * @return false on immediate error, true otherwise
     * @hide
     */
    public boolean disconnect(BluetoothDevice device) {
        if (DBG) log("disconnect(" + device + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled() && isValidDevice(device)) {
                return service.disconnect(device);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull List<BluetoothDevice> getConnectedDevices() {
        log("getConnectedDevices()");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()) {
                return service.getConnectedDevices();
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return new ArrayList<BluetoothDevice>();
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return new ArrayList<BluetoothDevice>();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull List<BluetoothDevice> getDevicesMatchingConnectionStates(
    @NonNull int[] states) {
        log("getDevicesMatchingStates()");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()) {
                return service.getDevicesMatchingConnectionStates(states);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return new ArrayList<BluetoothDevice>();
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return new ArrayList<BluetoothDevice>();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public @BluetoothProfile.BtProfileState int getConnectionState(
    @NonNull BluetoothDevice device) {
        log("getState(" + device + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                return service.getConnectionState(device);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return BluetoothProfile.STATE_DISCONNECTED;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return BluetoothProfile.STATE_DISCONNECTED;
        }
    }
    /**
     * Get the connection policy of the profile.
     *
     * <p> The connection policy can be any of:
     * {@link #CONNECTION_POLICY_ALLOWED}, {@link #CONNECTION_POLICY_FORBIDDEN},
     * {@link #CONNECTION_POLICY_UNKNOWN}
     *
     * @param device Bluetooth device
     * @return connection policy of the device
     * @hide
     */
    //@SystemApi
    @RequiresPermission(Manifest.permission.BLUETOOTH)
    public int getConnectionPolicy(@NonNull BluetoothDevice device) {
        log("getConnectionPolicy(" + device + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                return service.getConnectionPolicy(device);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
        }
    }

    /**
     * Set connection policy of the profile
     *
     * <p> The device should already be paired.
     * Connection policy can be one of {@link #CONNECTION_POLICY_ALLOWED},
     * {@link #CONNECTION_POLICY_FORBIDDEN}, {@link #CONNECTION_POLICY_UNKNOWN}
     *
     * @param device Paired bluetooth device
     * @param connectionPolicy is the connection policy to set to for this profile
     * @return true if connectionPolicy is set, false on error
     * @hide
     */
    //@SystemApi
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADMIN)
    public boolean setConnectionPolicy(@NonNull BluetoothDevice device,
            int connectionPolicy) {
        if (DBG) log("setConnectionPolicy(" + device + ", " + connectionPolicy + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                if (connectionPolicy != BluetoothProfile.CONNECTION_POLICY_FORBIDDEN
                        && connectionPolicy != BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                    return false;
                }
                return service.setConnectionPolicy(device, connectionPolicy);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
    }

    private IBleBroadcastAudioScanAssistCallback wrap(BleBroadcastAudioScanAssistCallback callback,
                 Handler handler) {
             return new IBleBroadcastAudioScanAssistCallback.Stub() {
                 public void onBleBroadcastSourceFound(ScanResult scanres) {
                     handler.post(new Runnable() {
                         @Override
                         public void run() {
                             log("calling onBleBroadcastSourceFound for " +
                                                 "scanres:" + scanres);
                             callback.onBleBroadcastSourceFound(
                                                      scanres);
                         }
                      });
                 }

                 public void onBleBroadcastAudioSourceSelected(BluetoothDevice device, int status,
                         List<BleBroadcastSourceChannel> broadcastSourceChannels) {
                     handler.post(new Runnable() {
                       @Override
                       public void run() {
                           log("calling onBleBroadcastSourceSelected for " +
                                                 "status:" + status);
                           callback.onBleBroadcastSourceSelected(device,
                                           status, broadcastSourceChannels);
                       }
                    });
                 }
                 public void onBleBroadcastAudioSourceAdded(BluetoothDevice rcvr,
                                              byte srcId,
                                             int status) {
                     handler.post(new Runnable() {
                         @Override
                         public void run() {
                             log("calling onBleBroadcastAudioSourceAdded for " + rcvr +
                                 "srcId:" + srcId + "status:" + status);
                             callback.onBleBroadcastAudioSourceAdded(rcvr, srcId,
                                     status);
                         }
                     });
                 }
                 public void onBleBroadcastAudioSourceUpdated(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
                     handler.post(new Runnable() {
                         @Override
                         public void run() {
                             log("calling onBleBroadcastAudioSourceUpdated for " + rcvr +
                                 "srcId:" + srcId + "status:" + status);
                             callback.onBleBroadcastAudioSourceUpdated(rcvr, srcId,
                                     status);
                         }
                     });
                 }
                 public void onBleBroadcastPinUpdated(BluetoothDevice rcvr,
                                                byte srcId,
                                                int status) {
                     handler.post(new Runnable() {
                         @Override
                         public void run() {
                             log("calling onBleBroadcastPinUpdated for " + rcvr +
                                 "srcId:" + srcId + "status:" + status);
                             callback.onBleBroadcastPinUpdated(rcvr, srcId,
                                     status);
                             // App can still unregister the sync until notified it's lost.
                             // Remove callback after app was notifed.
                             //mCallbackWrappers.remove(callback);
                         }
                     });
                 }

                 public void onBleBroadcastAudioSourceRemoved(BluetoothDevice rcvr,
                                             byte srcId,
                                             int status) {
                     handler.post(new Runnable() {
                         @Override
                         public void run() {
                             log("calling onBleBroadcastAudioSourceRemoved for " + rcvr +
                                 "srcId:" + srcId + "status:" + status);
                             callback.onBleBroadcastAudioSourceRemoved(rcvr, srcId,
                                     status);

                         }
                     });
                 }
             };
         }


     boolean startScanOffload (BluetoothDevice device, boolean isGroupOp) {
        log("startScanOffload(" + device + ", isGroupOp: " + isGroupOp + ")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                return service.startScanOffload(device, isGroupOp);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
     }

     boolean stopScanOffload (BluetoothDevice device, boolean isGroupOp) {
        log("stopScanOffload(" + device + ", isGroupOp: " + isGroupOp + ")" );
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                return service.stopScanOffload(device, isGroupOp);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
     }

     boolean searchforLeAudioBroadcasters (BluetoothDevice device) {
         log("searchforLeAudioBroadcasters(" + device + ")");
         final IBluetoothSyncHelper service = getService();
         try {
             if (service != null && isEnabled()
                     && isValidDevice(device)) {
                 return service.searchforLeAudioBroadcasters(device);
             }
             if (service == null) Log.w(TAG, "Proxy not attached to service");
             return false;
         } catch (RemoteException e) {
             Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
             return false;
         }
     }

     @RequiresPermission(Manifest.permission.BLUETOOTH_ADMIN)
     boolean stopSearchforLeAudioBroadcasters(BluetoothDevice device) {
         log("stopSearchforLeAudioBroadcasters(" + device + ")");
         final IBluetoothSyncHelper service = getService();
         try {
             if (service != null && isEnabled()
                     && isValidDevice(device)) {
                 return service.stopSearchforLeAudioBroadcasters(device);
             }
             if (service == null) Log.w(TAG, "Proxy not attached to service");
             return false;
         } catch (RemoteException e) {
             Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
             return false;
         }
     }

     boolean selectBroadcastSource (BluetoothDevice device, ScanResult scanRes, boolean isGroupOp) {
        log("selectBroadcastSource(" + device + ": groupop" + isGroupOp +")");
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                return service.selectBroadcastSource(device, scanRes, isGroupOp);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return false;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return false;
        }
     }

     void registerAppCallback(BluetoothDevice device, BleBroadcastAudioScanAssistCallback appCallback) {
          log("registerAppCallback device :" + device + "appCB: " + appCallback);
          Handler handler = new Handler(Looper.getMainLooper());

          IBleBroadcastAudioScanAssistCallback wrapped = wrap(appCallback, handler);
          final IBluetoothSyncHelper service = getService();
          try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
               service.registerAppCallback(device, wrapped);
               if (mAppCallbackWrappers != null) {
                   mAppCallbackWrappers.put(appCallback, wrapped);
               }
            }
            if (service == null) {
                Log.w(TAG, "Proxy not attached to service");
                return;
            }
          } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return;
          }
     }

     void unregisterAppCallback(BluetoothDevice device, BleBroadcastAudioScanAssistCallback appCallback) {
         log("unregisterAppCallback: device" + device + "appCB:" + appCallback);
         // Remove callback after app was notifed.

         final IBluetoothSyncHelper service = getService();
         IBleBroadcastAudioScanAssistCallback cb = mAppCallbackWrappers.get(device);
         try {
            if (service != null && isEnabled()
                    && isValidDevice(device)) {
                service.unregisterAppCallback(device, cb);
                mAppCallbackWrappers.remove(appCallback);
                return;
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
            return;
          } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return;
          }
     }


    boolean addBroadcastSource (BluetoothDevice sinkDevice,
                                          BleBroadcastSourceInfo srcInfo,
                                          boolean isGroupOp) {
        log("addBroadcastSource  for :" + sinkDevice
            + "SourceInfo: " + srcInfo+ "isGroupOp: " + isGroupOp);
        boolean ret = false;
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                    && isValidDevice(sinkDevice)) {

                return service.addBroadcastSource(sinkDevice, srcInfo, isGroupOp);
            }
            if (service == null)
            {
                Log.w(TAG, "Proxy not attached to service");
                ret = false;
            }
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            ret = false;
        }
        return ret;
    }
    boolean updateBroadcastSource (BluetoothDevice device,
                                      BleBroadcastSourceInfo srcInfo,
                                      boolean isGroupOp) {
            //Same device can have more than one SourceId
            log("updateBroadcastSource for :" + device +
                "SourceInfo: " + srcInfo+ "isGroupOp: " + isGroupOp);
            boolean ret = false;
            final IBluetoothSyncHelper service = getService();
            try {
                if (service != null && isEnabled()
                    && isValidDevice(device)) {
                  return service.updateBroadcastSource(device,
                                            srcInfo, isGroupOp);
                }
                if (service == null)
                {
                    Log.w(TAG, "Proxy not attached to service");
                    ret = false;
                }
            } catch (RemoteException e) {
                Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
                ret = false;
            }
            return ret;
    }

     boolean setBroadcastCode (BluetoothDevice device,
                                BleBroadcastSourceInfo srcInfo,
                                boolean isGroupOp) {
            //Same device can have more than one SourceId
            log("setBroadcastCode for :" + device);
            log("SourceInfo: " + srcInfo+ "isGroupOp: " + isGroupOp);
            boolean ret = false;
            final IBluetoothSyncHelper service = getService();
            try {
                if (service != null && isEnabled()
                    && isValidDevice(device)) {
                   return service.setBroadcastCode(device,
                                                 srcInfo, isGroupOp);
                }
                if (service == null)
                {
                    Log.w(TAG, "Proxy not attached to service");
                    ret = false;
                }
            } catch (RemoteException e) {
                Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
                ret = false;
            }
            return ret;
    }
    boolean removeBroadcastSource (BluetoothDevice device,
                                      byte sourceId,
                                      boolean isGroupOp
                                      ) {
            log("removeBroadcastSource for :" + device +
                "SourceId: " + sourceId + "isGroupOp: " + isGroupOp);
            final IBluetoothSyncHelper service = getService();
            boolean ret = false;
            try {
                if (service != null && isEnabled()
                    && isValidDevice(device)) {
                   return service.removeBroadcastSource(device, sourceId
                                                          , isGroupOp);
                }
                if (service == null)
                {
                    Log.w(TAG, "Proxy not attached to service");
                    ret = false;
                }
            } catch (RemoteException e) {
                Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
                ret = false;
            }
            return ret;
    }

    List<BleBroadcastSourceInfo> getAllBroadcastSourceInformation (BluetoothDevice device) {
        log("GetAllBroadcastReceiverStates for :" + device);
        final IBluetoothSyncHelper service = getService();
        try {
            if (service != null && isEnabled()
                && isValidDevice(device)) {
                return service.getAllBroadcastSourceInformation(device);
            }
            if (service == null) Log.w(TAG, "Proxy not attached to service");
                return null;
        } catch (RemoteException e) {
            Log.e(TAG, "Stack:" + Log.getStackTraceString(new Throwable()));
            return null;
        }
     }
    private boolean isEnabled() {
        if (mBluetoothAdapter.getState() == BluetoothAdapter.STATE_ON) return true;
        return false;
    }

    private boolean isValidDevice(BluetoothDevice device) {
        if (device == null) return false;

        if (BluetoothAdapter.checkBluetoothAddress(device.getAddress())) return true;
        return false;
    }

    private static void log(String msg) {
        BleBroadcastSourceInfo.BASS_Debug(TAG, msg);
    }

}
