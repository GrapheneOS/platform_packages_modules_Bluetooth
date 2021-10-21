/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.
 *
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

/**
 * Bluetooth Bassclient StateMachine. There is one instance per remote device.
 *  - "Disconnected" and "Connected" are steady states.
 *  - "Connecting" and "Disconnecting" are transient states until the
 *     connection / disconnection is completed.
 *  - "ConnectedProcessing" is an intermediate state to ensure, there is only
 *    one Gatt transaction from the profile at any point of time
 *
 *
 *                        (Disconnected)
 *                           |       ^
 *                   CONNECT |       | DISCONNECTED
 *                           V       |
 *                 (Connecting)<--->(Disconnecting)
 *                           |       ^
 *                 CONNECTED |       | DISCONNECT
 *                           V       |
 *                          (Connected)
 *                           |       ^
 *                 GATT_TXN  |       | GATT_TXN_DONE/GATT_TXN_TIMEOUT
 *                           V       |
 *                          (ConnectedProcessing)
 * NOTES:
 *  - If state machine is in "Connecting" state and the remote device sends
 *    DISCONNECT request, the state machine transitions to "Disconnecting" state.
 *  - Similarly, if the state machine is in "Disconnecting" state and the remote device
 *    sends CONNECT request, the state machine transitions to "Connecting" state.
 *  - Whenever there is any Gatt Write/read, State machine will moved "ConnectedProcessing" and
 *    all other requests (add, update, remove source) operations will be deferred in "ConnectedProcessing" state
 *  - Once the gatt transaction is done (or after a specified timeout of no response), State machine will
 *    move back to "Connected" and try to process the deferred requests as needed
 *
 *                    DISCONNECT
 *    (Connecting) ---------------> (Disconnecting)
 *                 <---------------
 *                      CONNECT
 *
 */

package com.android.bluetooth.bc;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothSyncHelper;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.IBleBroadcastAudioScanAssistCallback;
import android.bluetooth.BleBroadcastAudioScanAssistCallback;
import com.android.bluetooth.Utils;

//CSIP related imports
///*_CSIP
import com.android.bluetooth.groupclient.GroupService;
import android.bluetooth.BluetoothGroupCallback;
import android.bluetooth.DeviceGroup;
//_CSIP*/

///*_VCP
import android.bluetooth.BluetoothVcp;
import com.android.bluetooth.vcp.VcpController;
//_VCP*/

import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.PeriodicAdvertisingCallback;
import android.bluetooth.le.PeriodicAdvertisingManager;
import android.bluetooth.le.PeriodicAdvertisingReport;

import android.bluetooth.IBluetoothManager;
import android.os.ServiceManager;
import android.os.IBinder;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import android.content.Intent;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import java.util.UUID;
import java.util.Collection;
import android.os.UserHandle;
import java.lang.IllegalArgumentException;

import com.android.bluetooth.btservice.ProfileService;
/*_PACS
import com.android.bluetooth.pacsclient.PacsClientService;
_PACS*/

import com.android.bluetooth.btservice.ServiceFactory;
///*_BMS
import com.android.bluetooth.broadcast.BroadcastService;
//_BMS*/

import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.lang.String;
import java.lang.StringBuffer;
import java.lang.Integer;

import java.nio.ByteBuffer;
import java.lang.Byte;
import java.util.stream.IntStream;
import android.os.SystemProperties;
import android.os.ParcelUuid;


final class BassClientStateMachine extends StateMachine {
    private static final String TAG = "BassClientStateMachine";
    public static final boolean BASS_DBG = true;
    //public static final boolean BASS_DBG = Log.isLoggable(TAG, Log.DEBUG);

    private boolean mIsWhitelist = false;

    static final int BCAST_RECEIVER_STATE_LENGTH = 15;
    static final int CONNECT = 1;
    static final int DISCONNECT = 2;
    static final int CONNECTION_STATE_CHANGED = 3;
    static final int GATT_TXN_PROCESSED = 4;
    static final int READ_BASS_CHARACTERISTICS= 5;
    static final int START_SCAN_OFFLOAD = 6;
    static final int STOP_SCAN_OFFLOAD = 7;
    static final int SELECT_BCAST_SOURCE = 8;
    static final int ADD_BCAST_SOURCE = 9;
    static final int UPDATE_BCAST_SOURCE = 10;
    static final int SET_BCAST_CODE = 11;
    static final int REMOVE_BCAST_SOURCE = 12;
    static final int GATT_TXN_TIMEOUT = 13;
    static final int PSYNC_ACTIVE_TIMEOUT = 14;
    public static final int CSIP_CONNECTION_STATE_CHANGED = 15;
    static final int CONNECT_TIMEOUT = 16;

    //30 secs time out for all gatt writes
    static final int GATT_TXN_TIMEOUT_MS = 30000;

    //3 min time out for keeping PSYNC active
    static final int PSYNC_ACTIVE_TIMEOUT_MS = 3*60000;
    //2 secs time out achieving psync
    static final int PSYNC_TIMEOUT = 200;

    int NUM_OF_BROADCAST_RECEIVER_STATES = 0;

    private final Disconnected mDisconnected;
    private final Connected mConnected;
    private final Connecting mConnecting;
    private final Disconnecting mDisconnecting;
    private final ConnectedProcessing mConnectedProcessing;
    private int mLastConnectionState = -1;
    private static int mConnectTimeoutMs = 30000;
    private boolean mMTUChangeRequested = false;
    private boolean mDiscoveryInitiated = false;

    private BCService mService;
    private final BluetoothDevice mDevice;
    private BluetoothGatt mBluetoothGatt = null;

    //BASS Characteristics UUID
    public static final UUID BASS_UUID = UUID.fromString("0000184F-0000-1000-8000-00805F9B34FB");
    private static final UUID BASS_BCAST_AUDIO_SCAN_CTRL_POINT = UUID.fromString("00002BC7-0000-1000-8000-00805F9B34FB");
    private static final UUID BASS_BCAST_RECEIVER_STATE = UUID.fromString("00002BC8-0000-1000-8000-00805F9B34FB");
    private static final UUID CLIENT_CHARACTERISTIC_CONFIG = UUID.fromString(
             "00002902-0000-1000-8000-00805f9b34fb");
    private List<BluetoothGattCharacteristic> mBroadcastReceiverStates;
    private BluetoothGattCharacteristic mBroadcastScanControlPoint;
    /*key is combination of sourceId, Address and advSid for this hashmap*/
    private final Map<Integer, BleBroadcastSourceInfo> mBleBroadcastSourceInfos;
    private boolean mFirstTimeBisDiscovery = false;
    private int mPASyncRetryCounter = 0;
    private ScanResult mScanRes = null;

    BluetoothAdapter mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    private ServiceFactory mFactory = new ServiceFactory();
    ///*_BMS
    private BroadcastService mBAService = null;
    //_BMS*/

    private final byte[] REMOTE_SCAN_STOP = {00};
    private final byte[] REMOTE_SCAN_START = {01};
    private byte BASS_ADD_SOURCE_OPCODE = 0x02;
    private byte BASS_UPDATE_SOURCE_OPCODE = 0x03;
    private byte BASS_SET_BCAST_PIN_OPCODE = 0x04;
    private byte BASS_REMOVE_SOURCE_OPCODE = 0x05;

    private static int num_of_recever_states = 0;
    private static int PIN_CODE_CMD_LEN = 18;
    private final int BASS_MAX_BYTES = 100;
    private int mPendingOperation = -1;
    private byte mPendingSourceId = -1;
    public static byte INVALID_SRC_ID = -1;
    private int  GATT_TXN_TOUT_ERROR = -1;
    private BleBroadcastSourceInfo mSetBroadcastPINSrcInfo = null;
    private boolean mSetBroadcastCodePending = false;

    //types of command for  set broadcast PIN operation
    public int FRESH = 1;
    private int QUEUED = 2;

    //types of command for select and add Broadcast source operations
    public int AUTO = 1;
    public int USER = 2;

    //types of operation for Select source to determine
    //if psync achieved on behalf of single device or multiple devices
    public int GROUP_OP = 1;
    public int NON_GROUP_OP = 0;

    public static int BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC = 0;

    //Service data Octet0
    private static int BROADCAST_ADV_ADDRESS_DONT_MATCHES_EXT_ADV_ADDRESS = 0x00000001;
    private static int BROADCAST_ADV_ADDRESS_DONT_MATCHES_SOURCE_ADV_ADDRESS = 0x00000002;

    //Psync and PAST interfaces
    private PeriodicAdvertisingManager mPeriodicAdvManager;
    private static UUID BASIC_AUDIO_UUID = UUID.fromString("00001851-0000-1000-8000-00805F9B34FB");
    private boolean mAutoAssist = false;
    private boolean mNoReverse = false;
    private boolean mAutoTriggerred = false;
    private boolean mSyncingOnBehalfOfGroup = false;
    private boolean mNoStopScanOffload = false;

    //CSET interfaces
    ///*_CSIP
    private GroupService mSetCoordinator = GroupService.getGroupService();
    private boolean mCsipConnected = false;
    //_CSIP*/

    private boolean mPacsAvail = false;
    private boolean mDefNoPAS = false;
    private boolean mNoPast = false;
    private boolean mNoCSIPReconn = false;
    private boolean mPublicAddrForcSrc = false;
    private boolean mForceSB = false;
    private boolean mVcpForBroadcast = false;

    private int BROADCAST_SOURCE_ID_LENGTH = 3;
    private byte mTempSourceId = 0;
    //broadcast receiver state indicies
    private static final int BCAST_RCVR_STATE_SRC_ID_IDX = 0;
    private static final int BCAST_RCVR_STATE_SRC_ADDR_TYPE_IDX = 1;
    private static final int BCAST_RCVR_STATE_SRC_ADDR_START_IDX = 2;
    private static final int BCAST_RCVR_STATE_SRC_BCAST_ID_START_IDX = 9;
    private static final int BCAST_RCVR_STATE_SRC_ADDR_SIZE = 6;
    private static final int BCAST_RCVR_STATE_SRC_ADV_SID_IDX = 8;
    private static final int BCAST_RCVR_STATE_PA_SYNC_IDX = 12;
    private static final int BCAST_RCVR_STATE_ENC_STATUS_IDX = 13;
    private static final int BCAST_RCVR_STATE_BADCODE_START_IDX = 14;
    private static final int BCAST_RCVR_STATE_BADCODE_SIZE = 16;


    private static final int BCAST_RCVR_STATE_BIS_SYNC_START_IDX = 10;
    private static final int BCAST_RCVR_STATE_BIS_SYNC_SIZE = 4;
    private static final int BCAST_RCVR_STATE_METADATA_LENGTH_IDX = 15;
    private static final int BCAST_RCVR_STATE_METADATA_START_IDX = 16;
    BassClientStateMachine(BluetoothDevice device, BCService svc,
            Looper looper) {
        super(TAG + "(" + device.toString() + ")", looper);
        mDevice = device;
        mService = svc;

        mDisconnected = new Disconnected();
        mDisconnecting = new Disconnecting();
        mConnected = new Connected();
        mConnecting = new Connecting();
        mConnectedProcessing = new  ConnectedProcessing();

        addState(mDisconnected);
        addState(mDisconnecting);
        addState(mConnected);
        addState(mConnecting);
        addState(mConnectedProcessing);

        setInitialState(mDisconnected);
        mBroadcastReceiverStates = new ArrayList<BluetoothGattCharacteristic>();
        mBleBroadcastSourceInfos = new HashMap<Integer, BleBroadcastSourceInfo>();

        //PSYNC and PAST instances
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
        if (mBluetoothAdapter != null) {
            mPeriodicAdvManager = mBluetoothAdapter.getPeriodicAdvertisingManager();
        }
        ///*_BMS
        mBAService = BroadcastService.getBroadcastService();
        //_BMS*/

        mNoReverse = SystemProperties.getBoolean("persist.vendor.service.bt.nReverse", false);
        mAutoAssist = SystemProperties.getBoolean("persist.vendor.service.bt.autoassist", false);
        mIsWhitelist = SystemProperties.getBoolean("persist.vendor.service.bt.wl", true);
        mDefNoPAS = SystemProperties.getBoolean("persist.vendor.service.bt.defNoPAS", false);
        mNoPast = SystemProperties.getBoolean("persist.vendor.service.bt.noPast", false);
        mNoCSIPReconn = SystemProperties.getBoolean("persist.vendor.service.bt.noCsipRec", false);
        mPublicAddrForcSrc = SystemProperties.getBoolean("persist.vendor.service.bt.pAddrForcSource", true);
        mForceSB = SystemProperties.getBoolean("persist.vendor.service.bt.forceSB", false);
        mVcpForBroadcast = SystemProperties.getBoolean("persist.vendor.service.bt.vcpForBroadcast", true);
    }

    static BassClientStateMachine make(BluetoothDevice device, BCService svc,
            Looper looper) {
        Log.d(TAG, "make for device " + device);
        BassClientStateMachine BassclientSm = new BassClientStateMachine(device, svc,
                looper);
        BassclientSm.start();
        return BassclientSm;
    }

    public void doQuit() {
        log("doQuit for device " + mDevice);
        quitNow();
    }

    public void cleanup() {
        log("cleanup for device " + mDevice);
        clearCharsCache();

        if (mBluetoothGatt != null) {
            log("disconnect gatt");
            mBluetoothGatt.disconnect();
            mBluetoothGatt.close();
            mBluetoothGatt = null;
        }
        mPendingOperation = -1;
        mPendingSourceId = -1;
    }

    BleBroadcastSourceInfo getBroadcastSourceInfoForSourceDevice (BluetoothDevice srcDevice) {
        List<BleBroadcastSourceInfo> currentSourceInfos =
                getAllBroadcastSourceInformation();
        BleBroadcastSourceInfo srcInfo = null;
        for (int i=0; i<currentSourceInfos.size(); i++) {
            BluetoothDevice device = currentSourceInfos.get(i).getSourceDevice();
            if (device != null && device.equals(srcDevice)) {
                srcInfo = currentSourceInfos.get(i);
                Log.e(TAG, "getBroadcastSourceInfoForSourceDevice: returns for: " + srcDevice + "&srcInfo" + srcInfo);
                return srcInfo;
            }
        }
        return null;
     }

    BleBroadcastSourceInfo getBroadcastSourceInfoForSourceId (int srcId) {
        List<BleBroadcastSourceInfo> currentSourceInfos =
                getAllBroadcastSourceInformation();
        BleBroadcastSourceInfo srcInfo = null;
        for (int i=0; i<currentSourceInfos.size(); i++) {
            int sId = currentSourceInfos.get(i).getSourceId();
            if (srcId == sId) {
                srcInfo = currentSourceInfos.get(i);
                Log.e(TAG, "getBroadcastSourceInfoForSourceId: returns for: " + srcId + "&srcInfo" + srcInfo);
                return srcInfo;
            }
        }
        return null;
     }

    void parseBaseData(BluetoothDevice device, int syncHandle, byte[] serviceData) {
        log("parseBaseData" + Arrays.toString(serviceData));
        BaseData base_ = new BaseData(serviceData);
        if (base_ != null) {
            mService.updateBASE(syncHandle, base_);
            base_.print();
            base_.printConsolidated();
            if (mAutoTriggerred == false) {
                mService.sendBroadcastSourceSelectedCallback(device, base_.getBroadcastChannels(),
                  BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS);
            } else {
                //successfull auto periodic synchrnization with source
                log("auto triggered assist");
                mAutoTriggerred = false;
                //perform PAST with this device
                BluetoothDevice srcDevice = mService.getDeviceForSyncHandle(syncHandle);
                if (srcDevice != null) {
                    BleBroadcastSourceInfo srcInfo = getBroadcastSourceInfoForSourceDevice(srcDevice);
                    processPASyncState(srcInfo);
                } else {
                    Log.w(TAG, "Autoassist: no matching device");
                }
            }
        } else {
            //
            Log.e(TAG, "Seems BASE is not in parsable format");
            if (mAutoTriggerred == false) {
                mService.sendBroadcastSourceSelectedCallback(device, base_.getBroadcastChannels(),
                          BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_SELECTED);
                BluetoothDevice srcDevice = mService.getDeviceForSyncHandle(syncHandle);
                cancelActiveSync(srcDevice);
            } else {
                mAutoTriggerred = false;
            }
        }
    }

    void parseScanRecord(int syncHandle, ScanRecord record) {
        log("parseScanRecord" + record);
        BluetoothDevice srcDevice = mService.getDeviceForSyncHandle(syncHandle);
        Map<ParcelUuid, byte[]> bmsAdvDataMap = record.getServiceData();
        if (bmsAdvDataMap != null) {
            for (Map.Entry<ParcelUuid,byte[]> entry : bmsAdvDataMap.entrySet()) {
                log("ParcelUUid = " + entry.getKey() +
                             ", Value = " + entry.getValue());
            }
        } else {
           log("bmsAdvDataMap is null");
           if (mAutoTriggerred == false) {
               mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                  BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_SELECTED);
               cancelActiveSync(srcDevice);
           } else {
               mAutoTriggerred = false;
           }
        }
        ParcelUuid basicAudioUuid = new ParcelUuid(BASIC_AUDIO_UUID);
        byte[] bmsAdvData = record.getServiceData(basicAudioUuid);
        if (bmsAdvData != null) {
            //ByteBuffer bb = ByteBuffer.wrap(bmsAdvData);
            parseBaseData(mDevice, syncHandle, bmsAdvData);

        } else {
            Log.e(TAG, "No service data in Scan record");
            if (mAutoTriggerred == false) {
                mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                  BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_SELECTED);
                cancelActiveSync(srcDevice);
            } else {
                mAutoTriggerred = false;
            }
        }
    }

    /*Local Public address based check
    Use this prior to addition of Broadcast source*/
    boolean isLocalBroadcastSource (BluetoothDevice device)
    {
        BluetoothAdapter btAdapter = BluetoothAdapter.getDefaultAdapter();
        boolean ret = btAdapter.getAddress().equals(device.getAddress());

        log("isLocalBroadcastSource returns" +ret);
        return ret;
    }

    private boolean isValidBroadcastSourceInfo(BleBroadcastSourceInfo srcInfo) {
        boolean ret = true;
        List<BleBroadcastSourceInfo> currentSourceInfos =
            getAllBroadcastSourceInformation();
        Log.i(TAG, "input srcInfo: " + srcInfo);
        for (int i=0; i<currentSourceInfos.size(); i++) {
            Log.i(TAG, "srcInfo:  [" + i + "]" + currentSourceInfos.get(i));
            if (srcInfo.matches(currentSourceInfos.get(i))) {
                ret = false;
                break;
            }
        }

        log("isValidBroadcastSourceInfo returns: " + ret);
        return ret;
    }

    public boolean selectBroadcastSource (ScanResult scanRes, boolean groupOp, boolean autoTriggerred) {
        Log.i(TAG, "selectBroadcastSource for " + "isGroupOp:" + groupOp);
        Log.i(TAG, "ScanResult " + scanRes);
        int broadcastId = BCService.INVALID_BROADCAST_ID;
        if (isLocalBroadcastSource(scanRes.getDevice()) != true) {
            mAutoTriggerred = autoTriggerred;
            mFirstTimeBisDiscovery = true;
            mPASyncRetryCounter = 1;
            //Cache Scan res for Retrys
            mScanRes = scanRes;
            /*This is an override case
              if Previous sync is still active, cancel It
              But dont stop the Scan offload as we still trying to assist remote*/
            mNoStopScanOffload = true;
            cancelActiveSync(null);
            mService.getBassUtils().leScanControl(true);
            try {
               mPeriodicAdvManager.registerSync(scanRes, 0,
                                            PSYNC_TIMEOUT, mPeriodicAdvCallback);
               mSyncingOnBehalfOfGroup = groupOp;
            } catch (IllegalArgumentException ex) {
                Log.w(TAG, "registerSync:IllegalArguementException");
                mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                    BleBroadcastAudioScanAssistCallback.BASS_STATUS_INVALID_SOURCE_SELECTED);
                mService.stopScanOffloadInternal(mDevice, false);
                return false;
            }
            //updating mainly for Address type and PA Interval here
            //extract BroadcastId from ScanResult
            ScanRecord scanRecord = scanRes.getScanRecord();
            if (scanRecord != null) {
                Map<ParcelUuid, byte[]> listOfUuids = scanRecord.getServiceData();
                if (listOfUuids != null) {
                    if(listOfUuids.containsKey(ParcelUuid.fromString(BassUtils.BAAS_UUID))) {
                        byte[] bId = listOfUuids.get(ParcelUuid.fromString(BassUtils.BAAS_UUID));
                        broadcastId = (0x00FF0000 & (bId[0] << 16));
                        broadcastId |= (0x0000FF00 & (bId[1] << 8));
                        broadcastId |= (0x000000FF & bId[2]);
                }
            }
            mService.updatePAResultsMap(scanRes.getDevice(), scanRes.getAddressType(),
                          BCService.INVALID_SYNC_HANDLE, BCService.INVALID_ADV_SID,
                          scanRes.getPeriodicAdvertisingInterval(),
                          broadcastId);
                }
        }
        else {
            log("colocated case");
            if (autoTriggerred) {
                log("should never happen!!!");
                //ignore
                mAutoTriggerred = false;
            }
            ///*_BMS
            if (mBAService == null || mBAService.isBroadcastActive() != true) {
                Log.e(TAG, "colocated source handle unavailable OR not in streaming");
                mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                    BleBroadcastAudioScanAssistCallback.BASS_STATUS_COLOCATED_SRC_UNAVAILABLE);
                mService.stopScanOffloadInternal(mDevice, false);
                return false;
            }
            String colocatedAddress = null;
            int colocatedAddressType;
            if (mPublicAddrForcSrc == true) {
                colocatedAddress = BluetoothAdapter.getDefaultAdapter().getAddress();
                colocatedAddressType = BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC;
            } else {
                colocatedAddress = mBAService.BroadcastGetAdvAddress();
                colocatedAddressType = mBAService.BroadcastGetAdvAddrType();
            }
            int paInterval = 0x0000FFFF;
            paInterval = mBAService.BroadcastGetAdvInterval();

            if (colocatedAddress == null) {
                log("colocatedAddress is null");
                mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                    BleBroadcastAudioScanAssistCallback.BASS_STATUS_COLOCATED_SRC_UNAVAILABLE);
                mService.stopScanOffloadInternal(mDevice, false);
                return false;
            }
            BluetoothDevice colocatedSrcDevice =
                                BluetoothAdapter.getDefaultAdapter().getRemoteDevice(colocatedAddress);
            log("caching local Broacast details: " + colocatedSrcDevice);

            //advSid is same as advHandle for collocated case
            byte[] broadcast_id = mBAService.getBroadcastId();
            broadcastId = (0x00FF0000 & (broadcast_id[2] << 16));
            broadcastId |= (0x0000FF00 & (broadcast_id[1] << 8));
            broadcastId |= (0x000000FF & broadcast_id[0]);

            mService.updatePAResultsMap(colocatedSrcDevice, colocatedAddressType,
                mBAService.BroadcatGetAdvHandle(),
                mBAService.BroadcatGetAdvHandle(),
                paInterval,
                broadcastId);
                BaseData localBase = new BaseData(mBAService.getNumSubGroups(),
                                 mBAService.BroadcastGetBisInfo(),
                                 mBAService.BroadcastGetMetaInfo());
                localBase.printConsolidated();
                //Use advHandle to cahce Base
                mService.updateBASE(mBAService.BroadcatGetAdvHandle(), localBase);
                mService.sendBroadcastSourceSelectedCallback(mDevice, localBase.getBroadcastChannels(),
                    BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS);
            //_BMS*/
        }
        return true;
    }

    private void cancelActiveSync(BluetoothDevice sourceDev) {
        log("cancelActiveSync");
        boolean isCancelSyncNeeded = false;
        BluetoothDevice activeSyncedSrc = mService.getActiveSyncedSource(mDevice);
        if (activeSyncedSrc != null ) {
            if (sourceDev == null) {
                isCancelSyncNeeded = true;
            } else if(activeSyncedSrc.equals(sourceDev)) {
                isCancelSyncNeeded = true;
            }
        }
        if (isCancelSyncNeeded) {
            removeMessages(PSYNC_ACTIVE_TIMEOUT);
            try {
                log("calling unregisterSync");
                mPeriodicAdvManager.unregisterSync(mPeriodicAdvCallback);
            } catch (IllegalArgumentException ex) {
                Log.w(TAG, "unregisterSync:IllegalArguementException");
                //ignore
            }
            mService.clearPAResults(activeSyncedSrc);
            mService.setActiveSyncedSource(mDevice, null);
            if (mNoStopScanOffload != true) {
                //trigger scan stop here
                mService.stopScanOffloadInternal(mDevice, false);
            }
        }
        mNoStopScanOffload = false;
    }

    /* Internal periodc Advertising manager callback
      *
      */
     private PeriodicAdvertisingCallback mPeriodicAdvCallback = new PeriodicAdvertisingCallback() {
           @Override
           public void onSyncEstablished(int syncHandle, BluetoothDevice device,
             int advertisingSid, int skip, int timeout,
             int status) {
               log ("onSyncEstablished" + "syncHandle" + syncHandle +
                          "device" + device + "advertisingSid" + advertisingSid +
                          "skip" + skip + "timeout" + timeout + "status" +
                          status);
                //turn off the LeScan once sync estd
                mService.getBassUtils().leScanControl(false);
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    //upates syncHandle, advSid
                    mService.updatePAResultsMap(device,
                         BCService.INVALID_ADV_ADDRESS_TYPE,
                         syncHandle, advertisingSid,
                         BCService.INVALID_ADV_INTERVAL,
                         BCService.INVALID_BROADCAST_ID);
                    sendMessageDelayed(PSYNC_ACTIVE_TIMEOUT, PSYNC_ACTIVE_TIMEOUT_MS);
                    mService.setActiveSyncedSource(mDevice, device);
                } else {
                    log("failed to sync to PA" + mPASyncRetryCounter);
                       mScanRes = null;
                       if (mAutoTriggerred == false) {
                           mService.sendBroadcastSourceSelectedCallback(mDevice, null,
                                BleBroadcastAudioScanAssistCallback.BASS_STATUS_SOURCE_UNAVAILABLE);
                           mService.stopScanOffloadInternal(mDevice, false);
                       }
                    mAutoTriggerred = false;
                }
           }
           @Override
           public void onPeriodicAdvertisingReport(PeriodicAdvertisingReport report) {
               log( "onPeriodicAdvertisingReport");
               //Parse the BIS indicies from report's service data
               if (mFirstTimeBisDiscovery) {
                   parseScanRecord(report.getSyncHandle(),report.getData());
                   mFirstTimeBisDiscovery = false;
               }
           }
           @Override
           public void onSyncLost(int syncHandle) {
               log( "OnSyncLost" + syncHandle);
               BluetoothDevice srcDevice = mService.getDeviceForSyncHandle(syncHandle);
               cancelActiveSync(srcDevice);
           }

           public void onSyncTransfered(BluetoothDevice device, int status) {
                 log("sync transferred:" + device + " : " + status);
           }
       };

    private void broadcastReceiverState(BleBroadcastSourceInfo state, int index, int max_num_srcInfos) {
        log("broadcastReceiverState: " + mDevice);

        Intent intent = new Intent(BleBroadcastAudioScanAssistManager.ACTION_BROADCAST_SOURCE_INFO);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.putExtra(BleBroadcastSourceInfo.EXTRA_SOURCE_INFO, state);
        intent.putExtra(BleBroadcastSourceInfo.EXTRA_SOURCE_INFO_INDEX, index);
        intent.putExtra(BleBroadcastSourceInfo.EXTRA_MAX_NUM_SOURCE_INFOS, max_num_srcInfos);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mService.sendBroadcastAsUser(intent, UserHandle.ALL, BLUETOOTH_CONNECT,
              Utils.getTempAllowlistBroadcastOptions());
    }

    private static boolean isEmpty(final byte[] data){
        return IntStream.range(0, data.length).parallel().allMatch(i -> data[i] == 0);
    }

   private void processPASyncState(BleBroadcastSourceInfo srcInfo) {
       log("processPASyncState" + srcInfo);
       int serviceData = 0;
       if (srcInfo == null) {
           Log.e(TAG, "processPASyncState: srcInfo is null");
           return;
       }
       if (srcInfo.getMetadataSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ) {
           log("Initiate PAST procedure");
            BCService.PAResults res = mService.getPAResults(srcInfo.getSourceDevice());
            if (isAddedBroadcastSourceIsLocal(srcInfo.getSourceDevice()) &&
                mService.isLocalBroadcasting()) {
                if (res == null) {
                    log("Populate colocated PA and initiate PAST");

                    int colocatedAddressType;
                    if (mPublicAddrForcSrc == true) {
                        colocatedAddressType = BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC;
                    } else {
                        colocatedAddressType = mBAService.BroadcastGetAdvAddrType();
                    }
                    int broadcastId;
                    byte[] broadcast_id = mBAService.getBroadcastId();
                    broadcastId = (0x00FF0000 & (broadcast_id[2] << 16));
                    broadcastId |= (0x0000FF00 & (broadcast_id[1] << 8));
                    broadcastId |= (0x000000FF & broadcast_id[0]);
                    mService.updatePAResultsMap(srcInfo.getSourceDevice(), colocatedAddressType,
                                                mBAService.BroadcatGetAdvHandle(),
                                                mBAService.BroadcatGetAdvHandle(),
                                                mBAService.BroadcastGetAdvInterval(),
                                                broadcastId);
                }
                res = mService.getPAResults(srcInfo.getSourceDevice());
            }
            if (res != null) {
                int syncHandle = res.mSyncHandle;
                log("processPASyncState: syncHandle" + res.mSyncHandle);
                if (mNoPast == false && syncHandle != BCService.INVALID_SYNC_HANDLE) {
                    if (isAddedBroadcastSourceIsLocal(srcInfo.getSourceDevice())) {
                        log("Collocated Case Initiate PAST for :" + mDevice + "syncHandle:" +  syncHandle +
                            "serviceData" + serviceData);
                        serviceData = 0x000000FF & srcInfo.getSourceId();
                        serviceData = serviceData << 8;
                        //advA matches EXT_ADV_ADDRESS
                        //but not matches source address (as we would have written pAddr)
                        serviceData = serviceData & (~BROADCAST_ADV_ADDRESS_DONT_MATCHES_EXT_ADV_ADDRESS);
                        serviceData = serviceData | (BROADCAST_ADV_ADDRESS_DONT_MATCHES_SOURCE_ADV_ADDRESS);
                        try {
                            mPeriodicAdvManager.transferSetInfo(mDevice, serviceData, syncHandle,mPeriodicAdvCallback);
                        } catch (IllegalArgumentException ex) {
                            Log.w(TAG, "transferSetInfo: IllegalArgumentException : PAST failure");
                            //ignore
                        }
                     } else {
                        serviceData = 0x000000FF & srcInfo.getSourceId();
                        serviceData = serviceData << 8;
                        //advA matches EXT_ADV_ADDRESS
                        //also matches source address (as we would have written)
                        serviceData = serviceData & (~BROADCAST_ADV_ADDRESS_DONT_MATCHES_EXT_ADV_ADDRESS);
                        serviceData = serviceData & (~BROADCAST_ADV_ADDRESS_DONT_MATCHES_SOURCE_ADV_ADDRESS);
                        log("Initiate PAST for :" + mDevice + "syncHandle:" +  syncHandle +
                            "serviceData" + serviceData);
                        mPeriodicAdvManager.transferSync(mDevice, serviceData, syncHandle);
                    }
                }
            } else {
                Log.e(TAG, "There is no valid sync handle for this Source");
                if (mAutoAssist) {
                    //initiate Auto Assist procedure for this device
                    mService.getBassUtils().triggerAutoAssist (srcInfo);
                }
            }
       }
        else if (srcInfo.getAudioSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED ||
            srcInfo.getMetadataSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_NO_PAST) {
           //Cancel the existing sync and Invalidate the sync handle
           if (isAddedBroadcastSourceIsLocal(srcInfo.getSourceDevice()) == false) {
               if (mSyncingOnBehalfOfGroup == false) {
                   //Cancel the Sync only If it is NOT syced on behalf of group.
                   //group based sync will be kept active PSYNC_ACTIVE_TIMEOUT seconds so that
                   //all group members can get back in sync
                   log("Unregister sync as It is non colocated");
                   cancelActiveSync(srcInfo.getSourceDevice());
               }
           } else {
               //trigger scan stop here
               mService.stopScanOffloadInternal(mDevice, false);
           }
       }
   }

    /*Actual OTA advertising address based check
    Use this after the addition of Broadcast source*/
    private boolean isAddedBroadcastSourceIsLocal (BluetoothDevice device)
    {
        if (device  == null) {
            Log.e(TAG, "device handle is null");
            return false;
        }
        String localBroadcasterAddr = null;
        ///*_BMS
        if (mPublicAddrForcSrc) {
            localBroadcasterAddr = BluetoothAdapter.getDefaultAdapter().getAddress();
        } else {
            if (mBAService == null) {
                mBAService = BroadcastService.getBroadcastService();
            }
            if (mBAService == null || mBAService.isBroadcastActive() != true) {
                Log.e(TAG, "isAddedBroadcastSourceIsLocal: colocated source handle is unavailable");
                return false;
            }
            localBroadcasterAddr = mBAService.BroadcastGetAdvAddress();
        }
        //_BMS*/
        boolean ret = false;
        if (localBroadcasterAddr == null) {
            Log.e(TAG, "isAddedBroadcastSourceIsLocal: localBroadcasterAddr is null");
            ret = false;
        } else {
            ret = localBroadcasterAddr.equals(device.getAddress());
        }
        log("isAddedBroadcastSourceIsLocal returns" +ret);
        return ret;
    }

    private void checkAndUpdateBroadcastCode(BleBroadcastSourceInfo srcInfo) {
        if (isAddedBroadcastSourceIsLocal(srcInfo.getSourceDevice())) {
            if (mForceSB == true ||
                srcInfo.getEncryptionStatus() == BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED) {
                //query the Encryption Key from BMS and update
                ///*_BMS
                byte[] colocatedBcastCode = mBAService.GetEncryptionKey(null);
                if (mBAService.isBroadcastStreamingEncrypted() == false) {
                    Log.e(TAG, "seem to be Unencrypted colocated broadcast");
                    //do nothing
                    return;
                }
                log("colocatedBcastCode is " + colocatedBcastCode);
                //queue a fresh command to update the
                Message m = obtainMessage(BassClientStateMachine.SET_BCAST_CODE);
                m.obj = srcInfo;
                m.arg1 = FRESH;
                log("checkAndUpdateBroadcastCode: src device: " + srcInfo.getSourceDevice());
                sendMessage(m);
                //_BMS*/
            }
        } else {
            log("checkAndUpdateBroadcastCode");
            //non colocated case, Broadcast PIN should have been updated from lyaer
            //If there is pending one process it Now
            if (srcInfo.getEncryptionStatus() == BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED &&
                mSetBroadcastCodePending == true) {
                //Make a QUEUED command
                log("Update the Broadcast now");
                Message m = obtainMessage(BassClientStateMachine.SET_BCAST_CODE);
                m.obj = mSetBroadcastPINSrcInfo;
                m.arg1 = QUEUED;

                sendMessage(m);
                mSetBroadcastCodePending = false;
                mSetBroadcastPINSrcInfo = null;
            }
           }
   }

   private List<BleBroadcastSourceChannel> getListOfBisIndicies(int bisIndicies, int subGroupId, byte[] metaData) {
       List<BleBroadcastSourceChannel> bcastIndicies = new ArrayList<BleBroadcastSourceChannel>();
        int index =0;
        log("getListOfBisIndicies:" + bisIndicies);
        while (bisIndicies != 0) {
            if ((bisIndicies & 0x00000001) == 0x00000001) {
                BleBroadcastSourceChannel bI =
                    new BleBroadcastSourceChannel(index, Integer.toString(index), true, subGroupId, metaData);
                bcastIndicies.add(bI);
                log("Adding BIS index for :" + index);
            }
            bisIndicies = bisIndicies>>1;
            index++;
        }
        return bcastIndicies;

    }

    private void processBroadcastReceiverState (byte[] receiverState, BluetoothGattCharacteristic characteristic) {
        int index = -1;
        boolean isEmptyEntry = false;
        BleBroadcastSourceInfo srcInfo = null;

        log("processBroadcastReceiverState:: characteristic:" + characteristic);

        byte sourceId = 0;
        if (receiverState.length > 0)
            sourceId = receiverState[BCAST_RCVR_STATE_SRC_ID_IDX];
        log("processBroadcastReceiverState: receiverState length: " + receiverState.length);
        if (receiverState.length == 0 ||
            isEmpty(Arrays.copyOfRange(receiverState, 1, receiverState.length-1))) {
            log("This is an Empty Entry");
            if (mPendingOperation == REMOVE_BCAST_SOURCE) {
                srcInfo = new BleBroadcastSourceInfo(mPendingSourceId);
            } else if (receiverState.length == 0) {
                if (mBleBroadcastSourceInfos != null) {
                    mTempSourceId = (byte)mBleBroadcastSourceInfos.size();
                }
                if (mTempSourceId < NUM_OF_BROADCAST_RECEIVER_STATES) {
                    mTempSourceId++;
                    srcInfo = new BleBroadcastSourceInfo(mTempSourceId);
                } else {
                    Log.e(TAG, "reached the remote supported max SourceInfos");
                    return;
                }
            }
            isEmptyEntry = true;
            //just create an Empty entry
           if (srcInfo.isEmptyEntry()) {
                log("An empty entry has been created");
        }
        }
        else {
            byte sourceAddressType = receiverState[BCAST_RCVR_STATE_SRC_ADDR_TYPE_IDX];
            byte[] sourceAddress = new byte[BCAST_RCVR_STATE_SRC_ADDR_SIZE];
            System.arraycopy(receiverState, BCAST_RCVR_STATE_SRC_ADDR_START_IDX, sourceAddress, 0, BCAST_RCVR_STATE_SRC_ADDR_SIZE);
            byte sourceAdvSid = receiverState[BCAST_RCVR_STATE_SRC_ADV_SID_IDX];

            byte[] broadcastIdBytes = new byte[BROADCAST_SOURCE_ID_LENGTH];
            System.arraycopy(receiverState, BCAST_RCVR_STATE_SRC_BCAST_ID_START_IDX, broadcastIdBytes, 0, BROADCAST_SOURCE_ID_LENGTH);
            int broadcastId = (0x00FF0000 & (broadcastIdBytes[2] << 16));
            broadcastId |= (0x0000FF00 & (broadcastIdBytes[1] << 8));
            broadcastId |= (0x000000FF & broadcastIdBytes[0]);

            BluetoothAdapter btAdapter = BluetoothAdapter.getDefaultAdapter();
            BluetoothDevice  device = btAdapter.getRemoteDevice(reverseBytes(sourceAddress));
            byte metaDataSyncState = receiverState[BCAST_RCVR_STATE_PA_SYNC_IDX];


            byte encyptionStatus = receiverState[BCAST_RCVR_STATE_ENC_STATUS_IDX];
            byte[] badBroadcastCode = null;
            byte badBroadcastCodeLen = 0;
            byte numSubGroups = 0;
            byte[] metadataLength = null;
            byte[] metaData = null;
            if (encyptionStatus == BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_BADCODE) {
                badBroadcastCode = new byte[BCAST_RCVR_STATE_BADCODE_SIZE];
                System.arraycopy(receiverState, BCAST_RCVR_STATE_BADCODE_START_IDX, badBroadcastCode, 0, BCAST_RCVR_STATE_BADCODE_SIZE);
                badBroadcastCode = reverseBytes(badBroadcastCode);
                badBroadcastCodeLen = BCAST_RCVR_STATE_BADCODE_SIZE;
            }
            numSubGroups = receiverState[BCAST_RCVR_STATE_BADCODE_START_IDX + badBroadcastCodeLen];
            int offset = BCAST_RCVR_STATE_BADCODE_START_IDX + badBroadcastCodeLen + 1;
            //Map of Bis Status <subGroupId, List_OF_Broadcast_channel>
            Map<Integer, List<BleBroadcastSourceChannel>> bisIndexList = new HashMap<Integer, List<BleBroadcastSourceChannel>>();
            //Map for Metada <subGroupId, Metadata>
            Map<Integer, byte[]> metadataList = new HashMap<Integer, byte[]>();
            metadataLength = new byte[numSubGroups];
            byte audioSyncState = 0;
            for (int i = 0; i < numSubGroups; i++) {
                byte[] audioSyncIndex = new byte[BCAST_RCVR_STATE_BIS_SYNC_SIZE];
                System.arraycopy(receiverState, offset, audioSyncIndex, 0, BCAST_RCVR_STATE_BIS_SYNC_SIZE);
                offset = offset + BCAST_RCVR_STATE_BIS_SYNC_SIZE;
                log("BIS index byte array: ");
                BassUtils.printByteArray(audioSyncIndex);
                ByteBuffer wrapped = ByteBuffer.wrap(reverseBytes(audioSyncIndex));
                int audioBisIndex = wrapped.getInt();
                if (audioBisIndex == 0xFFFFFFFF) {
                    log("Remote failed to sync to BIS");
                    audioSyncState = 0x00;
                    audioBisIndex = 0;
                } else {
                    //Bits (0-30)=> (1-31)
                    audioBisIndex = audioBisIndex << 1;
                    log("BIS index converted: " + audioBisIndex);
                    if (audioBisIndex != 0){
                        //If any BIS is in sync, Set Audio state as ON
                        audioSyncState = 0x01;
                    }
                }

                metadataLength[i] =  receiverState[offset++];
                if (metadataLength[i] != 0) {
                    log("metadata of length: " + metadataLength[i] + "is avaialble");
                    metaData = new byte[metadataLength[i]];
                    System.arraycopy(receiverState, offset, metaData, 0, metadataLength[i]);
                    offset = offset + metadataLength[i];
                    metaData = reverseBytes(metaData);
                    metadataList.put(i, metaData);
                }
                bisIndexList.put(i, getListOfBisIndicies(audioBisIndex, i, metaData));
            }
            srcInfo = new BleBroadcastSourceInfo(device,
                                             sourceId,
                                             sourceAdvSid,
                                             broadcastId,
                                             (int)sourceAddressType,
                                             (int)metaDataSyncState,
                                             (int)encyptionStatus,
                                             badBroadcastCode,
                                             numSubGroups,
                                             (int)audioSyncState,
                                             bisIndexList,
                                             metadataList
                                             );
        }
        BleBroadcastSourceInfo oldSourceInfo = mBleBroadcastSourceInfos.get(characteristic.getInstanceId());
        if (oldSourceInfo == null) {
            log("Initial Read and Populating values");
            if (mBleBroadcastSourceInfos.size() == NUM_OF_BROADCAST_RECEIVER_STATES) {
                Log.e(TAG, "reached the Max SourceInfos");
                return;
            }
            mBleBroadcastSourceInfos.put(characteristic.getInstanceId(), srcInfo);
            checkAndUpdateBroadcastCode(srcInfo);
            processPASyncState(srcInfo);
        } else {
            log("old sourceInfo: " + oldSourceInfo);
            log("new sourceInfo: " + srcInfo);
            mBleBroadcastSourceInfos.replace(characteristic.getInstanceId(), srcInfo);
            if (oldSourceInfo.isEmptyEntry() == true) {
                log("New Source Addition");
                sendPendingCallbacks(ADD_BCAST_SOURCE,
                          srcInfo.getSourceId(), BluetoothGatt.GATT_SUCCESS);
                checkAndUpdateBroadcastCode(srcInfo);
                processPASyncState(srcInfo);
            } else {
                if (isEmptyEntry) {
                    BluetoothDevice removedDevice = oldSourceInfo.getSourceDevice();
                    log("sourceInfo removal" + removedDevice);
                    cancelActiveSync(removedDevice);
                    sendPendingCallbacks(REMOVE_BCAST_SOURCE,
                          srcInfo.getSourceId(), BluetoothGatt.GATT_SUCCESS);
                } else {
                    log("update to an existing srcInfo");
                    sendPendingCallbacks(UPDATE_BCAST_SOURCE,
                          srcInfo.getSourceId(),BluetoothGatt.GATT_SUCCESS);
                    processPASyncState(srcInfo);
                    checkAndUpdateBroadcastCode(srcInfo);
                }
            }
        }
        index = srcInfo.getSourceId();
        if (index == -1) {
            log("processBroadcastReceiverState: invalid index");
            return;
        }
        broadcastReceiverState(srcInfo, index, NUM_OF_BROADCAST_RECEIVER_STATES);
    }
    // Implements callback methods for GATT events that the app cares about.  For example,
    // connection change and services discovered.
    private final BluetoothGattCallback mGattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
           boolean isStateChanged = false;
           log( "onConnectionStateChange : Status=" + status + "newState" + newState);
           if (newState == BluetoothProfile.STATE_CONNECTED && getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
              isStateChanged = true;
               Log.w(TAG, "Bassclient Connected from Disconnected state: " + mDevice);
               if (mService.okToConnect(mDevice)) {
                   log("Bassclient Connected to: " + mDevice);
                   if (mBluetoothGatt != null) {
                       log( "Attempting to start service discovery:" +
                        mBluetoothGatt.discoverServices());
                       mDiscoveryInitiated = true;
                   }
               } else {
                   if (mBluetoothGatt != null) {
                       // Reject the connection
                      Log.w(TAG, "Bassclient Connect request rejected: " + mDevice);
                      mBluetoothGatt.disconnect();
                      mBluetoothGatt.close();
                      mBluetoothGatt = null;
                      //force move to disconnected
                      newState = BluetoothProfile.STATE_DISCONNECTED;
                   }
               }
           } else if (newState == BluetoothProfile.STATE_DISCONNECTED &&
                      getConnectionState() != BluetoothProfile.STATE_DISCONNECTED) {
                isStateChanged = true;
                log( "Disconnected from Bass GATT server.");
           }
           if (isStateChanged) {
               Message m = obtainMessage(CONNECTION_STATE_CHANGED);
               m.obj = newState;
               sendMessage(m);
           }
        }
        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            log("onServicesDiscovered:" + status);
            if (mDiscoveryInitiated == true) {
                mDiscoveryInitiated = false;
                if (status == BluetoothGatt.GATT_SUCCESS && mBluetoothGatt != null) {
                    mBluetoothGatt.requestMtu(BASS_MAX_BYTES);
                    mMTUChangeRequested = true;
                } else {
                    Log.w(TAG, "onServicesDiscovered received: " + status
                        + "mBluetoothGatt" + mBluetoothGatt);
                }
            } else {
                log("remote initiated callback");
                //do nothing
            }
        }
        @Override
        public void onCharacteristicRead(BluetoothGatt gatt,
                                     BluetoothGattCharacteristic characteristic,
                                     int status) {
            log( "onCharacteristicRead:: status: " + status + "char:" + characteristic);

            if (status == BluetoothGatt.GATT_SUCCESS &&
                characteristic.getUuid().equals(BASS_BCAST_RECEIVER_STATE)) {
                log( "onCharacteristicRead: BASS_BCAST_RECEIVER_STATE: status" + status);
                logByteArray("Received ", characteristic.getValue(), 0,
                     characteristic.getValue().length);
                if (characteristic.getValue() == null) {
                    Log.e(TAG, "Remote receiver state is NULL");
                    return;
                }
                processBroadcastReceiverState(characteristic.getValue(), characteristic);
            }
            // switch to receiving notifications after initial characteristic read
            BluetoothGattDescriptor desc = characteristic.getDescriptor(CLIENT_CHARACTERISTIC_CONFIG);
            if (mBluetoothGatt != null && desc != null) {
                log("Setting the value for Desc");
                mBluetoothGatt.setCharacteristicNotification(characteristic, true);
                desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                mBluetoothGatt.writeDescriptor(desc);
            } else {
                Log.w(TAG, "CCC for " + characteristic + "seem to be not present");
                //atleast move the SM to stable state
                Message m = obtainMessage(GATT_TXN_PROCESSED);
                m.arg1 = status;
                sendMessage(m);
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor,
             int status) {
             log("onDescriptorWrite");
             if (status == BluetoothGatt.GATT_SUCCESS &&
                 descriptor.getUuid().equals(CLIENT_CHARACTERISTIC_CONFIG)) {
                 log("CCC write resp");
            }

             //Move the SM to connected so further reads happens
             Message m = obtainMessage(GATT_TXN_PROCESSED);
             m.arg1 = status;
             sendMessage(m);
        }

        @Override
        public void onMtuChanged(BluetoothGatt gatt, int mtu, int status)
        {
            log("onMtuChanged: mtu:" + mtu);
            if (mMTUChangeRequested == true && mBluetoothGatt != null) {
                acquireAllBassChars();
                mMTUChangeRequested = false;
            } else {
                log("onMtuChanged is remote initiated trigger, mBluetoothGatt:" + mBluetoothGatt);
                //Do nothing
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt,
                                        BluetoothGattCharacteristic characteristic) {
            log( "onCharacteristicChanged :: "
                        + characteristic.getUuid().toString());
            if (characteristic.getUuid().equals(BASS_BCAST_RECEIVER_STATE)) {
                log( "onCharacteristicChanged is rcvr State :: "
                        + characteristic.getUuid().toString());
                if (characteristic.getValue() == null) {
                    Log.e(TAG, "Remote receiver state is NULL");
                    return;
                }
                logByteArray("onCharacteristicChanged: Received ", characteristic.getValue(), 0,
                     characteristic.getValue().length);
                processBroadcastReceiverState(characteristic.getValue(), characteristic);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt,
                BluetoothGattCharacteristic characteristic, int status) {
            log( "onCharacteristicWrite: "
                        + characteristic.getUuid().toString()
                        + "status:" + status);
            if (status == 0 &&
                    characteristic.getUuid().equals(BASS_BCAST_AUDIO_SCAN_CTRL_POINT)) {
                log( "BASS_BCAST_AUDIO_SCAN_CTRL_POINT is written successfully");
            }
            Message m = obtainMessage(GATT_TXN_PROCESSED);
            m.arg1 = status;
            sendMessage(m);
        }
    };

    public List<BleBroadcastSourceInfo> getAllBroadcastSourceInformation() {
        log( "getAllBroadcastSourceInformation");
        List list = new ArrayList(mBleBroadcastSourceInfos.values());
        return list;
    }

    void acquireAllBassChars() {
        clearCharsCache();
        BluetoothGattService service = null;
        if (mBluetoothGatt != null) {
            log("getting Bass Service handle");
            service = mBluetoothGatt.getService(BASS_UUID);
        }
        if (service != null) {
            log( "found BASS_SERVICE");
            List<BluetoothGattCharacteristic> allChars = service.getCharacteristics();
            int numOfChars = allChars.size();
            NUM_OF_BROADCAST_RECEIVER_STATES = numOfChars-1;
            log( "Total number of chars" + numOfChars);
            //static var to keep track of read callbacks
            num_of_recever_states = NUM_OF_BROADCAST_RECEIVER_STATES;
            for (int i = 0; i < allChars.size(); i++) {
                if (allChars.get(i).getUuid().equals(BASS_BCAST_AUDIO_SCAN_CTRL_POINT)) {
                    mBroadcastScanControlPoint = allChars.get(i);
                    log( "Index of ScanCtrlPoint:" + i);
                } else {
                    log( "Reading " + i + "th ReceiverState");
                    mBroadcastReceiverStates.add(allChars.get(i));
                    Message m = obtainMessage(READ_BASS_CHARACTERISTICS);
                    m.obj = allChars.get(i);
                    sendMessage(m);
                }
            }
        } else {
            Log.e(TAG, "acquireAllBassChars: BASS service not found");
        }
     }

     void clearCharsCache() {
         if (mBroadcastReceiverStates != null) {
            mBroadcastReceiverStates.clear();
        }
        if (mBroadcastScanControlPoint != null) {
            mBroadcastScanControlPoint = null;
        }
        num_of_recever_states = 0;
        if (mBleBroadcastSourceInfos != null) {
            mBleBroadcastSourceInfos.clear();
        }
        mPendingOperation = -1;
     }

    @VisibleForTesting
    class Disconnected extends State {
        @Override
        public void enter() {
            log( "Enter Disconnected(" + mDevice + "): " + messageWhatToString(
                    getCurrentMessage().what));
            clearCharsCache();
            mTempSourceId = 0;
            removeDeferredMessages(DISCONNECT);

            if (mLastConnectionState == -1) {
                log( "no Broadcast of initial profile state ");
            } else {
                if (mPacsAvail == true) {
                    /*_PACS
                    PacsClientService mPacsClientService = PacsClientService.getPacsClientService();
                    if (mPacsClientService != null) {
                        log("trigger disconnect to Pacs");
                        mPacsClientService.disconnect(mDevice);
                    } else {
                       Log.e(TAG, "PACs interface is null");
                    }
                    _PACS*/
                }

                ///*_VCP
                if (mVcpForBroadcast) {
                    VcpController vcpController = VcpController.getVcpController();
                    if (vcpController != null) {
                        log("trigger disconnect to Vcp Renderer");
                        if (!vcpController.disconnect(mDevice, BluetoothVcp.MODE_BROADCAST)) {
                            log("Disconnect Vcp failed");
                        }
                    } else {
                        Log.e(TAG, "VcpController interface is null");
                    }
                }
                //_VCP*/
                 broadcastConnectionState(mDevice, mLastConnectionState,
                              BluetoothProfile.STATE_DISCONNECTED);
            }
        }

        @Override
        public void exit() {
            log("Exit Disconnected(" + mDevice + "): " + messageWhatToString(
                    getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_DISCONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Disconnected process message(" + mDevice + "): " + messageWhatToString(
                    message.what));

            switch (message.what) {
                case CONNECT:
                    log("Connecting to " + mDevice);
                    if (mBluetoothGatt != null) {
                        Log.d(TAG, "clear off, pending wl connection");
                        mBluetoothGatt.disconnect();
                        mBluetoothGatt.close();
                        mBluetoothGatt = null;
                    }

                    if ((mBluetoothGatt = mDevice.connectGatt(mService, mIsWhitelist, mGattCallback,
                            BluetoothDevice.TRANSPORT_LE, false, (BluetoothDevice.PHY_LE_1M_MASK |
                            BluetoothDevice.PHY_LE_2M_MASK | BluetoothDevice.PHY_LE_CODED_MASK),
                            null, true)) == null) {
                        Log.e(TAG, "Disconnected: error connecting to " + mDevice);
                        break;
                    } else {
                        transitionTo(mConnecting);
                    }
                    break;
                case DISCONNECT:
                    Log.w(TAG, "Disconnected: DISCONNECT ignored: " + mDevice);
                    break;
                case CONNECTION_STATE_CHANGED:
                    int state = (int)message.obj;
                    Log.w(TAG, "connection state changed:" + state);
                    if (state == BluetoothProfile.STATE_CONNECTED) {
                        log("remote/wl connection, ensure csip is up as well");
                        if (mNoCSIPReconn == false && mService != null &&
                           mService.isLockSupportAvailable(mDevice)) {
                            /////*_CSIP
                            mCsipConnected = false;
                            mSetCoordinator.connect(mService.mCsipAppId, mDevice);
                            transitionTo(mConnecting);
                            break;
                            ////_CSIP*/
                        } else {
                            transitionTo(mConnected);
                        }
                    } else {
                        Log.w(TAG, "Disconected: Connection failed to " + mDevice);
                    }
                    break;
                case PSYNC_ACTIVE_TIMEOUT:
                    cancelActiveSync(null);
                    break;
                default:
                    log("DISCONNECTED: not handled message:" + message.what);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }

    @VisibleForTesting
     class Connecting extends State {
         @Override
         public void enter() {
             log( "Enter Connecting(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
             sendMessageDelayed(CONNECT_TIMEOUT, mDevice, mConnectTimeoutMs);
             broadcastConnectionState(mDevice, mLastConnectionState,
                               BluetoothProfile.STATE_CONNECTING);
         }

         @Override
         public void exit() {
             log("Exit Connecting(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
             mLastConnectionState = BluetoothProfile.STATE_CONNECTING;
             removeMessages(CONNECT_TIMEOUT);
         }

         @Override
         public boolean processMessage(Message message) {
             log("Connecting process message(" + mDevice + "): " + messageWhatToString(
                     message.what));

             switch (message.what) {
                 case CONNECT:
                     log("Already Connecting to " + mDevice);
                     log("Ignore this connection request " + mDevice);
                     break;
                 case DISCONNECT:
                     Log.w(TAG, "Connecting: DISCONNECT deferred: " + mDevice);
                     deferMessage(message);
                     break;
                 case READ_BASS_CHARACTERISTICS:
                     Log.w(TAG, "defer READ_BASS_CHARACTERISTICS requested!: " + mDevice);
                     deferMessage(message);
                     break;
                 case CSIP_CONNECTION_STATE_CHANGED:
                     int state = (int)message.obj;
                    if (state == BluetoothProfile.STATE_CONNECTED) {
                        ///*_CSIP
                        if (mCsipConnected == true) {
                            Log.e(TAG,  "CSIP is already up, ignore this DUP event");
                            break;
                        }
                        mCsipConnected = true;
                        Log.d(TAG, "Csip connected");
                        transitionTo(mConnected);
                    } else {
                        Log.w(TAG, "CSIP Connection failed to " + mDevice);
                        if (mBluetoothGatt != null) {
                            //disc bass
                            mBluetoothGatt.disconnect();
                            mBluetoothGatt.close();
                            mBluetoothGatt = null;
                        }
                        transitionTo(mDisconnected);
                    }

                    break;
                 case CONNECTION_STATE_CHANGED:
                     state = (int)message.obj;
                     Log.w(TAG, "Connecting: connection state changed:" + state);
                     if (state == BluetoothProfile.STATE_CONNECTED) {
                         if (mService != null &&
                             mService.isLockSupportAvailable(mDevice)) {
                             ///*_CSIP
                             //If Lock support available & connect to csip
                             mCsipConnected = false;
                             mSetCoordinator.connect(mService.mCsipAppId, mDevice);
                             break;
                             //_CSIP*/
                         } else {
                             transitionTo(mConnected);
                         }
                     } else {
                         Log.w(TAG, "Connection failed to " + mDevice);
                         transitionTo(mDisconnected);
                     }
                     break;
                 case CONNECT_TIMEOUT:
                    Log.w(TAG, "CONNECT_TIMEOUT");
                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                         Log.e(TAG, "Unknown device timeout " + device);
                         break;
                    }
                    transitionTo(mDisconnected);
                    break;
                 case PSYNC_ACTIVE_TIMEOUT:
                    deferMessage(message);
                    break;
                 default:
                      log("CONNECTING: not handled message:" + message.what);
                     return NOT_HANDLED;
             }
             return HANDLED;
         }
     }

    private byte[] reverseBytes(byte[] a) {
        if (mNoReverse) {
               log("no reverse is enabled>");
               return a;
        }
        for(int i=0; i<a.length/2; i++){
          byte tmp = a[i];
          a[i] = a[a.length -i -1];
          a[a.length -i -1] = tmp;
        }

        return a;
    }

    private byte[] BluetoothAddressToBytes (String s) {
        log("BluetoothAddressToBytes: input string:" + s);
        String[] splits = s.split(":");

        byte[] addressBytes = new byte[6];
        for (int i=0; i<6; i++) {
            int hexValue = Integer.parseInt(splits[i], 16);
            log("hexValue:" + hexValue);
            addressBytes[i] = (byte)hexValue;
        }

        return addressBytes;

    }

    private int convertBisIndiciesToIntegerValue(List<BleBroadcastSourceChannel> bisIndicies, int subGroupId) {
        int audioBisIndex = 0;
        if (bisIndicies != null) {
            for (int i=0; i<bisIndicies.size(); i++) {
                if (bisIndicies.get(i).getStatus() == true && bisIndicies.get(i).getSubGroupId() == subGroupId) {
                    audioBisIndex = audioBisIndex | 1<<(bisIndicies.get(i).getIndex()-1);
                    log( "set the bit" + bisIndicies.get(i).getIndex() + "after:" + audioBisIndex);
                }
            }
        } else {
            log("bisIndicies Channels are null");
            audioBisIndex = 0xFFFFFFFF;

        }
        log( "audioBisIndex" + audioBisIndex);

        return audioBisIndex;
    }

    private byte[] convertSourceInfoToAddSourceByteArray(BleBroadcastSourceInfo srcInfo) {
        byte[] res;
        /*fixed length for add source op*/
        int addSourceFixedLength = 16;
        byte[] metaDataLength = null;
        BluetoothDevice broadcastSource = null;
        String localBcastAddr = null;
        BCService.PAResults paRes = null;
        log("Get PAresults for :" + srcInfo.getSourceDevice());
        broadcastSource = srcInfo.getSourceDevice();

        ///*_BMS
        if (mPublicAddrForcSrc == false) {
            if (isLocalBroadcastSource(broadcastSource)){
                //update broadcastSource if it is colocated
                if (mBAService != null) {
                    localBcastAddr = mBAService.BroadcastGetAdvAddress();
                }
                if (localBcastAddr == null) {
                    Log.w(TAG, "convertSourceInfoToAddSourceByteArray: localBCast not avaiable");
                    sendPendingCallbacks(ADD_BCAST_SOURCE,INVALID_SRC_ID,
                       BleBroadcastAudioScanAssistCallback.BASS_STATUS_SOURCE_UNAVAILABLE);
                    return null;
                } else {
                   broadcastSource =
                       BluetoothAdapter.getDefaultAdapter().getRemoteDevice(localBcastAddr);
                       log("convertSourceInfoToAddSourceByteArray: colocated case: " + broadcastSource);
                }
            }
        }
        //_BMS*/
        paRes = mService.getPAResults(broadcastSource);
        if (paRes == null) {
            Log.e(TAG, "No mathcing psync, scan res for this addition");
            sendPendingCallbacks(ADD_BCAST_SOURCE,INVALID_SRC_ID,
                       BleBroadcastAudioScanAssistCallback.BASS_STATUS_SOURCE_UNAVAILABLE);
            return null;
        }

        //populate metadata from BASE levelOne
        BaseData base_ = mService.getBASE(paRes.mSyncHandle);
        if (base_ == null) {
            Log.e(TAG, "No valid base data populated for this device");
            sendPendingCallbacks(ADD_BCAST_SOURCE,INVALID_SRC_ID,
                       BleBroadcastAudioScanAssistCallback.BASS_STATUS_SOURCE_UNAVAILABLE);
            return null;
        }
        int numSubGroups = base_.getNumberOfSubgroupsofBIG();
        metaDataLength = new byte[numSubGroups];
        int totalMetadataLength = 0;
        for (int i=0; i<numSubGroups; i++) {
            if (base_.getMetadata(i) == null) {
                Log.w(TAG, "no valid metadata from BASE");
                metaDataLength[i] = 0;
            } else {
                metaDataLength[i] = (byte)base_.getMetadata(i).length;
                log("metaDataLength updated:" + metaDataLength[i]);
            }
            totalMetadataLength = totalMetadataLength + metaDataLength[i];
        }
        res = new byte [addSourceFixedLength + numSubGroups*5 + totalMetadataLength];
        srcInfo.setSourceDevice(broadcastSource);
        srcInfo.setAdvAddressType((byte)paRes.mAddressType);
        srcInfo.setAdvertisingSid((byte)paRes.mAdvSid);
        srcInfo.setBroadcasterId(paRes.mBroadcastId);

        if (isValidBroadcastSourceInfo(srcInfo) == false) {
            log("Discarding this Add Broadcast source If It is DUP");
            sendPendingCallbacks(ADD_BCAST_SOURCE,INVALID_SRC_ID,
                            BleBroadcastAudioScanAssistCallback.BASS_STATUS_DUPLICATE_ADDITION);
            return null;
        }

        res[0] = BASS_ADD_SOURCE_OPCODE;
        res[1] = (byte)paRes.mAddressType;
        String address = broadcastSource.getAddress();
        byte[] addrByteVal = BluetoothAddressToBytes(address);
        log("Address bytes: " + Arrays.toString(addrByteVal));
        byte[] revAddress= reverseBytes(addrByteVal);
        log("reverse Address bytes: " + Arrays.toString(revAddress));
        System.arraycopy(revAddress, 0, res, 2, 6);
        res[8] = (byte)paRes.mAdvSid;

        //System.arraycopy(paRes.mBroadcastId, 0, res, 9, BROADCAST_SOURCE_ID_LENGTH);
        log("mBroadcastId: " + paRes.mBroadcastId);
        res[9] = (byte)(paRes.mBroadcastId & 0x00000000000000FF);
        res[10] = (byte)((paRes.mBroadcastId & 0x000000000000FF00) >>> 8);
        res[11] = (byte)((paRes.mBroadcastId & 0x0000000000FF0000) >>> 16);
        if (mDefNoPAS == false &&
                srcInfo.getMetadataSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            res[12] = (byte)(0x01);
        } else {
            log("setting PA sync to ZERO");
            res[12] = (byte)0x00;
        }

        res[13] = (byte)(paRes.mPAInterval & 0x00000000000000FF);
        res[14] = (byte)((paRes.mPAInterval & 0x000000000000FF00)>>>8);

        res[15] = base_.getNumberOfSubgroupsofBIG();

        int offset = 16;
        for (int i=0; i<base_.getNumberOfSubgroupsofBIG(); i++) {

            //Select based on PACs?
            //int bisIndexValue = convertBisIndiciesToIntegerValue(srcInfo.getBroadcastChannelsSyncStatus());
            int bisIndexValue = convertBisIndiciesToIntegerValue(mService.getBassUtils().selectBises(mDevice, srcInfo, base_), i);

            res[offset++] = (byte)(bisIndexValue & 0x00000000000000FF);
            res[offset++] = (byte)((bisIndexValue & 0x000000000000FF00)>>>8);
            res[offset++] = (byte)((bisIndexValue & 0x0000000000FF0000)>>>16);
            res[offset++] = (byte)((bisIndexValue & 0x00000000FF000000)>>>24);

            res[offset++] = metaDataLength[i];
            if (metaDataLength[i] != 0) {
                if (isLocalBroadcastSource(broadcastSource) == false) {
                    byte[] revMetadata = reverseBytes(base_.getMetadata(i));
                    System.arraycopy(revMetadata, 0, res, offset, metaDataLength[i]);
                } else {
                    System.arraycopy(base_.getMetadata(i), 0, res, offset, metaDataLength[i]);
                }
            }
            offset = offset + metaDataLength[i];
        }

        log("ADD_BCAST_SOURCE in Bytes");
        BassUtils.printByteArray(res);
        return res;
    }

    private byte[] convertSourceInfoToUpdateSourceByteArray(BleBroadcastSourceInfo srcInfo) {
        byte[] res;
        int updateSourceFixedLength = 6;
        BCService.PAResults paRes = null;
        BleBroadcastSourceInfo existingSI = getBroadcastSourceInfoForSourceId(srcInfo.getSourceId());
        if (existingSI == null) {
            log("no existing SI for update source op");
            return null;
        }

        byte numSubGroups = existingSI.getNumberOfSubGroups();
        //on Modify source, dont update any Metadata
        byte metaDataLength = 0;
        res = new byte [updateSourceFixedLength + numSubGroups*5];

        res[0] = BASS_UPDATE_SOURCE_OPCODE;
        res[1] = srcInfo.getSourceId();

        if (srcInfo.getMetadataSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC) {
            res[2] = (byte)(0x01);
        } else {
            res[2] = (byte)0x00;
        }
        //update these from existing SI
        BluetoothDevice existingSrcDevice = existingSI.getSourceDevice();
        if (isAddedBroadcastSourceIsLocal(existingSrcDevice)) {
            int paInterval = 0x0000FFFF;
            paInterval = mBAService.BroadcastGetAdvInterval();
            res[4] = (byte)((paInterval & 0x000000000000FF00)>>>8);
            res[3] = (byte)(paInterval & 0x00000000000000FF);
        } else {
            //for non-c mmodify op, set PA Interval as UNKNOWN
            res[4] = (byte)0xFF;
            res[3] = (byte)0xFF;
        }
        //For modify op, just set number of Subgroups as UNKNOWN
        //ZERO is treated as UNKNOWN
        res[5] = numSubGroups;

        int offset = 6;
        int bisIndexValue = 0;
        Map<Integer, Integer> bisIndexList =  existingSI.getBisIndexList();
        if (srcInfo.getAudioSyncState() == BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED) {
            //Force BIS index value to NO_PREF for modify SRC
            bisIndexValue = 0xFFFFFFFF;
        } else {
            bisIndexValue = 0x00000000;
        }
        log("UPDATE_BCAST_SOURCE b4: bisIndexValue : " + bisIndexValue);
        //If there is an empty List, set NO pref all subgroups
        if (bisIndexList == null || bisIndexList.size() == 0) {
            bisIndexValue = 0xFFFFFFFF;
        }
        for (int i=0; i<numSubGroups; i++) {

            //Select based on PACs?
            //int bisIndexValue = convertBisIndiciesToIntegerValue(srcInfo.getBroadcastChannelsSyncStatus());
            if (bisIndexValue != 0xFFFFFFFF && bisIndexValue != 0) {
                bisIndexValue = bisIndexList.get(i);
            }
            log("UPDATE_BCAST_SOURCE: bisIndexValue : " + bisIndexValue);

            res[offset++] = (byte)(bisIndexValue & 0x00000000000000FF);
            res[offset++] = (byte)((bisIndexValue & 0x000000000000FF00)>>>8);
            res[offset++] = (byte)((bisIndexValue & 0x0000000000FF0000)>>>16);
            res[offset++] = (byte)((bisIndexValue & 0x00000000FF000000)>>>24);

            res[offset++] = metaDataLength;
        }
        log("UPDATE_BCAST_SOURCE in Bytes");
        BassUtils.printByteArray(res);
        return res;
    }

    private byte[] convertAsciitoValues (byte[] val) {
        byte[] ret = new byte[val.length];
        for (int i=0; i< val.length; i++) {
            ret[i] = (byte)(val[i] - (byte)'0');
        }
        log("convertAsciitoValues: returns:" + Arrays.toString(val));
        return ret;
    }

    private byte[] convertSourceInfoToSetBroadcastCodeByteArray(BleBroadcastSourceInfo srcInfo) {

        byte[] res = new byte[PIN_CODE_CMD_LEN];
        res[0] = BASS_SET_BCAST_PIN_OPCODE;
        res[1] = srcInfo.getSourceId();
        log("convertSourceInfoToSetBroadcastCodeByteArray: Source device : " + srcInfo.getSourceDevice());
        byte[] actualPIN = null;
        //srcInfo.getSourceDevice() will be NULL if this request coming from SDK
        // srcInfo.getSourceDevice() will have valid Source device only If this is
        //collocated device
        if (srcInfo.getSourceDevice() != null &&
               isAddedBroadcastSourceIsLocal(srcInfo.getSourceDevice())) {
            //colocated Source addition
            //query the Encryption Key from BMS and update
            ///*_BMS
            actualPIN = mBAService.GetEncryptionKey(null);
            //_BMS*/
            log("colocatedBcastCode is " + Arrays.toString(actualPIN));
        } else {
            //Can Keep as ASCII as is
            String reversePIN = new StringBuffer(srcInfo.getBroadcastCode()).reverse().toString();
            actualPIN = reversePIN.getBytes();
        }
        if (actualPIN == null) {
            Log.e(TAG, "actual PIN is null");
            return null;
        } else {
            log( "byte array broadcast Code:" + Arrays.toString(actualPIN));
            log( "pinLength:" + actualPIN.length);

            //Fill the PIN code in the Last Position
            System.arraycopy(actualPIN, 0, res, ((PIN_CODE_CMD_LEN)-actualPIN.length), actualPIN.length);

            log("SET_BCAST_PIN in Bytes");
            BassUtils.printByteArray(res);
        }
        return res;
    }

    private boolean IsItRightTimeToUpdateBroadcastPIN(byte srcId) {
        Collection<BleBroadcastSourceInfo> srcInfos = mBleBroadcastSourceInfos.values();
        Iterator<BleBroadcastSourceInfo> iterator = srcInfos.iterator();
        boolean ret = false;
        if (mForceSB) {
            log("force SB is set");
            return true;
        }
        while (iterator.hasNext()) {
            BleBroadcastSourceInfo sI = iterator.next();
            if (sI == null) {
                log("src Info is null");
                continue;
            }
            if (srcId == sI.getSourceId() &&
                sI.getEncryptionStatus() == BleBroadcastSourceInfo.BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED) {
                ret = true;
                break;
            }
        }
        log("IsItRightTimeToUpdateBroadcastPIN returning:" + ret);
        return ret;
    }

    @VisibleForTesting
    class Connected extends State {
        @Override
        public void enter() {
            log( "Enter Connected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));

            removeDeferredMessages(CONNECT);
            if (mLastConnectionState == BluetoothProfile.STATE_CONNECTED) {
                log("CONNECTED->CONNTECTED: Ignore");
             } else {
                broadcastConnectionState(mDevice, mLastConnectionState,
                                              BluetoothProfile.STATE_CONNECTED);
                //initialize PACs for this devices
                if (mPacsAvail == true) {
                    /*
                    PacsClientService mPacsClientService = PacsClientService.getPacsClientService();
                    if (mPacsClientService != null) {
                        log("trigger connect to Pacs");
                        mPacsClientService.connect(mDevice);
                    } else {
                        Log.e(TAG, "PACs interface is null");
                    }
                    */
                 }

                ///*_VCP
                if (mVcpForBroadcast) {
                    VcpController vcpController = VcpController.getVcpController();
                    if (vcpController != null) {
                        log("trigger connect to Vcp Renderer");
                        if (!vcpController.connect(mDevice, BluetoothVcp.MODE_BROADCAST)) {
                            log("Connect vcp failed");
                        }
                    } else {
                        Log.e(TAG, "VcpController interface is null");
                    }
                }
                //_VCP*/
             }
        }

        @Override
        public void exit() {
            log("Exit Connected(" + mDevice + "): "
                    + messageWhatToString(getCurrentMessage().what));
            mLastConnectionState = BluetoothProfile.STATE_CONNECTED;
        }

        @Override
        public boolean processMessage(Message message) {
            log("Connected process message(" + mDevice + "): "
                    + messageWhatToString(message.what));
            BleBroadcastSourceInfo srcInfo;
            switch (message.what) {
                case CONNECT:
                    Log.w(TAG, "Connected: CONNECT ignored: " + mDevice);
                    break;
                case DISCONNECT:
                    log("Disconnecting from " + mDevice);
                    if (mBluetoothGatt != null) {
                        mBluetoothGatt.disconnect();
                        mBluetoothGatt.close();
                        mBluetoothGatt = null;
                        //transitionTo(mDisconnecting);
                        cancelActiveSync(null);
                        //Trigger the CSip disconnection, dont worry about pass/failure
                        if (mCsipConnected && mSetCoordinator != null) {
                             mSetCoordinator.disconnect(mService.mCsipAppId, mDevice);
                             mCsipConnected = false;
                        }
                        transitionTo(mDisconnected);
                    } else {
                        log("mBluetoothGatt is null");
                    }
                    break;
                case CONNECTION_STATE_CHANGED:
                    int state = (int)message.obj;
                    Log.w(TAG, "Connected:connection state changed:" + state);
                    if (state == BluetoothProfile.STATE_CONNECTED) {
                        Log.w(TAG, "device is already connected to Bass" + mDevice);
                    } else {
                        Log.w(TAG, "unexpected disconnected from " + mDevice);
                        cancelActiveSync(null);
                        ///*_CSIP
                        //Trigger the CSip disconnection, dont worry about pass/failure
                        if (mCsipConnected) {
                              mSetCoordinator.disconnect(mService.mCsipAppId, mDevice);
                              mCsipConnected = false;
                        }
                        //_CSIP*/
                        transitionTo(mDisconnected);
                    }
                    break;
                case READ_BASS_CHARACTERISTICS:
                    BluetoothGattCharacteristic characteristic = (BluetoothGattCharacteristic)message.obj;
                    if (mBluetoothGatt != null) {
                        mBluetoothGatt.readCharacteristic(characteristic);
                        transitionTo(mConnectedProcessing);
                    } else {
                        Log.e(TAG, "READ_BASS_CHARACTERISTICS is ignored, Gatt handle is null");
                    }
                    break;
                case START_SCAN_OFFLOAD:
                    if (mBluetoothGatt != null &&
                         mBroadcastScanControlPoint != null) {
                        mBroadcastScanControlPoint.setValue(REMOTE_SCAN_START);
                        mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                        mPendingOperation = message.what;
                        transitionTo(mConnectedProcessing);
                    } else {
                        log("no Bluetooth Gatt handle, may need to fetch write");
                    }
                    break;
                case STOP_SCAN_OFFLOAD:
                    if (mBluetoothGatt != null &&
                          mBroadcastScanControlPoint != null) {
                        mBroadcastScanControlPoint.setValue(REMOTE_SCAN_STOP);
                        mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                        mPendingOperation = message.what;
                        transitionTo(mConnectedProcessing);
                    } else {
                        log("no Bluetooth Gatt handle, may need to fetch write");
                    }
                    break;
                case SELECT_BCAST_SOURCE:
                    ScanResult scanRes = (ScanResult)message.obj;
                    boolean auto = ((int) message.arg1) == AUTO;
                    boolean isGroupOp = ((int) message.arg2) == GROUP_OP;
                    selectBroadcastSource(scanRes, isGroupOp, auto);
                    break;
                case ADD_BCAST_SOURCE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    log("Adding Broadcast source" + srcInfo);
                    byte[] addSourceInfo =  convertSourceInfoToAddSourceByteArray(srcInfo);
                    if (addSourceInfo == null) {
                        Log.e(TAG, "add source: source Info is NULL");
                        break;
                    }
                    if (mBluetoothGatt != null &&
                          mBroadcastScanControlPoint != null) {
                        mBroadcastScanControlPoint.setValue(addSourceInfo);
                        mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                        mPendingOperation = message.what;
                        transitionTo(mConnectedProcessing);
                        sendMessageDelayed(GATT_TXN_TIMEOUT, GATT_TXN_TIMEOUT_MS);
                    } else {
                        Log.e(TAG, "ADD_BCAST_SOURCE: no Bluetooth Gatt handle, Fatal");
                        sendPendingCallbacks(ADD_BCAST_SOURCE,INVALID_SRC_ID,
                            BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL);
                    }
                    break;
                case UPDATE_BCAST_SOURCE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    mAutoTriggerred = ((int) message.arg1) == AUTO;
                    log("Updating Broadcast source" + srcInfo);
                    byte[] updateSourceInfo =  convertSourceInfoToUpdateSourceByteArray(srcInfo);
                    if (updateSourceInfo == null) {
                        Log.e(TAG, "update source: source Info is NULL");
                        break;
                    }
                    if (mBluetoothGatt != null &&
                          mBroadcastScanControlPoint != null) {
                        mBroadcastScanControlPoint.setValue(updateSourceInfo);
                        mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                        mPendingOperation = message.what;
                        mPendingSourceId = srcInfo.getSourceId();
                        transitionTo(mConnectedProcessing);
                        sendMessageDelayed(GATT_TXN_TIMEOUT, GATT_TXN_TIMEOUT_MS);
                    } else {
                        Log.e(TAG, "UPDATE_BCAST_SOURCE: no Bluetooth Gatt handle, Fatal");
                        sendPendingCallbacks(UPDATE_BCAST_SOURCE,INVALID_SRC_ID,
                            BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL);
                    }
                    break;
                case SET_BCAST_CODE:
                    srcInfo = (BleBroadcastSourceInfo)message.obj;
                    int cmdType = message.arg1;
                    log("SET_BCAST_CODE srcInfo: " + srcInfo);

                    if (cmdType != QUEUED &&
                        IsItRightTimeToUpdateBroadcastPIN(srcInfo.getSourceId()) != true) {
                        mSetBroadcastCodePending = true;
                        mSetBroadcastPINSrcInfo = srcInfo;
                        log("Ignore SET_BCAST now, but store it for later");
                        //notify so that lock release happens as SET_BCAST_CODE
                        //queued for future
                        mService.notifyOperationCompletion(mDevice,SET_BCAST_CODE);
                    } else {
                        byte[] setBroadcastPINcmd =  convertSourceInfoToSetBroadcastCodeByteArray(srcInfo);
                        if (setBroadcastPINcmd == null) {
                            Log.e(TAG, "SET_BCAST_CODE: Broadcast code is NULL");
                            break;
                        }
                        if (mBluetoothGatt != null &&
                          mBroadcastScanControlPoint != null) {
                            mBroadcastScanControlPoint.setValue(setBroadcastPINcmd);
                            mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                            mPendingOperation = message.what;
                            mPendingSourceId = srcInfo.getSourceId();
                            transitionTo(mConnectedProcessing);
                            sendMessageDelayed(GATT_TXN_TIMEOUT, GATT_TXN_TIMEOUT_MS);
                        } else {
                            Log.e(TAG, "SET_BCAST_CODE: no Bluetooth Gatt handle, Fatal");
                            sendPendingCallbacks(SET_BCAST_CODE,INVALID_SRC_ID,
                                BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL);

                        }
                    }
                    break;
                case REMOVE_BCAST_SOURCE:
                    byte sourceId = (byte)message.arg1;
                    BluetoothDevice audioSrc = (BluetoothDevice)message.obj;
                    log("Removing Broadcast source: audioSource:" + audioSrc + "sourceId:" + sourceId);
                    byte[] removeSourceInfo = new byte [2];
                    removeSourceInfo[0] = BASS_REMOVE_SOURCE_OPCODE;
                    removeSourceInfo[1] = sourceId;
                    if (mBluetoothGatt != null &&
                          mBroadcastScanControlPoint != null) {
                        mBroadcastScanControlPoint.setValue(removeSourceInfo);
                        mBluetoothGatt.writeCharacteristic(mBroadcastScanControlPoint);
                        mPendingOperation = message.what;
                        mPendingSourceId = sourceId;
                        transitionTo(mConnectedProcessing);
                        sendMessageDelayed(GATT_TXN_TIMEOUT, GATT_TXN_TIMEOUT_MS);
                    } else {
                        Log.e(TAG, "REMOVE_BCAST_SOURCE: no Bluetooth Gatt handle, Fatal");
                        sendPendingCallbacks(REMOVE_BCAST_SOURCE,INVALID_SRC_ID,
                            BleBroadcastAudioScanAssistCallback.BASS_STATUS_FATAL);

                    }
                    break;
                case PSYNC_ACTIVE_TIMEOUT:
                    cancelActiveSync(null);
                    break;
                default:
                    log("CONNECTED: not handled message:" + message.what);
                    return NOT_HANDLED;
            }
            return HANDLED;
        }
    }


    void sendPendingCallbacks(int pendingOp, byte sourceId, int status) {
        if (status != 0) {
            //Notify service only In case of failure cases
            //Success case would have been notified through State machine anyways
            mService.notifyOperationCompletion(mDevice, pendingOp);
        }
        switch (pendingOp) {
            case START_SCAN_OFFLOAD:
                if (status != 0) {
                    if (mAutoTriggerred == false) {
                        log("notify the app only if start Scan offload fails");
                        //shouldnt happen in general
                        mService.sendBroadcastSourceSelectedCallback(mDevice, null, status);
                        cancelActiveSync(null);
                    } else {
                        mAutoTriggerred = false;
                    }
                }
                break;
            case ADD_BCAST_SOURCE:
                if (status != 0) {
                    sourceId = INVALID_SRC_ID;
                    cancelActiveSync(null);
                    //stop Scan offload for colocated case
                    mService.stopScanOffloadInternal(mDevice, false);
                }
                mService.sendAddBroadcastSourceCallback(mDevice, sourceId, status);
                break;
            case UPDATE_BCAST_SOURCE:
                if (mAutoTriggerred == false) {
                    mService.sendUpdateBroadcastSourceCallback(mDevice, sourceId, status);
                } else {
                    mAutoTriggerred = false;
                }
                break;
            case REMOVE_BCAST_SOURCE:
                mService.sendRemoveBroadcastSourceCallback(mDevice, sourceId, status);
                break;
            case SET_BCAST_CODE:
                mService.sendSetBroadcastPINupdatedCallback(mDevice, sourceId, status);
                break;
            default:
                    {
                        log("sendPendingCallbacks: unhandled case");
                    }
            }
    }
    @VisibleForTesting
    class ConnectedProcessing extends State {
         @Override
         public void enter() {
             log( "Enter ConnectedProcessing(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
         }

         @Override
         public void exit() {
             log("Exit ConnectedProcessing(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
         }
         @Override
         public boolean processMessage(Message message) {
             log("ConnectedProcessing process message(" + mDevice + "): " + messageWhatToString(
                     message.what));
             switch (message.what) {
                 case CONNECT:
                     Log.w(TAG, "CONNECT request is ignored" + mDevice);
                     break;
                 case DISCONNECT:
                     Log.w(TAG, "DISCONNECT requested!: " + mDevice);
                     if (mBluetoothGatt != null) {
                        mBluetoothGatt.disconnect();
                        mBluetoothGatt.close();
                        mBluetoothGatt = null;
                        cancelActiveSync(null);
                        //Trigger the CSIP disconnection, dont worry about pass/failure
                        if (mCsipConnected && mSetCoordinator != null) {
                             mSetCoordinator.disconnect(mService.mCsipAppId, mDevice);
                             mCsipConnected = false;
                        }
                        transitionTo(mDisconnected);
                    } else {
                        log("mBluetoothGatt is null");
                    }
                     break;
                 case READ_BASS_CHARACTERISTICS:
                       Log.w(TAG, "defer READ_BASS_CHARACTERISTICS requested!: " + mDevice);
                      deferMessage(message);
                      break;
                 case CONNECTION_STATE_CHANGED:
                     int state = (int)message.obj;
                     Log.w(TAG, "ConnectedProcessing: connection state changed:" + state);
                     if (state == BluetoothProfile.STATE_CONNECTED) {
                         Log.w(TAG, "should never happen from this state");
                     } else {
                         Log.w(TAG, "Unexpected disconnection " + mDevice);
                         transitionTo(mDisconnected);
                     }
                     break;
                case GATT_TXN_PROCESSED:
                    removeMessages(GATT_TXN_TIMEOUT);
                    int status = (int)message.arg1;
                    log( "GATT transaction processed for" + mDevice);
                    mService.notifyOperationCompletion(mDevice, mPendingOperation);
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        if (mPendingOperation == SET_BCAST_CODE) {
                            //If Pending operation is SET_BCAST_CODE
                            //send callback to notify BCAST is updated
                            //This is needed only for SET_BCAST operation
                           sendPendingCallbacks(mPendingOperation,
                                  mPendingSourceId, BleBroadcastAudioScanAssistCallback.BASS_STATUS_SUCCESS);
                        }
                    } else {
                        //any failure to write operation
                        //will be converted to corresponding
                        //callback with failure status
                        sendPendingCallbacks(mPendingOperation,
                                  mPendingSourceId, BleBroadcastAudioScanAssistCallback.BASS_STATUS_FAILURE);
                    }
                    transitionTo(mConnected);
                    break;
                case GATT_TXN_TIMEOUT:
                    log( "GATT transaction timedout for" + mDevice);
                    mService.notifyOperationCompletion(mDevice, mPendingOperation);
                    sendPendingCallbacks(mPendingOperation,
                                 mPendingSourceId, BleBroadcastAudioScanAssistCallback.BASS_STATUS_TXN_TIMEOUT);
                    mPendingOperation = -1;
                    transitionTo(mConnected);
                    mPendingSourceId = -1;
               break;
                case START_SCAN_OFFLOAD:
                case STOP_SCAN_OFFLOAD:
                case SELECT_BCAST_SOURCE:
                case ADD_BCAST_SOURCE:
                case SET_BCAST_CODE:
                case REMOVE_BCAST_SOURCE:
                case PSYNC_ACTIVE_TIMEOUT:
                    log("defer the message:" + message.what + "so that it will be processed later");
                    deferMessage(message);
                       break;
                 default:
                     log("CONNECTEDPROCESSING: not handled message:" + message.what);
                    return NOT_HANDLED;
             }
             return HANDLED;
         }
     }


    @VisibleForTesting
     class Disconnecting extends State {
         @Override
         public void enter() {
             log( "Enter Disconnecting(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
             sendMessageDelayed(CONNECT_TIMEOUT, mDevice, mConnectTimeoutMs);
             broadcastConnectionState(mDevice, mLastConnectionState,
                               BluetoothProfile.STATE_DISCONNECTING);
         }
         @Override
         public void exit() {
             log("Exit Disconnecting(" + mDevice + "): " + messageWhatToString(
                     getCurrentMessage().what));
             removeMessages(CONNECT_TIMEOUT);
             mLastConnectionState = BluetoothProfile.STATE_DISCONNECTING;
         }
         @Override
         public boolean processMessage(Message message) {
             log("Disconnecting process message(" + mDevice + "): " + messageWhatToString(
                     message.what));
             switch (message.what) {
                 case CONNECT:
                     log("Disconnecting to " + mDevice);
                     log("deferring this connection request " + mDevice);
                     deferMessage(message);
                     break;
                 case DISCONNECT:
                     Log.w(TAG, "Already disconnecting: DISCONNECT ignored: " + mDevice);
                     break;
                 case CONNECTION_STATE_CHANGED:
                     int state = (int)message.obj;
                     Log.w(TAG, "Disconnecting: connection state changed:" + state);
                     if (state == BluetoothProfile.STATE_CONNECTED) {
                         Log.e(TAG, "should never happen from this state");
                         transitionTo(mConnected);
                     } else {
                         Log.w(TAG, "disconnection successfull to " + mDevice);
                         cancelActiveSync(null);
                         transitionTo(mDisconnected);
                         ///*_CSIP
                         //Trigger the CSip disconnection, dont worry about pass/failure
                         if (mCsipConnected) {
                             mSetCoordinator.disconnect(mService.mCsipAppId, mDevice);
                             mCsipConnected = false;
                         }
                         //_CSIP*/
                     }
                     break;
                 case CONNECT_TIMEOUT:
                     Log.w(TAG, "CONNECT_TIMEOUT");

                    BluetoothDevice device = (BluetoothDevice) message.obj;
                    if (!mDevice.equals(device)) {
                         Log.e(TAG, "Unknown device timeout " + device);
                         break;
                    }
                    transitionTo(mDisconnected);
            break;
                 default:
                     return NOT_HANDLED;
             }
             return HANDLED;
         }
     }


    void broadcastConnectionState(BluetoothDevice device, int fromState, int toState) {
         log( "broadcastConnectionState " + device + ": " + fromState + "->" + toState);
         if (fromState == BluetoothProfile.STATE_CONNECTED &&
             toState == BluetoothProfile.STATE_CONNECTED) {
             log("CONNECTED->CONNTECTED: Ignore");
            return;
         }
         Intent intent = new Intent(BluetoothSyncHelper.ACTION_CONNECTION_STATE_CHANGED);
         intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, fromState);
         intent.putExtra(BluetoothProfile.EXTRA_STATE, toState);
         intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
         intent.addFlags(Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
         mService.sendBroadcastAsUser(intent, UserHandle.ALL,
                 BLUETOOTH_CONNECT, Utils.getTempAllowlistBroadcastOptions());
    }

    int getConnectionState() {
        String currentState = "Unknown";
        if (getCurrentState() != null) {
            currentState = getCurrentState().getName();
        }
        switch (currentState) {
            case "Disconnected":
                log("Disconnected");
                return BluetoothProfile.STATE_DISCONNECTED;
            case "Disconnecting":
                log("Disconnecting");
                return BluetoothProfile.STATE_DISCONNECTING;
            case "Connecting":
                log("Connecting");
                return BluetoothProfile.STATE_CONNECTING;
            case "Connected":
            case "ConnectedProcessing":
                log("connected");
                return BluetoothProfile.STATE_CONNECTED;
            default:
                Log.e(TAG, "Bad currentState: " + currentState);
                return BluetoothProfile.STATE_DISCONNECTED;
        }
    }

    BluetoothDevice getDevice() {
        return mDevice;
    }

    synchronized boolean isConnected() {
        return getCurrentState() == mConnected;
    }

    public static String messageWhatToString(int what) {
        switch (what) {
            case CONNECT:
                return "CONNECT";
            case DISCONNECT:
                return "DISCONNECT";
            case CONNECTION_STATE_CHANGED:
                return "CONNECTION_STATE_CHANGED";
            case GATT_TXN_PROCESSED:
                return "GATT_TXN_PROCESSED";
            case READ_BASS_CHARACTERISTICS:
                return "READ_BASS_CHARACTERISTICS";
            case START_SCAN_OFFLOAD:
                return "START_SCAN_OFFLOAD";
            case STOP_SCAN_OFFLOAD:
                return "STOP_SCAN_OFFLOAD";
            case ADD_BCAST_SOURCE:
                return "ADD_BCAST_SOURCE";
            case SELECT_BCAST_SOURCE:
                return "SELECT_BCAST_SOURCE";
            case UPDATE_BCAST_SOURCE:
                return "UPDATE_BCAST_SOURCE";
            case SET_BCAST_CODE:
                return "SET_BCAST_CODE";
            case REMOVE_BCAST_SOURCE:
                return "REMOVE_BCAST_SOURCE";
            case PSYNC_ACTIVE_TIMEOUT:
                return "PSYNC_ACTIVE_TIMEOUT";
            case CSIP_CONNECTION_STATE_CHANGED:
                return "CSIP_CONNECTION_STATE_CHANGED";
            case CONNECT_TIMEOUT:
                return "CONNECT_TIMEOUT";
            default:
                break;
        }
        return Integer.toString(what);
    }

    private static String profileStateToString(int state) {
        switch (state) {
            case BluetoothProfile.STATE_DISCONNECTED:
                return "DISCONNECTED";
            case BluetoothProfile.STATE_CONNECTING:
                return "CONNECTING";
            case BluetoothProfile.STATE_CONNECTED:
                return "CONNECTED";
            case BluetoothProfile.STATE_DISCONNECTING:
                return "DISCONNECTING";
            default:
                break;
        }
        return Integer.toString(state);
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mDevice: " + mDevice);
        ProfileService.println(sb, "  StateMachine: " + this);
        // Dump the state machine logs
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        super.dump(new FileDescriptor(), printWriter, new String[]{});
        printWriter.flush();
        stringWriter.flush();
        ProfileService.println(sb, "  StateMachineLog:");
        Scanner scanner = new Scanner(stringWriter.toString());
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            ProfileService.println(sb, "    " + line);
        }
        scanner.close();
    }

    @Override
    protected void log( String msg) {
        if (BASS_DBG) {
            super.log(msg);
        }
    }

    private static void logByteArray(String prefix, byte[] value, int offset, int count) {
        StringBuilder builder = new StringBuilder(prefix);
        for (int i = offset; i < count; i++) {
            builder.append(String.format("0x%02X", value[i]));
            if (i != value.length - 1) {
                builder.append(", ");
            }
        }
        Log.d(TAG, builder.toString());
    }
}
