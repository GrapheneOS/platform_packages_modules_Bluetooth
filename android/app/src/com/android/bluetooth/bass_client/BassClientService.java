/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.bluetooth.bass_client;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import static com.android.bluetooth.Utils.enforceBluetoothPrivilegedPermission;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothLeBroadcastMetadata;
import android.bluetooth.BluetoothLeBroadcastReceiveState;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothStatusCodes;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothLeBroadcastAssistant;
import android.bluetooth.IBluetoothLeBroadcastAssistantCallback;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.sysprop.BluetoothProperties;
import android.util.Log;
import android.util.Pair;

import com.android.bluetooth.BluetoothEventLogger;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.btservice.ServiceFactory;
import com.android.bluetooth.btservice.storage.DatabaseManager;
import com.android.bluetooth.csip.CsipSetCoordinatorService;
import com.android.bluetooth.flags.FeatureFlags;
import com.android.bluetooth.flags.FeatureFlagsImpl;
import com.android.bluetooth.le_audio.LeAudioService;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Broacast Assistant Scan Service
 */
public class BassClientService extends ProfileService {
    private static final boolean DBG = true;
    private static final String TAG = BassClientService.class.getSimpleName();
    private static final int MAX_BASS_CLIENT_STATE_MACHINES = 10;
    private static final int MAX_ACTIVE_SYNCED_SOURCES_NUM = 4;

    private static BassClientService sService;

    private final Map<BluetoothDevice, BassClientStateMachine> mStateMachines = new HashMap<>();
    private final Object mSearchScanCallbackLock = new Object();
    private final Map<Integer, ScanResult> mCachedBroadcasts = new HashMap<>();

    private final Map<BluetoothDevice, List<Pair<Integer, Object>>> mPendingGroupOp =
            new ConcurrentHashMap<>();
    private final Map<BluetoothDevice, List<Integer>> mGroupManagedSources =
            new ConcurrentHashMap<>();
    private final Map<BluetoothDevice, List<Integer>> mActiveSourceMap = new ConcurrentHashMap<>();
    private final FeatureFlags mFeatureFlags;
    private final Map<BluetoothDevice, BluetoothLeBroadcastMetadata> mBroadcastMetadataMap =
            new ConcurrentHashMap<>();
    private final LinkedList<BluetoothDevice> mPausedBroadcastSinks = new LinkedList<>();

    private HandlerThread mStateMachinesThread;
    private HandlerThread mCallbackHandlerThread;
    private Handler mHandler = null;
    private AdapterService mAdapterService;
    private DatabaseManager mDatabaseManager;
    private BluetoothAdapter mBluetoothAdapter = null;

    /* Caching the PeriodicAdvertisementResult from Broadcast source */
    /* This is stored at service so that each device state machine can access
    and use it as needed. Once the periodic sync in cancelled, this data will bre
    removed to ensure stable data won't used */
    /* syncHandle, broadcastSrcDevice */
    private Map<Integer, BluetoothDevice> mSyncHandleToDeviceMap;
    /*syncHandle, parsed BaseData data*/
    private Map<Integer, BaseData> mSyncHandleToBaseDataMap;
    /*syncHandle, broadcast id */
    private Map<Integer, Integer> mSyncHandleToBroadcastIdMap;
    /*bcastSrcDevice, corresponding broadcast id and PeriodicAdvertisementResult*/
    private Map<BluetoothDevice, HashMap<Integer, PeriodicAdvertisementResult>>
            mPeriodicAdvertisementResultMap;
    private ScanCallback mSearchScanCallback;
    private Callbacks mCallbacks;

    private static final int LOG_NB_EVENTS = 100;
    private static final BluetoothEventLogger sEventLogger =
            new BluetoothEventLogger(LOG_NB_EVENTS, TAG + " event log");
    ;

    @VisibleForTesting
    ServiceFactory mServiceFactory = new ServiceFactory();

    BassClientService() {
        mFeatureFlags = new FeatureFlagsImpl();
    }

    @VisibleForTesting
    BassClientService(Context ctx, FeatureFlags featureFlags) {
        attachBaseContext(ctx);
        mFeatureFlags = featureFlags;
        onCreate();
    }

    public static boolean isEnabled() {
        return BluetoothProperties.isProfileBapBroadcastAssistEnabled().orElse(false);
    }

    void updatePeriodicAdvertisementResultMap(
            BluetoothDevice device,
            int addressType,
            int syncHandle,
            int advSid,
            int advInterval,
            int bId,
            PublicBroadcastData pbData,
            String broadcastName) {
        log("updatePeriodicAdvertisementResultMap: device: " + device);
        log("updatePeriodicAdvertisementResultMap: syncHandle: " + syncHandle);
        log("updatePeriodicAdvertisementResultMap: advSid: " + advSid);
        log("updatePeriodicAdvertisementResultMap: addressType: " + addressType);
        log("updatePeriodicAdvertisementResultMap: advInterval: " + advInterval);
        log("updatePeriodicAdvertisementResultMap: broadcastId: " + bId);
        log("updatePeriodicAdvertisementResultMap: broadcastName: " + broadcastName);
        log("mSyncHandleToDeviceMap" + mSyncHandleToDeviceMap);
        log("mPeriodicAdvertisementResultMap" + mPeriodicAdvertisementResultMap);
        // Cache the SyncHandle and source device
        if (mSyncHandleToDeviceMap != null && syncHandle != BassConstants.INVALID_SYNC_HANDLE) {
            mSyncHandleToDeviceMap.put(syncHandle, device);
        }
        if (mPeriodicAdvertisementResultMap != null) {
            HashMap<Integer, PeriodicAdvertisementResult> paResMap =
                    mPeriodicAdvertisementResultMap.get(device);
            if (paResMap == null
                    || (bId != BassConstants.INVALID_BROADCAST_ID && !paResMap.containsKey(bId))) {
                log("PAResmap: add >>>");
                PeriodicAdvertisementResult paRes = new PeriodicAdvertisementResult(device,
                        addressType, syncHandle, advSid, advInterval, bId, pbData, broadcastName);
                if (paRes != null) {
                    paRes.print();
                    mPeriodicAdvertisementResultMap.putIfAbsent(device, new HashMap<>());
                    mPeriodicAdvertisementResultMap.get(device).put(bId, paRes);
                }
            } else {
                log("PAResmap: update >>>");
                if (bId == BassConstants.INVALID_BROADCAST_ID) {
                    // Update when onSyncEstablished, try to retrieve valid broadcast id
                    for (Map.Entry<Integer, PeriodicAdvertisementResult> entry :
                            paResMap.entrySet()) {
                        PeriodicAdvertisementResult value = entry.getValue();
                        if (value.getBroadcastId() != BassConstants.INVALID_BROADCAST_ID) {
                            bId = value.getBroadcastId();
                            break;
                        }
                    }
                    if (bId == BassConstants.INVALID_BROADCAST_ID) {
                        log("PAResmap: error! no valid broadcast id found>>>");
                        return;
                    }
                }
                PeriodicAdvertisementResult paRes = paResMap.get(bId);
                if (advSid != BassConstants.INVALID_ADV_SID) {
                    paRes.updateAdvSid(advSid);
                }
                if (syncHandle != BassConstants.INVALID_SYNC_HANDLE) {
                    paRes.updateSyncHandle(syncHandle);
                    if (mSyncHandleToBroadcastIdMap != null
                            && paRes.getBroadcastId() != BassConstants.INVALID_BROADCAST_ID) {
                        // broadcast successfully synced, update the map
                        mSyncHandleToBroadcastIdMap.put(syncHandle, paRes.getBroadcastId());
                    }
                }
                if (addressType != BassConstants.INVALID_ADV_ADDRESS_TYPE) {
                    paRes.updateAddressType(addressType);
                }
                if (advInterval != BassConstants.INVALID_ADV_INTERVAL) {
                    paRes.updateAdvInterval(advInterval);
                }
                if (bId != BassConstants.INVALID_BROADCAST_ID) {
                    paRes.updateBroadcastId(bId);
                }
                if (pbData != null) {
                    paRes.updatePublicBroadcastData(pbData);
                }
                if (broadcastName != null) {
                    paRes.updateBroadcastName(broadcastName);
                }
                paRes.print();
                paResMap.replace(bId, paRes);
            }
        }
        log(">>mPeriodicAdvertisementResultMap" + mPeriodicAdvertisementResultMap);
    }

    PeriodicAdvertisementResult getPeriodicAdvertisementResult(
            BluetoothDevice device, int broadcastId) {
        if (mPeriodicAdvertisementResultMap == null) {
            Log.e(TAG, "getPeriodicAdvertisementResult: mPeriodicAdvertisementResultMap is null");
            return null;
        }

        if (broadcastId == BassConstants.INVALID_BROADCAST_ID) {
            Log.e(TAG, "getPeriodicAdvertisementResult: invalid broadcast id");
            return null;
        }

        if (mPeriodicAdvertisementResultMap.containsKey(device)) {
            return mPeriodicAdvertisementResultMap.get(device).get(broadcastId);
        }
        return null;
    }

    void clearNotifiedFlags() {
        log("clearNotifiedFlags");
        for (Map.Entry<BluetoothDevice, HashMap<Integer, PeriodicAdvertisementResult>> entry :
                mPeriodicAdvertisementResultMap.entrySet()) {
            HashMap<Integer, PeriodicAdvertisementResult> value = entry.getValue();
            for (PeriodicAdvertisementResult result : value.values()) {
                result.setNotified(false);
                result.print();
            }
        }
    }

    void updateBase(int syncHandlemap, BaseData base) {
        if (mSyncHandleToBaseDataMap == null) {
            Log.e(TAG, "updateBase: mSyncHandleToBaseDataMap is null");
            return;
        }
        log("updateBase : mSyncHandleToBaseDataMap>>");
        mSyncHandleToBaseDataMap.put(syncHandlemap, base);
    }

    BaseData getBase(int syncHandlemap) {
        if (mSyncHandleToBaseDataMap == null) {
            Log.e(TAG, "getBase: mSyncHandleToBaseDataMap is null");
            return null;
        }
        BaseData base = mSyncHandleToBaseDataMap.get(syncHandlemap);
        log("getBase returns" + base);
        return base;
    }

    void removeActiveSyncedSource(BluetoothDevice scanDelegator, Integer syncHandle) {
        if (mActiveSourceMap == null) {
            Log.e(TAG, "removeActiveSyncedSource: mActiveSourceMap is null");
            return;
        }

        log("removeActiveSyncedSource, scanDelegator: " + scanDelegator + ", syncHandle: "
                + syncHandle);
        if (syncHandle == null) {
            // remove all sources for this scanDelegator
            mActiveSourceMap.remove(scanDelegator);
        } else {
            List<Integer> sources = mActiveSourceMap.get(scanDelegator);
            if (sources != null) {
                sources.removeIf(e -> e.equals(syncHandle));
                if (sources.isEmpty()) {
                    mActiveSourceMap.remove(scanDelegator);
                }
            }
        }
        sEventLogger.logd(DBG, TAG, "Broadcast Source Unsynced: scanDelegator= " + scanDelegator
                + ", syncHandle= " + syncHandle);
    }

    void addActiveSyncedSource(BluetoothDevice scanDelegator, Integer syncHandle) {
        if (mActiveSourceMap == null) {
            Log.e(TAG, "addActiveSyncedSource: mActiveSourceMap is null");
            return;
        }

        log("addActiveSyncedSource, scanDelegator: " + scanDelegator + ", syncHandle: "
                + syncHandle);
        if (syncHandle != BassConstants.INVALID_SYNC_HANDLE) {
            mActiveSourceMap.putIfAbsent(scanDelegator, new ArrayList<>());
            if (!mActiveSourceMap.get(scanDelegator).contains(syncHandle)) {
                mActiveSourceMap.get(scanDelegator).add(syncHandle);
            }
        }
        sEventLogger.logd(DBG, TAG, "Broadcast Source Synced: scanDelegator= " + scanDelegator
                + ", syncHandle= " + syncHandle);
    }

    List<Integer> getActiveSyncedSources(BluetoothDevice scanDelegator) {
        if (mActiveSourceMap == null) {
            Log.e(TAG, "getActiveSyncedSources: mActiveSourceMap is null");
            return null;
        }

        List<Integer> currentSources = mActiveSourceMap.get(scanDelegator);
        if (currentSources != null) {
            log("getActiveSyncedSources: scanDelegator: " + scanDelegator
                    + ", sources num: " + currentSources.size());
        } else {
            log("getActiveSyncedSources: scanDelegator: " + scanDelegator
                    + ", currentSources is null");
        }
        return currentSources;
    }

    ScanResult getCachedBroadcast(int broadcastId) {
        return mCachedBroadcasts.get(broadcastId);
    }

    public Callbacks getCallbacks() {
        return mCallbacks;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new BluetoothLeBroadcastAssistantBinder(this);
    }

    @Override
    protected boolean start() {
        if (DBG) {
            Log.d(TAG, "start()");
        }
        if (sService != null) {
            throw new IllegalStateException("start() called twice");
        }
        mAdapterService = Objects.requireNonNull(AdapterService.getAdapterService(),
                "AdapterService cannot be null when BassClientService starts");
        mDatabaseManager = Objects.requireNonNull(mAdapterService.getDatabase(),
                "DatabaseManager cannot be null when BassClientService starts");
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        // Setup Handler to handle local broadcast use cases.
        mHandler = new Handler(Looper.getMainLooper());

        mStateMachines.clear();
        mStateMachinesThread = new HandlerThread("BassClientService.StateMachines");
        mStateMachinesThread.start();
        mCallbackHandlerThread = new HandlerThread(TAG);
        mCallbackHandlerThread.start();
        mCallbacks = new Callbacks(mCallbackHandlerThread.getLooper());

        setBassClientService(this);
        // Saving PSync stuff for future addition
        mSyncHandleToDeviceMap = new HashMap<Integer, BluetoothDevice>();
        mPeriodicAdvertisementResultMap =
                new HashMap<BluetoothDevice, HashMap<Integer, PeriodicAdvertisementResult>>();
        mSyncHandleToBaseDataMap = new HashMap<Integer, BaseData>();
        mSyncHandleToBroadcastIdMap = new HashMap<Integer, Integer>();
        mSearchScanCallback = null;
        return true;
    }

    @Override
    protected boolean stop() {
        if (DBG) {
            Log.d(TAG, "stop()");
        }

        synchronized (mStateMachines) {
            for (BassClientStateMachine sm : mStateMachines.values()) {
                BassObjectsFactory.getInstance().destroyStateMachine(sm);
            }
            mStateMachines.clear();
        }
        if (mCallbackHandlerThread != null) {
            mCallbackHandlerThread.quitSafely();
            mCallbackHandlerThread = null;
        }
        if (mStateMachinesThread != null) {
            mStateMachinesThread.quitSafely();
            mStateMachinesThread = null;
        }

        // Unregister Handler and stop all queued messages.
        if (mHandler != null) {
            mHandler.removeCallbacksAndMessages(null);
            mHandler = null;
        }

        setBassClientService(null);
        if (mSyncHandleToDeviceMap != null) {
            mSyncHandleToDeviceMap.clear();
            mSyncHandleToDeviceMap = null;
        }
        if (mPeriodicAdvertisementResultMap != null) {
            mPeriodicAdvertisementResultMap.clear();
            mPeriodicAdvertisementResultMap = null;
        }
        if (mActiveSourceMap != null) {
            mActiveSourceMap.clear();
        }
        if (mPendingGroupOp != null) {
            mPendingGroupOp.clear();
        }
        if (mCachedBroadcasts != null) {
            mCachedBroadcasts.clear();
        }
        if (mBroadcastMetadataMap != null) {
            mBroadcastMetadataMap.clear();
        }
        if (mSyncHandleToBroadcastIdMap != null) {
            mSyncHandleToBroadcastIdMap.clear();
            mSyncHandleToBroadcastIdMap = null;
        }
        return true;
    }

    @Override
    public boolean onUnbind(Intent intent) {
        Log.d(TAG, "Need to unregister app");
        return super.onUnbind(intent);
    }

    BluetoothDevice getDeviceForSyncHandle(int syncHandle) {
        if (mSyncHandleToDeviceMap == null) {
            return null;
        }
        return mSyncHandleToDeviceMap.get(syncHandle);
    }

    int getSyncHandleForBroadcastId(int broadcastId) {
        if (mSyncHandleToBroadcastIdMap == null) {
            return BassConstants.INVALID_SYNC_HANDLE;
        }

        int syncHandle = BassConstants.INVALID_SYNC_HANDLE;
        for (Map.Entry<Integer, Integer> entry : mSyncHandleToBroadcastIdMap.entrySet()) {
            Integer value = entry.getValue();
            if (value == broadcastId) {
                syncHandle = entry.getKey();
                break;
            }
        }
        return syncHandle;
    }

    int getBroadcastIdForSyncHandle(int syncHandle) {
        if (mSyncHandleToBroadcastIdMap == null) {
            return BassConstants.INVALID_BROADCAST_ID;
        }

        if (mSyncHandleToBroadcastIdMap.containsKey(syncHandle)) {
            return mSyncHandleToBroadcastIdMap.get(syncHandle);
        }
        return BassConstants.INVALID_BROADCAST_ID;
    }

    private static synchronized void setBassClientService(BassClientService instance) {
        if (DBG) {
            Log.d(TAG, "setBassClientService(): set to: " + instance);
        }
        sService = instance;
    }

    private void enqueueSourceGroupOp(BluetoothDevice sink, Integer msgId, Object obj) {
        log("enqueueSourceGroupOp device: " + sink + ", msgId: " + msgId);

        if (!mPendingGroupOp.containsKey(sink)) {
            mPendingGroupOp.put(sink, new ArrayList());
        }
        mPendingGroupOp.get(sink).add(new Pair<Integer, Object>(msgId, obj));
    }

    private boolean isSuccess(int status) {
        boolean ret = false;
        switch (status) {
            case BluetoothStatusCodes.REASON_LOCAL_APP_REQUEST:
            case BluetoothStatusCodes.REASON_LOCAL_STACK_REQUEST:
            case BluetoothStatusCodes.REASON_REMOTE_REQUEST:
            case BluetoothStatusCodes.REASON_SYSTEM_POLICY:
                ret = true;
                break;
            default:
                break;
        }
        return ret;
    }

    private void checkForPendingGroupOpRequest(BluetoothDevice sink, int reason, int reqMsg,
            Object obj) {
        log("checkForPendingGroupOpRequest device: " + sink + ", reason: " + reason
                + ", reqMsg: " + reqMsg);

        List<Pair<Integer, Object>> operations = mPendingGroupOp.get(sink);
        if (operations == null) {
            return;
        }

        switch (reqMsg) {
            case BassClientStateMachine.ADD_BCAST_SOURCE:
                if (obj == null) {
                    return;
                }
                // Identify the operation by operation type and broadcastId
                if (isSuccess(reason)) {
                    BluetoothLeBroadcastReceiveState sourceState =
                            (BluetoothLeBroadcastReceiveState) obj;
                    boolean removed = operations.removeIf(m ->
                            (m.first.equals(BassClientStateMachine.ADD_BCAST_SOURCE))
                            && (sourceState.getBroadcastId()
                                    == ((BluetoothLeBroadcastMetadata) m.second).getBroadcastId()));
                    if (removed) {
                        setSourceGroupManaged(sink, sourceState.getSourceId(), true);

                    }
                } else {
                    BluetoothLeBroadcastMetadata metadata = (BluetoothLeBroadcastMetadata) obj;
                    operations.removeIf(m ->
                            (m.first.equals(BassClientStateMachine.ADD_BCAST_SOURCE))
                            && (metadata.getBroadcastId()
                                    == ((BluetoothLeBroadcastMetadata) m.second).getBroadcastId()));
                }
                break;
            case BassClientStateMachine.REMOVE_BCAST_SOURCE:
                // Identify the operation by operation type and sourceId
                Integer sourceId = (Integer) obj;
                operations.removeIf(m ->
                        m.first.equals(BassClientStateMachine.REMOVE_BCAST_SOURCE)
                        && (sourceId.equals((Integer) m.second)));
                setSourceGroupManaged(sink, sourceId, false);
                break;
            default:
                break;
        }
    }

    private void setSourceGroupManaged(BluetoothDevice sink, int sourceId, boolean isGroupOp) {
        log("setSourceGroupManaged device: " + sink);
        if (isGroupOp) {
            if (!mGroupManagedSources.containsKey(sink)) {
                mGroupManagedSources.put(sink, new ArrayList<>());
            }
            mGroupManagedSources.get(sink).add(sourceId);
        } else {
            List<Integer> sources = mGroupManagedSources.get(sink);
            if (sources != null) {
                sources.removeIf(e -> e.equals(sourceId));
            }
        }
    }

    private Pair<BluetoothLeBroadcastMetadata, Map<BluetoothDevice, Integer>>
            getGroupManagedDeviceSources(BluetoothDevice sink, Integer sourceId) {
        log("getGroupManagedDeviceSources device: " + sink + " sourceId: " + sourceId);
        Map map = new HashMap<BluetoothDevice, Integer>();

        if (mGroupManagedSources.containsKey(sink)
                && mGroupManagedSources.get(sink).contains(sourceId)) {
            BassClientStateMachine stateMachine = getOrCreateStateMachine(sink);
            BluetoothLeBroadcastMetadata metadata =
                    stateMachine.getCurrentBroadcastMetadata(sourceId);
            if (metadata != null) {
                int broadcastId = metadata.getBroadcastId();

                for (BluetoothDevice device: getTargetDeviceList(sink, true)) {
                    List<BluetoothLeBroadcastReceiveState> sources =
                            getOrCreateStateMachine(device).getAllSources();

                    // For each device, find the source ID having this broadcast ID
                    Optional<BluetoothLeBroadcastReceiveState> receiver = sources.stream()
                            .filter(e -> e.getBroadcastId() == broadcastId)
                            .findAny();
                    if (receiver.isPresent()) {
                        map.put(device, receiver.get().getSourceId());
                    } else {
                        // Put invalid source ID if the remote doesn't have it
                        map.put(device, BassConstants.INVALID_SOURCE_ID);
                    }
                }
                return new Pair<BluetoothLeBroadcastMetadata,
                        Map<BluetoothDevice, Integer>>(metadata, map);
            } else {
                Log.e(TAG, "Couldn't find broadcast metadata for device: "
                        + sink.getAnonymizedAddress() + ", and sourceId:" + sourceId);
            }
        }

        // Just put this single device if this source is not group managed
        map.put(sink, sourceId);
        return new Pair<BluetoothLeBroadcastMetadata, Map<BluetoothDevice, Integer>>(null, map);
    }

    private List<BluetoothDevice> getTargetDeviceList(BluetoothDevice device, boolean isGroupOp) {
        if (isGroupOp) {
            CsipSetCoordinatorService csipClient = mServiceFactory.getCsipSetCoordinatorService();
            if (csipClient != null) {
                // Check for coordinated set of devices in the context of CAP
                List<BluetoothDevice> csipDevices = csipClient.getGroupDevicesOrdered(device,
                        BluetoothUuid.CAP);
                if (!csipDevices.isEmpty()) {
                    return csipDevices;
                } else {
                    Log.w(TAG, "CSIP group is empty.");
                }
            } else {
                Log.e(TAG, "CSIP service is null. No grouping information available.");
            }
        }

        List<BluetoothDevice> devices = new ArrayList<>();
        devices.add(device);
        return devices;
    }

    private boolean isValidBroadcastSourceAddition(
            BluetoothDevice device, BluetoothLeBroadcastMetadata metaData) {
        boolean retval = true;
        List<BluetoothLeBroadcastReceiveState> currentAllSources = getAllSources(device);
        for (int i = 0; i < currentAllSources.size(); i++) {
            BluetoothLeBroadcastReceiveState state = currentAllSources.get(i);
            if (metaData.getSourceDevice().equals(state.getSourceDevice())
                    && metaData.getSourceAddressType() == state.getSourceAddressType()
                    && metaData.getSourceAdvertisingSid() == state.getSourceAdvertisingSid()
                    && metaData.getBroadcastId() == state.getBroadcastId()) {
                retval = false;
                Log.e(TAG, "isValidBroadcastSourceAddition: fail for " + device
                        + " metaData: " + metaData);
                break;
            }
        }
        return retval;
    }

    private boolean hasRoomForBroadcastSourceAddition(BluetoothDevice device) {
        BassClientStateMachine stateMachine = null;
        synchronized (mStateMachines) {
            stateMachine = getOrCreateStateMachine(device);
        }
        if (stateMachine == null) {
            log("stateMachine is null");
            return false;
        }
        boolean isRoomAvailable = false;
        String emptyBluetoothDevice = "00:00:00:00:00:00";
        for (BluetoothLeBroadcastReceiveState recvState: stateMachine.getAllSources()) {
            if (recvState.getSourceDevice().getAddress().equals(emptyBluetoothDevice)) {
                isRoomAvailable = true;
                break;
            }
        }
        log("isRoomAvailable: " + isRoomAvailable);
        return isRoomAvailable;
    }

    private BassClientStateMachine getOrCreateStateMachine(BluetoothDevice device) {
        if (device == null) {
            Log.e(TAG, "getOrCreateStateMachine failed: device cannot be null");
            return null;
        }
        synchronized (mStateMachines) {
            BassClientStateMachine stateMachine = mStateMachines.get(device);
            if (stateMachine != null) {
                return stateMachine;
            }
            // Limit the maximum number of state machines to avoid DoS attack
            if (mStateMachines.size() >= MAX_BASS_CLIENT_STATE_MACHINES) {
                Log.e(TAG, "Maximum number of Bassclient state machines reached: "
                        + MAX_BASS_CLIENT_STATE_MACHINES);
                return null;
            }
            log("Creating a new state machine for " + device);
            stateMachine =
                    BassObjectsFactory.getInstance()
                            .makeStateMachine(
                                    device, this, mStateMachinesThread.getLooper(), mFeatureFlags);
            mStateMachines.put(device, stateMachine);
            return stateMachine;
        }
    }

    /**
     * Get the BassClientService instance
     *
     * @return BassClientService instance
     */
    public static synchronized BassClientService getBassClientService() {
        if (sService == null) {
            Log.w(TAG, "getBassClientService(): service is NULL");
            return null;
        }
        if (!sService.isAvailable()) {
            Log.w(TAG, "getBassClientService(): service is not available");
            return null;
        }
        return sService;
    }

    private void removeStateMachine(BluetoothDevice device) {
        synchronized (mStateMachines) {
            BassClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                Log.w(TAG, "removeStateMachine: device " + device
                        + " does not have a state machine");
                return;
            }
            log("removeStateMachine: removing state machine for device: " + device);
            sm.doQuit();
            sm.cleanup();
            mStateMachines.remove(device);
        }

        // Cleanup device cache
        mPendingGroupOp.remove(device);
        mGroupManagedSources.remove(device);
        mActiveSourceMap.remove(device);
    }

    void handleConnectionStateChanged(BluetoothDevice device, int fromState, int toState) {
        mHandler.post(() -> connectionStateChanged(device, fromState, toState));
    }

    synchronized void connectionStateChanged(BluetoothDevice device, int fromState,
                                             int toState) {
        if (!isAvailable()) {
            Log.w(TAG, "connectionStateChanged: service is not available");
            return;
        }

        if ((device == null) || (fromState == toState)) {
            Log.e(TAG, "connectionStateChanged: unexpected invocation. device=" + device
                    + " fromState=" + fromState + " toState=" + toState);
            return;
        }

        sEventLogger.logd(
                DBG,
                TAG,
                "connectionStateChanged: fromState= "
                        + BluetoothProfile.getConnectionStateName(fromState)
                        + ", toState= "
                        + BluetoothProfile.getConnectionStateName(toState));

        // Check if the device is disconnected - if unbond, remove the state machine
        if (toState == BluetoothProfile.STATE_DISCONNECTED) {
            mPendingGroupOp.remove(device);

            int bondState = mAdapterService.getBondState(device);
            if (bondState == BluetoothDevice.BOND_NONE) {
                log("Unbonded " + device + ". Removing state machine");
                removeStateMachine(device);
            }
        }
    }

    public void handleBondStateChanged(BluetoothDevice device, int fromState, int toState) {
        mHandler.post(() -> bondStateChanged(device, toState));
    }

    @VisibleForTesting
    void bondStateChanged(BluetoothDevice device, int bondState) {
        log("Bond state changed for device: " + device + " state: " + bondState);

        // Remove state machine if the bonding for a device is removed
        if (bondState != BluetoothDevice.BOND_NONE) {
            return;
        }

        synchronized (mStateMachines) {
            BassClientStateMachine sm = mStateMachines.get(device);
            if (sm == null) {
                return;
            }
            if (sm.getConnectionState() != BluetoothProfile.STATE_DISCONNECTED) {
                Log.i(TAG, "Disconnecting device because it was unbonded.");
                disconnect(device);
                return;
            }
            removeStateMachine(device);
        }
    }

    /**
     * Connects the bass profile to the passed in device
     *
     * @param device is the device with which we will connect the Bass profile
     * @return true if BAss profile successfully connected, false otherwise
     */
    public boolean connect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "connect(): " + device);
        }
        if (device == null) {
            Log.e(TAG, "connect: device is null");
            return false;
        }
        if (getConnectionPolicy(device) == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            Log.e(TAG, "connect: connection policy set to forbidden");
            return false;
        }
        synchronized (mStateMachines) {
            BassClientStateMachine stateMachine = getOrCreateStateMachine(device);
            stateMachine.sendMessage(BassClientStateMachine.CONNECT);
        }
        return true;
    }

    /**
     * Disconnects Bassclient profile for the passed in device
     *
     * @param device is the device with which we want to disconnected the BAss client profile
     * @return true if Bass client profile successfully disconnected, false otherwise
     */
    public boolean disconnect(BluetoothDevice device) {
        if (DBG) {
            Log.d(TAG, "disconnect(): " + device);
        }
        if (device == null) {
            Log.e(TAG, "disconnect: device is null");
            return false;
        }
        synchronized (mStateMachines) {
            BassClientStateMachine stateMachine = getOrCreateStateMachine(device);
            stateMachine.sendMessage(BassClientStateMachine.DISCONNECT);
        }
        return true;
    }

    /**
     * Check whether can connect to a peer device. The check considers a number of factors during
     * the evaluation.
     *
     * @param device the peer device to connect to
     * @return true if connection is allowed, otherwise false
     */
    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
    public boolean okToConnect(BluetoothDevice device) {
        // Check if this is an incoming connection in Quiet mode.
        if (mAdapterService.isQuietModeEnabled()) {
            Log.e(TAG, "okToConnect: cannot connect to " + device + " : quiet mode enabled");
            return false;
        }
        // Check connection policy and accept or reject the connection.
        int connectionPolicy = getConnectionPolicy(device);
        int bondState = mAdapterService.getBondState(device);
        // Allow this connection only if the device is bonded. Any attempt to connect while
        // bonding would potentially lead to an unauthorized connection.
        if (bondState != BluetoothDevice.BOND_BONDED) {
            Log.w(TAG, "okToConnect: return false, bondState=" + bondState);
            return false;
        } else if (connectionPolicy != BluetoothProfile.CONNECTION_POLICY_UNKNOWN
                && connectionPolicy != BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
            // Otherwise, reject the connection if connectionPolicy is not valid.
            Log.w(TAG, "okToConnect: return false, connectionPolicy=" + connectionPolicy);
            return false;
        }
        return true;
    }

    /**
     * Get connection state of remote device
     *
     * @param sink the remote device
     * @return connection state
     */
    public int getConnectionState(BluetoothDevice sink) {
        synchronized (mStateMachines) {
            BassClientStateMachine sm = getOrCreateStateMachine(sink);
            if (sm == null) {
                log("getConnectionState returns STATE_DISC");
                return BluetoothProfile.STATE_DISCONNECTED;
            }
            return sm.getConnectionState();
        }
    }

    /**
     * Get a list of all LE Audio Broadcast Sinks with the specified connection states.
     * @param states states array representing the connection states
     * @return a list of devices that match the provided connection states
     */
    List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
        ArrayList<BluetoothDevice> devices = new ArrayList<>();
        if (states == null) {
            return devices;
        }
        final BluetoothDevice[] bondedDevices = mAdapterService.getBondedDevices();
        if (bondedDevices == null) {
            return devices;
        }
        synchronized (mStateMachines) {
            for (BluetoothDevice device : bondedDevices) {
                final ParcelUuid[] featureUuids = device.getUuids();
                if (!Utils.arrayContains(
                        featureUuids, BluetoothUuid.BASS)) {
                    continue;
                }
                int connectionState = BluetoothProfile.STATE_DISCONNECTED;
                BassClientStateMachine sm = getOrCreateStateMachine(device);
                if (sm != null) {
                    connectionState = sm.getConnectionState();
                }
                for (int state : states) {
                    if (connectionState == state) {
                        devices.add(device);
                        break;
                    }
                }
            }
            return devices;
        }
    }

    /**
     * Get a list of all LE Audio Broadcast Sinks connected with the LE Audio Broadcast Assistant.
     * @return list of connected devices
     */
    public List<BluetoothDevice> getConnectedDevices() {
        synchronized (mStateMachines) {
            List<BluetoothDevice> devices = new ArrayList<>();
            for (BassClientStateMachine sm : mStateMachines.values()) {
                if (sm.isConnected()) {
                    devices.add(sm.getDevice());
                }
            }
            log("getConnectedDevices: " + devices);
            return devices;
        }
    }

    /**
     * Set the connectionPolicy of the Broadcast Audio Scan Service profile.
     *
     * <p>The connection policy can be one of:
     * {@link BluetoothProfile#CONNECTION_POLICY_ALLOWED},
     * {@link BluetoothProfile#CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile#CONNECTION_POLICY_UNKNOWN}
     *
     * @param device paired bluetooth device
     * @param connectionPolicy is the connection policy to set to for this profile
     * @return true if connectionPolicy is set, false on error
     */
    public boolean setConnectionPolicy(BluetoothDevice device, int connectionPolicy) {
        if (DBG) {
            Log.d(TAG, "Saved connectionPolicy " + device + " = " + connectionPolicy);
        }
        boolean setSuccessfully =
                mDatabaseManager.setProfileConnectionPolicy(device,
                        BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT, connectionPolicy);
        if (setSuccessfully && connectionPolicy == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
            connect(device);
        } else if (setSuccessfully
                && connectionPolicy == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            disconnect(device);
        }
        return setSuccessfully;
    }

    /**
     * Get the connection policy of the profile.
     *
     * <p>The connection policy can be any of:
     * {@link BluetoothProfile#CONNECTION_POLICY_ALLOWED},
     * {@link BluetoothProfile#CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile#CONNECTION_POLICY_UNKNOWN}
     *
     * @param device paired bluetooth device
     * @return connection policy of the device
     */
    public int getConnectionPolicy(BluetoothDevice device) {
        return mDatabaseManager
                .getProfileConnectionPolicy(device, BluetoothProfile.LE_AUDIO_BROADCAST_ASSISTANT);
    }

    /**
     * Register callbacks that will be invoked during scan offloading.
     *
     * @param cb callbacks to be invoked
     */
    public void registerCallback(IBluetoothLeBroadcastAssistantCallback cb) {
        Log.i(TAG, "registerCallback");
        mCallbacks.register(cb);
        return;
    }

    /**
     * Unregister callbacks that are invoked during scan offloading.
     *
     * @param cb callbacks to be unregistered
     */
    public void unregisterCallback(IBluetoothLeBroadcastAssistantCallback cb) {
        Log.i(TAG, "unregisterCallback");
        mCallbacks.unregister(cb);
        return;
    }

    /**
     * Search for LE Audio Broadcast Sources on behalf of all devices connected via Broadcast Audio
     * Scan Service, filtered by filters
     *
     * @param filters ScanFilters for finding exact Broadcast Source
     */
    public void startSearchingForSources(List<ScanFilter> filters) {
        log("startSearchingForSources");
        if (mBluetoothAdapter == null) {
            Log.e(TAG, "startSearchingForSources: Adapter is NULL");
            return;
        }
        BluetoothLeScannerWrapper scanner = BassObjectsFactory.getInstance()
                .getBluetoothLeScannerWrapper(mBluetoothAdapter);
        if (scanner == null) {
            Log.e(TAG, "startLeScan: cannot get BluetoothLeScanner");
            return;
        }
        synchronized (mSearchScanCallbackLock) {
            if (mSearchScanCallback != null) {
                Log.e(TAG, "LE Scan has already started");
                mCallbacks.notifySearchStartFailed(BluetoothStatusCodes.ERROR_UNKNOWN);
                return;
            }
            mSearchScanCallback = new ScanCallback() {
                @Override
                public void onScanResult(int callbackType, ScanResult result) {
                    log("onScanResult:" + result);
                    if (callbackType != ScanSettings.CALLBACK_TYPE_ALL_MATCHES) {
                        // Should not happen
                        Log.e(TAG, "LE Scan has already started");
                        return;
                    }
                    ScanRecord scanRecord = result.getScanRecord();
                    if (scanRecord == null) {
                        Log.e(TAG, "Null scan record");
                        return;
                    }
                    Map<ParcelUuid, byte[]> listOfUuids = scanRecord.getServiceData();
                    if (listOfUuids == null) {
                        Log.e(TAG, "Service data is null");
                        return;
                    }
                    if (!listOfUuids.containsKey(
                            BassConstants.BAAS_UUID)) {
                        return;
                    }
                    log( "Broadcast Source Found:" + result.getDevice());
                    byte[] broadcastIdArray = listOfUuids.get(BassConstants.BAAS_UUID);
                    int broadcastId = (int)(((broadcastIdArray[2] & 0xff) << 16)
                            | ((broadcastIdArray[1] & 0xff) << 8)
                            | (broadcastIdArray[0] & 0xff));

                    sEventLogger.logd(DBG, TAG, "Broadcast Source Found: Broadcast ID: "
                            + broadcastId);

                    if (broadcastId != BassConstants.INVALID_BROADCAST_ID
                            && mCachedBroadcasts.get(broadcastId) == null) {
                        log("selectBroadcastSource: broadcastId " + broadcastId);
                        mCachedBroadcasts.put(broadcastId, result);
                        synchronized (mStateMachines) {
                            for (BassClientStateMachine sm : mStateMachines.values()) {
                                if (sm.isConnected()) {
                                    selectSource(sm.getDevice(), result, false);
                                }
                            }
                        }
                    }
                }

                public void onScanFailed(int errorCode) {
                    Log.e(TAG, "Scan Failure:" + errorCode);
                }
            };
            // when starting scan, clear the previously cached broadcast scan results
            mCachedBroadcasts.clear();
            // clear previous sources notify flag before scanning new result
            // this is to make sure the active sources are notified even if already synced
            if (mPeriodicAdvertisementResultMap != null) {
                clearNotifiedFlags();
            }
            ScanSettings settings = new ScanSettings.Builder().setCallbackType(
                    ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setLegacy(false)
                    .build();
            if (filters == null) {
                filters = new ArrayList<ScanFilter>();
            }
            if (!BassUtils.containUuid(filters, BassConstants.BAAS_UUID)) {
                byte[] serviceData = {0x00, 0x00 ,0x00}; // Broadcast_ID
                byte[] serviceDataMask = {0x00, 0x00, 0x00};

                filters.add(new ScanFilter.Builder()
                        .setServiceData(BassConstants.BAAS_UUID,
                                serviceData, serviceDataMask).build());
            }
            scanner.startScan(filters, settings, mSearchScanCallback);
            sEventLogger.logd(DBG, TAG, "startSearchingForSources");
            mCallbacks.notifySearchStarted(BluetoothStatusCodes.REASON_LOCAL_APP_REQUEST);
        }
    }

    /**
     * Stops an ongoing search for nearby Broadcast Sources
     */
    public void stopSearchingForSources() {
        log("stopSearchingForSources");
        if (mBluetoothAdapter == null) {
            Log.e(TAG, "stopSearchingForSources: Adapter is NULL");
            return;
        }
        BluetoothLeScannerWrapper scanner = BassObjectsFactory.getInstance()
                .getBluetoothLeScannerWrapper(mBluetoothAdapter);
        if (scanner == null) {
            Log.e(TAG, "startLeScan: cannot get BluetoothLeScanner");
            return;
        }
        synchronized (mSearchScanCallbackLock) {
            if (mSearchScanCallback == null) {
                Log.e(TAG, "Scan not started yet");
                mCallbacks.notifySearchStopFailed(BluetoothStatusCodes.ERROR_UNKNOWN);
                return;
            }
            scanner.stopScan(mSearchScanCallback);
            mSearchScanCallback = null;
            sEventLogger.logd(DBG, TAG, "stopSearchingForSources");
            mCallbacks.notifySearchStopped(BluetoothStatusCodes.REASON_LOCAL_APP_REQUEST);
        }
    }

    /**
     * Return true if a search has been started by this application
     * @return true if a search has been started by this application
     */
    public boolean isSearchInProgress() {
        synchronized (mSearchScanCallbackLock) {
            return mSearchScanCallback != null;
        }
    }

    void selectSource(BluetoothDevice sink, ScanResult result, boolean autoTrigger) {
        if (!hasRoomForBroadcastSourceAddition(sink)) {
            log("selectSource: No more slot");
            return;
        }

        List<Integer> activeSyncedSrc = getActiveSyncedSources(sink);
        if (activeSyncedSrc != null && activeSyncedSrc.size() >= MAX_ACTIVE_SYNCED_SOURCES_NUM) {
            log("selectSource : reached max allowed active source");
            int syncHandle = activeSyncedSrc.get(0);
            // removing the 1st synced source before proceeding to add new
            synchronized (mStateMachines) {
                BassClientStateMachine stateMachine = getOrCreateStateMachine(sink);
                Message message =
                        stateMachine.obtainMessage(BassClientStateMachine.REACHED_MAX_SOURCE_LIMIT);
                message.arg1 = syncHandle;
                stateMachine.sendMessage(message);
            }
        }

        synchronized (mStateMachines) {
            sEventLogger.logd(DBG, TAG, "Select Broadcast Source");

            BassClientStateMachine stateMachine = getOrCreateStateMachine(sink);
            Message message = stateMachine.obtainMessage(
                    BassClientStateMachine.SELECT_BCAST_SOURCE);
            message.obj = result;
            message.arg1 = autoTrigger ? BassConstants.AUTO : BassConstants.USER;
            stateMachine.sendMessage(message);
        }
    }

    /**
     * Add a Broadcast Source to the Broadcast Sink
     *
     * @param sink Broadcast Sink to which the Broadcast Source should be added
     * @param sourceMetadata Broadcast Source metadata to be added to the Broadcast Sink
     * @param isGroupOp set to true If Application wants to perform this operation for all
     *                  coordinated set members, False otherwise
     */
    public void addSource(BluetoothDevice sink, BluetoothLeBroadcastMetadata sourceMetadata,
            boolean isGroupOp) {
        log("addSource: device: " + sink + " sourceMetadata" + sourceMetadata
                + " isGroupOp: " + isGroupOp);

        List<BluetoothDevice> devices = getTargetDeviceList(sink, isGroupOp);
        // Don't coordinate it as a group if there's no group or there is one device only
        if (devices.size() < 2) {
            isGroupOp = false;
        }

        if (sourceMetadata == null) {
            log("addSource: Error bad parameter: sourceMetadata cannot be null");
            for (BluetoothDevice device : devices) {
                mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                        BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
            }
            return;
        }

        /* Store metadata for sink device */
        mBroadcastMetadataMap.put(sink, sourceMetadata);

        byte[] code = sourceMetadata.getBroadcastCode();
        for (BluetoothDevice device : devices) {
            BassClientStateMachine stateMachine = getOrCreateStateMachine(device);
            if (stateMachine == null) {
                log("addSource: Error bad parameter: no state machine for " + device);
                mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                        BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
                continue;
            }
            if (getConnectionState(device) != BluetoothProfile.STATE_CONNECTED) {
                log("addSource: device is not connected");
                mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                        BluetoothStatusCodes.ERROR_REMOTE_LINK_ERROR);
                continue;
            }
            if (stateMachine.hasPendingSourceOperation()) {
                throw new IllegalStateException("addSource: source operation already pending");
            }
            if (!hasRoomForBroadcastSourceAddition(device)) {
                log("addSource: device has no room");
                mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                        BluetoothStatusCodes.ERROR_REMOTE_NOT_ENOUGH_RESOURCES);
                continue;
            }
            if (!isValidBroadcastSourceAddition(device, sourceMetadata)) {
                log("addSource: not a valid broadcast source addition");
                mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                        BluetoothStatusCodes.ERROR_LE_BROADCAST_ASSISTANT_DUPLICATE_ADDITION);
                continue;
            }
            if ((code != null) && (code.length != 0)) {
                if ((code.length > 16) || (code.length < 4)) {
                    log("Invalid broadcast code length: " + code.length
                            + ", should be between 4 and 16 octets");
                    mCallbacks.notifySourceAddFailed(device, sourceMetadata,
                            BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
                    continue;
                }
            }

            if (isGroupOp) {
                enqueueSourceGroupOp(device, BassClientStateMachine.ADD_BCAST_SOURCE,
                        sourceMetadata);
            }

            sEventLogger.logd(
                    DBG,
                    TAG,
                    "Add Broadcast Source: device: "
                            + sink
                            + ", sourceMetadata: "
                            + sourceMetadata
                            + ", isGroupOp: "
                            + isGroupOp);

            Message message = stateMachine.obtainMessage(BassClientStateMachine.ADD_BCAST_SOURCE);
            message.obj = sourceMetadata;
            stateMachine.sendMessage(message);
            if (code != null && code.length != 0) {
                sEventLogger.logd(DBG, TAG, "Set Broadcast Code (Add Source context)");

                message = stateMachine.obtainMessage(BassClientStateMachine.SET_BCAST_CODE);
                message.obj = sourceMetadata;
                message.arg1 = BassClientStateMachine.ARGTYPE_METADATA;
                stateMachine.sendMessage(message);
            }
        }
    }

    /**
     * Modify the Broadcast Source information on a Broadcast Sink
     *
     * @param sink representing the Broadcast Sink to which the Broadcast
     *               Source should be updated
     * @param sourceId source ID as delivered in onSourceAdded
     * @param updatedMetadata updated Broadcast Source metadata to be updated on the Broadcast Sink
     */
    public void modifySource(BluetoothDevice sink, int sourceId,
            BluetoothLeBroadcastMetadata updatedMetadata) {
        log("modifySource: device: " + sink + " sourceId " + sourceId);

        Map<BluetoothDevice, Integer> devices = getGroupManagedDeviceSources(sink, sourceId).second;
        if (updatedMetadata == null) {
            log("modifySource: Error bad parameters: updatedMetadata cannot be null");
            for (BluetoothDevice device : devices.keySet()) {
                mCallbacks.notifySourceModifyFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
            }
            return;
        }

        /* Update metadata for sink device */
        mBroadcastMetadataMap.put(sink, updatedMetadata);

        byte[] code = updatedMetadata.getBroadcastCode();
        for (Map.Entry<BluetoothDevice, Integer> deviceSourceIdPair : devices.entrySet()) {
            BluetoothDevice device = deviceSourceIdPair.getKey();
            Integer deviceSourceId = deviceSourceIdPair.getValue();
            BassClientStateMachine stateMachine = getOrCreateStateMachine(device);
            if (updatedMetadata == null || stateMachine == null) {
                log("modifySource: Error bad parameters: sourceId = " + deviceSourceId
                        + " updatedMetadata = " + updatedMetadata);
                mCallbacks.notifySourceModifyFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
                continue;
            }
            if (deviceSourceId == BassConstants.INVALID_SOURCE_ID) {
                log("modifySource: no such sourceId for device: " + device);
                mCallbacks.notifySourceModifyFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_LE_BROADCAST_ASSISTANT_INVALID_SOURCE_ID);
                continue;
            }
            if (getConnectionState(device) != BluetoothProfile.STATE_CONNECTED) {
                log("modifySource: device is not connected");
                mCallbacks.notifySourceModifyFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_REMOTE_LINK_ERROR);
                continue;
            }
            if ((code != null) && (code.length != 0)) {
                if ((code.length > 16) || (code.length < 4)) {
                    log("Invalid broadcast code length: " + code.length
                            + ", should be between 4 and 16 octets");
                    mCallbacks.notifySourceModifyFailed(device, sourceId,
                            BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
                    continue;
                }
            }
            if (stateMachine.hasPendingSourceOperation()) {
                throw new IllegalStateException("modifySource: source operation already pending");
            }

            sEventLogger.logd(
                    DBG,
                    TAG,
                    "Modify Broadcast Source: device: "
                            + sink
                            + ", sourceId: "
                            + sourceId
                            + ", updatedMetadata: "
                            + updatedMetadata);

            Message message =
                    stateMachine.obtainMessage(BassClientStateMachine.UPDATE_BCAST_SOURCE);
            message.arg1 = deviceSourceId;
            message.arg2 = BluetoothLeBroadcastReceiveState.PA_SYNC_STATE_INVALID;
            message.obj = updatedMetadata;
            stateMachine.sendMessage(message);
            if (code != null && code.length != 0) {
                sEventLogger.logd(DBG, TAG, "Set Broadcast Code (Modify Source context)");
                message = stateMachine.obtainMessage(BassClientStateMachine.SET_BCAST_CODE);
                message.obj = updatedMetadata;
                message.arg1 = BassClientStateMachine.ARGTYPE_METADATA;
                stateMachine.sendMessage(message);
            }
        }
    }

    /**
     * Removes the Broadcast Source from a Broadcast Sink
     *
     * @param sink representing the Broadcast Sink from which a Broadcast
     *               Source should be removed
     * @param sourceId source ID as delivered in onSourceAdded
     */
    public void removeSource(BluetoothDevice sink, int sourceId) {
        log("removeSource: device = " + sink + ", sourceId " + sourceId);

        Map<BluetoothDevice, Integer> devices = getGroupManagedDeviceSources(sink, sourceId).second;
        for (Map.Entry<BluetoothDevice, Integer> deviceSourceIdPair : devices.entrySet()) {
            BluetoothDevice device = deviceSourceIdPair.getKey();
            Integer deviceSourceId = deviceSourceIdPair.getValue();
            BassClientStateMachine stateMachine = getOrCreateStateMachine(device);

            /* Removes metadata for sink device if not paused */
            if (!mPausedBroadcastSinks.contains(device)) {
                mBroadcastMetadataMap.remove(device);
            }

            if (stateMachine == null) {
                log("removeSource: Error bad parameters: device = " + device);
                mCallbacks.notifySourceRemoveFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_BAD_PARAMETERS);
                continue;
            }
            if (deviceSourceId == BassConstants.INVALID_SOURCE_ID) {
                log("removeSource: no such sourceId for device: " + device);
                mCallbacks.notifySourceRemoveFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_LE_BROADCAST_ASSISTANT_INVALID_SOURCE_ID);
                continue;
            }
            if (getConnectionState(device) != BluetoothProfile.STATE_CONNECTED) {
                log("removeSource: device is not connected");
                mCallbacks.notifySourceRemoveFailed(device, sourceId,
                        BluetoothStatusCodes.ERROR_REMOTE_LINK_ERROR);
                continue;
            }

            BluetoothLeBroadcastReceiveState recvState =
                    stateMachine.getBroadcastReceiveStateForSourceId(sourceId);
            BluetoothLeBroadcastMetadata metaData =
                    stateMachine.getCurrentBroadcastMetadata(sourceId);
            if (metaData != null && recvState != null && recvState.getPaSyncState()
                    == BluetoothLeBroadcastReceiveState.PA_SYNC_STATE_SYNCHRONIZED) {
                sEventLogger.logd(
                        DBG,
                        TAG,
                        "Remove Broadcast Source(Force lost PA sync): device: "
                                + sink
                                + ", sourceId: "
                                + sourceId);

                log("Force source to lost PA sync");
                Message message = stateMachine.obtainMessage(
                        BassClientStateMachine.UPDATE_BCAST_SOURCE);
                message.arg1 = sourceId;
                message.arg2 = BluetoothLeBroadcastReceiveState.PA_SYNC_STATE_IDLE;
                /* Pending remove set. Remove source once not synchronized to PA */
                message.obj = metaData;
                stateMachine.sendMessage(message);

                continue;
            }

            sEventLogger.logd(
                    DBG,
                    TAG,
                    "Remove Broadcast Source: device: " + sink + ", sourceId: " + sourceId);

            Message message =
                    stateMachine.obtainMessage(BassClientStateMachine.REMOVE_BCAST_SOURCE);
            message.arg1 = deviceSourceId;
            stateMachine.sendMessage(message);
        }

        for (Map.Entry<BluetoothDevice, Integer> deviceSourceIdPair : devices.entrySet()) {
            BluetoothDevice device = deviceSourceIdPair.getKey();
            Integer deviceSourceId = deviceSourceIdPair.getValue();
            enqueueSourceGroupOp(device, BassClientStateMachine.REMOVE_BCAST_SOURCE,
                    Integer.valueOf(deviceSourceId));
        }
    }

    /**
     * Get information about all Broadcast Sources
     *
     * @param sink Broadcast Sink from which to get all Broadcast Sources
     * @return the list of Broadcast Receive State {@link BluetoothLeBroadcastReceiveState}
     */
    public List<BluetoothLeBroadcastReceiveState> getAllSources(BluetoothDevice sink) {
        log("getAllSources for " + sink);
        synchronized (mStateMachines) {
            BassClientStateMachine stateMachine = getOrCreateStateMachine(sink);
            if (stateMachine == null) {
                log("stateMachine is null");
                return Collections.emptyList();
            }
            List<BluetoothLeBroadcastReceiveState> recvStates =
                    new ArrayList<BluetoothLeBroadcastReceiveState>();
            for (BluetoothLeBroadcastReceiveState rs: stateMachine.getAllSources()) {
                String emptyBluetoothDevice = "00:00:00:00:00:00";
                if (!rs.getSourceDevice().getAddress().equals(emptyBluetoothDevice)) {
                    recvStates.add(rs);
                }
            }
            return recvStates;
        }
    }

    /**
     * Get maximum number of sources that can be added to this Broadcast Sink
     *
     * @param sink Broadcast Sink device
     * @return maximum number of sources that can be added to this Broadcast Sink
     */
    int getMaximumSourceCapacity(BluetoothDevice sink) {
        log("getMaximumSourceCapacity: device = " + sink);
        BassClientStateMachine stateMachine = getOrCreateStateMachine(sink);
        if (stateMachine == null) {
            log("stateMachine is null");
            return 0;
        }
        return stateMachine.getMaximumSourceCapacity();
    }

    boolean isLocalBroadcast(BluetoothLeBroadcastMetadata metaData) {
        if (metaData == null) {
            return false;
        }

        LeAudioService leAudioService = mServiceFactory.getLeAudioService();
        if (leAudioService == null) {
            return false;
        }

        boolean wasFound = leAudioService.getAllBroadcastMetadata()
                .stream()
                .anyMatch(meta -> {
                    return meta.getSourceAdvertisingSid() == metaData.getSourceAdvertisingSid();
                });
        log("isLocalBroadcast=" + wasFound);
        return wasFound;
    }

    static void log(String msg) {
        if (BassConstants.BASS_DBG) {
            Log.d(TAG, msg);
        }
    }

    private void stopLocalSourceReceivers(int broadcastId, boolean store) {
        if (DBG) {
            Log.d(TAG, "stopLocalSourceReceivers()");
        }

        if (store && !mPausedBroadcastSinks.isEmpty()) {
            Log.w(TAG, "stopLocalSourceReceivers(), paused broadcast sinks are replaced");
            mPausedBroadcastSinks.clear();
        }

        for (BluetoothDevice device : getConnectedDevices()) {
            for (BluetoothLeBroadcastReceiveState receiveState : getAllSources(device)) {
                /* Check if local/last broadcast is the synced one */
                if (receiveState.getBroadcastId() != broadcastId) continue;

                removeSource(device, receiveState.getSourceId());

                if (store && !mPausedBroadcastSinks.contains(device)) {
                    mPausedBroadcastSinks.add(device);
                }
            }
        }
    }

    /** Request receivers to suspend broadcast sources synchronization */
    public void suspendReceiversSourceSynchronization(int broadcastId) {
        sEventLogger.logd(DBG, TAG, "Suspend receivers source synchronization: " + broadcastId);
        stopLocalSourceReceivers(broadcastId, true);
    }

    /** Request receivers to stop broadcast sources synchronization and remove them */
    public void stopReceiversSourceSynchronization(int broadcastId) {
        sEventLogger.logd(DBG, TAG, "Stop receivers source synchronization: " + broadcastId);
        stopLocalSourceReceivers(broadcastId, false);
    }

    /** Request receivers to resume broadcast source synchronization */
    public void resumeReceiversSourceSynchronization(int broadcastId) {
        sEventLogger.logd(DBG, TAG, "Resume receivers source synchronization: " + broadcastId);

        while (!mPausedBroadcastSinks.isEmpty()) {
            BluetoothDevice sink = mPausedBroadcastSinks.remove();
            BluetoothLeBroadcastMetadata metadata = mBroadcastMetadataMap.get(sink);

            addSource(sink, metadata, true);
        }
    }

    /**
     * Callback handler
     */
    static class Callbacks extends Handler {
        private static final int MSG_SEARCH_STARTED = 1;
        private static final int MSG_SEARCH_STARTED_FAILED = 2;
        private static final int MSG_SEARCH_STOPPED = 3;
        private static final int MSG_SEARCH_STOPPED_FAILED = 4;
        private static final int MSG_SOURCE_FOUND = 5;
        private static final int MSG_SOURCE_ADDED = 6;
        private static final int MSG_SOURCE_ADDED_FAILED = 7;
        private static final int MSG_SOURCE_MODIFIED = 8;
        private static final int MSG_SOURCE_MODIFIED_FAILED = 9;
        private static final int MSG_SOURCE_REMOVED = 10;
        private static final int MSG_SOURCE_REMOVED_FAILED = 11;
        private static final int MSG_RECEIVESTATE_CHANGED = 12;
        private static final int MSG_SOURCE_LOST = 13;

        private final RemoteCallbackList<IBluetoothLeBroadcastAssistantCallback>
                mCallbacks = new RemoteCallbackList<>();

        Callbacks(Looper looper) {
            super(looper);
        }

        public void register(IBluetoothLeBroadcastAssistantCallback callback) {
            mCallbacks.register(callback);
        }

        public void unregister(IBluetoothLeBroadcastAssistantCallback callback) {
            mCallbacks.unregister(callback);
        }

        private void checkForPendingGroupOpRequest(Message msg) {
            if (sService == null) {
                Log.e(TAG, "Service is null");
                return;
            }

            final int reason = msg.arg1;
            BluetoothDevice sink;

            switch (msg.what) {
                case MSG_SOURCE_ADDED:
                case MSG_SOURCE_ADDED_FAILED:
                    ObjParams param = (ObjParams) msg.obj;
                    sink = (BluetoothDevice) param.mObj1;
                    sService.checkForPendingGroupOpRequest(sink, reason,
                            BassClientStateMachine.ADD_BCAST_SOURCE, param.mObj2);
                    break;
                case MSG_SOURCE_REMOVED:
                case MSG_SOURCE_REMOVED_FAILED:
                    sink = (BluetoothDevice) msg.obj;
                    sService.checkForPendingGroupOpRequest(sink, reason,
                            BassClientStateMachine.REMOVE_BCAST_SOURCE, Integer.valueOf(msg.arg2));
                    break;
                default:
                    break;
            }
        }

        @Override
        public void handleMessage(Message msg) {
            checkForPendingGroupOpRequest(msg);
            final int n = mCallbacks.beginBroadcast();
            for (int i = 0; i < n; i++) {
                final IBluetoothLeBroadcastAssistantCallback callback =
                        mCallbacks.getBroadcastItem(i);
                try {
                    invokeCallback(callback, msg);
                } catch (RemoteException e) {
                    continue;
                }
            }
            mCallbacks.finishBroadcast();
        }

        private class ObjParams {
            Object mObj1;
            Object mObj2;
            ObjParams(Object o1, Object o2) {
                mObj1 = o1;
                mObj2 = o2;
            }
        }

        private void invokeCallback(IBluetoothLeBroadcastAssistantCallback callback,
                Message msg) throws RemoteException {
            final int reason = msg.arg1;
            final int sourceId = msg.arg2;
            ObjParams param;
            BluetoothDevice sink;

            switch (msg.what) {
                case MSG_SEARCH_STARTED:
                    callback.onSearchStarted(reason);
                    break;
                case MSG_SEARCH_STARTED_FAILED:
                    callback.onSearchStartFailed(reason);
                    break;
                case MSG_SEARCH_STOPPED:
                    callback.onSearchStopped(reason);
                    break;
                case MSG_SEARCH_STOPPED_FAILED:
                    callback.onSearchStopFailed(reason);
                    break;
                case MSG_SOURCE_FOUND:
                    callback.onSourceFound((BluetoothLeBroadcastMetadata) msg.obj);
                    break;
                case MSG_SOURCE_ADDED:
                    param = (ObjParams) msg.obj;
                    sink = (BluetoothDevice) param.mObj1;
                    callback.onSourceAdded(sink, sourceId, reason);
                    break;
                case MSG_SOURCE_ADDED_FAILED:
                    param = (ObjParams) msg.obj;
                    sink = (BluetoothDevice) param.mObj1;
                    BluetoothLeBroadcastMetadata metadata =
                            (BluetoothLeBroadcastMetadata) param.mObj2;
                    callback.onSourceAddFailed(sink, metadata, reason);
                    break;
                case MSG_SOURCE_MODIFIED:
                    callback.onSourceModified((BluetoothDevice) msg.obj, sourceId, reason);
                    break;
                case MSG_SOURCE_MODIFIED_FAILED:
                    callback.onSourceModifyFailed((BluetoothDevice) msg.obj, sourceId, reason);
                    break;
                case MSG_SOURCE_REMOVED:
                    sink = (BluetoothDevice) msg.obj;
                    callback.onSourceRemoved(sink, sourceId, reason);
                    break;
                case MSG_SOURCE_REMOVED_FAILED:
                    sink = (BluetoothDevice) msg.obj;
                    callback.onSourceRemoveFailed(sink, sourceId, reason);
                    break;
                case MSG_RECEIVESTATE_CHANGED:
                    param = (ObjParams) msg.obj;
                    sink = (BluetoothDevice) param.mObj1;
                    BluetoothLeBroadcastReceiveState state =
                            (BluetoothLeBroadcastReceiveState) param.mObj2;
                    callback.onReceiveStateChanged(sink, sourceId, state);
                    break;
                case MSG_SOURCE_LOST:
                    callback.onSourceLost(sourceId);
                    break;
                default:
                    Log.e(TAG, "Invalid msg: " + msg.what);
                    break;
            }
        }

        void notifySearchStarted(int reason) {
            sEventLogger.logd(DBG, TAG, "notifySearchStarted: " + ", reason: " + reason);
            obtainMessage(MSG_SEARCH_STARTED, reason, 0).sendToTarget();
        }

        void notifySearchStartFailed(int reason) {
            sEventLogger.loge(TAG, "notifySearchStartFailed: " + ", reason: " + reason);
            obtainMessage(MSG_SEARCH_STARTED_FAILED, reason, 0).sendToTarget();
        }

        void notifySearchStopped(int reason) {
            sEventLogger.logd(DBG, TAG, "notifySearchStopped: " + ", reason: " + reason);
            obtainMessage(MSG_SEARCH_STOPPED, reason, 0).sendToTarget();
        }

        void notifySearchStopFailed(int reason) {
            sEventLogger.loge(TAG, "notifySearchStopFailed: " + ", reason: " + reason);
            obtainMessage(MSG_SEARCH_STOPPED_FAILED, reason, 0).sendToTarget();
        }

        void notifySourceFound(BluetoothLeBroadcastMetadata source) {
            sEventLogger.logd(
                    DBG,
                    TAG,
                    "invokeCallback: MSG_SOURCE_FOUND"
                            + ", source: "
                            + source.getSourceDevice()
                            + ", broadcastId: "
                            + source.getBroadcastId()
                            + ", broadcastName: "
                            + source.getBroadcastName()
                            + ", isPublic: "
                            + source.isPublicBroadcast()
                            + ", isEncrypted: "
                            + source.isEncrypted());
            obtainMessage(MSG_SOURCE_FOUND, 0, 0, source).sendToTarget();
        }

        void notifySourceAdded(BluetoothDevice sink, BluetoothLeBroadcastReceiveState recvState,
                int reason) {
            sEventLogger.logd(
                    DBG,
                    TAG,
                    "notifySourceAdded: "
                            + ", source: "
                            + sink
                            + ", sourceId: "
                            + recvState.getSourceId()
                            + ", reason: "
                            + reason);

            ObjParams param = new ObjParams(sink, recvState);
            obtainMessage(MSG_SOURCE_ADDED, reason, recvState.getSourceId(), param).sendToTarget();
        }

        void notifySourceAddFailed(BluetoothDevice sink, BluetoothLeBroadcastMetadata source,
                int reason) {
            sEventLogger.loge(
                    TAG, "notifySourceAddFailed: " + ", source: " + sink + ", reason: " + reason);
            ObjParams param = new ObjParams(sink, source);
            obtainMessage(MSG_SOURCE_ADDED_FAILED, reason, 0, param).sendToTarget();
        }

        void notifySourceModified(BluetoothDevice sink, int sourceId, int reason) {
            sEventLogger.logd(
                    DBG,
                    TAG,
                    "notifySourceModified: "
                            + ", source: "
                            + sink
                            + ", sourceId: "
                            + sourceId
                            + ", reason: "
                            + reason);
            obtainMessage(MSG_SOURCE_MODIFIED, reason, sourceId, sink).sendToTarget();
        }

        void notifySourceModifyFailed(BluetoothDevice sink, int sourceId, int reason) {
            sEventLogger.loge(
                    TAG,
                    "notifySourceModifyFailed: " + ", source: " + sink + ", reason: " + reason);
            obtainMessage(MSG_SOURCE_MODIFIED_FAILED, reason, sourceId, sink).sendToTarget();
        }

        void notifySourceRemoved(BluetoothDevice sink, int sourceId, int reason) {
            sEventLogger.logd(
                    DBG,
                    TAG,
                    "notifySourceRemoved: "
                            + ", source: "
                            + sink
                            + ", sourceId: "
                            + sourceId
                            + ", reason: "
                            + reason);
            obtainMessage(MSG_SOURCE_REMOVED, reason, sourceId, sink).sendToTarget();
        }

        void notifySourceRemoveFailed(BluetoothDevice sink, int sourceId, int reason) {
            sEventLogger.loge(
                    TAG,
                    "notifySourceRemoveFailed: "
                            + ", source: "
                            + sink
                            + ", sourceId: "
                            + sourceId
                            + ", reason: "
                            + reason);
            obtainMessage(MSG_SOURCE_REMOVED_FAILED, reason, sourceId, sink).sendToTarget();
        }

        void notifyReceiveStateChanged(BluetoothDevice sink, int sourceId,
                BluetoothLeBroadcastReceiveState state) {
            ObjParams param = new ObjParams(sink, state);
            String subgroupState = " / SUB GROUPS: ";
            for (int i = 0; i < state.getNumSubgroups(); i++) {
                subgroupState += "IDX: " + i + ", SYNC: " + state.getBisSyncState().get(i);
            }

            sEventLogger.logd(
                    TAG,
                    "notifyReceiveStateChanged: "
                            + ", source: "
                            + sink
                            + ", state: SRC ID: "
                            + state.getSourceId()
                            + " / ADDR TYPE: "
                            + state.getSourceAddressType()
                            + " / SRC DEV: "
                            + state.getSourceDevice()
                            + " / ADV SID: "
                            + state.getSourceAdvertisingSid()
                            + " / BID: "
                            + state.getBroadcastId()
                            + " / PA STATE: "
                            + state.getPaSyncState()
                            + " / BENC STATE: "
                            + state.getBigEncryptionState()
                            + " / BAD CODE: "
                            + Arrays.toString(state.getBadCode())
                            + subgroupState);
            obtainMessage(MSG_RECEIVESTATE_CHANGED, 0, sourceId, param).sendToTarget();
        }

        void notifySourceLost(int broadcastId) {
            sEventLogger.logd(TAG, "notifySourceLost: " + ", broadcastId: " + broadcastId);
            obtainMessage(MSG_SOURCE_LOST, 0, broadcastId).sendToTarget();
        }
    }

    @Override
    public void dump(StringBuilder sb) {
        super.dump(sb);

        sb.append("Broadcast Assistant Service instance:\n");

        /* Dump first connected state machines */
        for (Map.Entry<BluetoothDevice, BassClientStateMachine> entry : mStateMachines.entrySet()) {
            BassClientStateMachine sm = entry.getValue();
            if (sm.getConnectionState() == BluetoothProfile.STATE_CONNECTED) {
                sm.dump(sb);
                sb.append("\n\n");
            }
        }

        /* Dump at least all other than connected state machines */
        for (Map.Entry<BluetoothDevice, BassClientStateMachine> entry : mStateMachines.entrySet()) {
            BassClientStateMachine sm = entry.getValue();
            if (sm.getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
                sm.dump(sb);
            }
        }

        sb.append("\n\n");
        sEventLogger.dump(sb);
        sb.append("\n");
    }

    /** Binder object: must be a static class or memory leak may occur */
    @VisibleForTesting
    static class BluetoothLeBroadcastAssistantBinder extends IBluetoothLeBroadcastAssistant.Stub
            implements IProfileServiceBinder {
        BassClientService mService;

        private BassClientService getService() {
            if (Utils.isInstrumentationTestMode()) {
                return mService;
            }
            if (!Utils.checkServiceAvailable(mService, TAG)
                    || !Utils.checkCallerIsSystemOrActiveOrManagedUser(mService, TAG)) {
                return null;
            }
            return mService;
        }

        BluetoothLeBroadcastAssistantBinder(BassClientService svc) {
            mService = svc;
        }

        @Override
        public void cleanup() {
            mService = null;
        }

        @Override
        public int getConnectionState(BluetoothDevice sink) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return BluetoothProfile.STATE_DISCONNECTED;
                }
                return service.getConnectionState(sink);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return BluetoothProfile.STATE_DISCONNECTED;
            }
        }

        @Override
        public List<BluetoothDevice> getDevicesMatchingConnectionStates(int[] states) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return Collections.emptyList();
                }
                return service.getDevicesMatchingConnectionStates(states);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return Collections.emptyList();
            }
        }

        @Override
        public List<BluetoothDevice> getConnectedDevices() {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return Collections.emptyList();
                }
                return service.getConnectedDevices();
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return Collections.emptyList();
            }
        }

        @Override
        public boolean setConnectionPolicy(BluetoothDevice device, int connectionPolicy) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return false;
                }
                mService.enforceCallingOrSelfPermission(
                        BLUETOOTH_CONNECT, "Need BLUETOOTH_CONNECT permission");
                return service.setConnectionPolicy(device, connectionPolicy);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return false;
            }
        }

        @Override
        public int getConnectionPolicy(BluetoothDevice device) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
                }
                mService.enforceCallingOrSelfPermission(
                        BLUETOOTH_CONNECT, "Need BLUETOOTH_CONNECT permission");
                return service.getConnectionPolicy(device);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return BluetoothProfile.CONNECTION_POLICY_FORBIDDEN;
            }
        }

        @Override
        public void registerCallback(IBluetoothLeBroadcastAssistantCallback cb) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.registerCallback(cb);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public void unregisterCallback(IBluetoothLeBroadcastAssistantCallback cb) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.unregisterCallback(cb);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public void startSearchingForSources(List<ScanFilter> filters) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.startSearchingForSources(filters);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public void stopSearchingForSources() {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.stopSearchingForSources();
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public boolean isSearchInProgress() {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return false;
                }
                enforceBluetoothPrivilegedPermission(service);
                return service.isSearchInProgress();
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return false;
            }
        }

        @Override
        public void addSource(
                BluetoothDevice sink, BluetoothLeBroadcastMetadata sourceMetadata,
                boolean isGroupOp) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.addSource(sink, sourceMetadata, isGroupOp);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public void modifySource(
                BluetoothDevice sink, int sourceId, BluetoothLeBroadcastMetadata updatedMetadata) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.modifySource(sink, sourceId, updatedMetadata);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public void removeSource(BluetoothDevice sink, int sourceId) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return;
                }
                enforceBluetoothPrivilegedPermission(service);
                service.removeSource(sink, sourceId);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
            }
        }

        @Override
        public List<BluetoothLeBroadcastReceiveState> getAllSources(BluetoothDevice sink) {
            try {
                BassClientService service = getService();
                if (sink == null) {
                    Log.e(TAG, "Service is null");
                    return Collections.emptyList();
                }
                enforceBluetoothPrivilegedPermission(service);
                return service.getAllSources(sink);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return Collections.emptyList();
            }
        }

        @Override
        public int getMaximumSourceCapacity(BluetoothDevice sink) {
            try {
                BassClientService service = getService();
                if (service == null) {
                    Log.e(TAG, "Service is null");
                    return 0;
                }
                enforceBluetoothPrivilegedPermission(service);
                return service.getMaximumSourceCapacity(sink);
            } catch (RuntimeException e) {
                Log.e(TAG, "Exception happened", e);
                return 0;
            }
        }
    }
}
