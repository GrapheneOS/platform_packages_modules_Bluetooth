/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */

package android.bluetooth;

import android.Manifest;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.RequiresPermission;
import android.annotation.SdkConstant;
import android.annotation.SystemApi;
import android.annotation.IntDef;
import android.annotation.SdkConstant.SdkConstantType;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Retention;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.IBluetoothGatt;
import android.bluetooth.IBluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothAdapter.LeScanCallback;
import android.os.Binder;
import android.os.IBinder;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import java.io.InvalidClassException;
import android.os.DeadObjectException;
import android.util.Log;
import android.content.Context;
import java.util.UUID;
import android.os.ParcelUuid;

import java.util.IdentityHashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Objects;

import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.BleBroadcastAudioScanAssistManager;

import android.os.SystemProperties;

/**
 * This class provides methods to perform Broadcast Assistance related
 * operations.
 * <p>
 * Use {@link BleBroadcastAudioScanAssistManager()} to get an
 * instance of {@link BleBroadcastAudioScanAssistManager}.
 * <p>
 * <b>Note:</b> Most of the methods here require
 * {@link android.Manifest.permission#BLUETOOTH_ADMIN} permission.
 *
 * @hide
 */
public final class BleBroadcastAudioScanAssistManager {

    private static final String TAG = "BleBroadcastAudioScanAssistManager";
    private static final boolean DBG = true;
    private static final boolean VDBG = true;

    /** @hide */
    @IntDef(prefix = "SYNC_", value = {
           SYNC_METADATA,
           SYNC_AUDIO,
           SYNC_METADATA_AUDIO
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface BroadcastAssistSyncState {}
    /**
     * Input to {@link BleBroadcastAudioScanAssistManager#addBroadcastSource} method
     * where Application wants to synchronize only to Metadata (i.e. Only Periodic advs) and not to
     *  Broadcsat audio stream (i.e. BIS )from broadcast source
     */
    public static final int SYNC_METADATA = 0;
    /**
     * Input to {@link BleBroadcastAudioScanAssistManager#addBroadcastSource} method
     * where Application wants to synchronize only to Broadcast Audio stream (i.e. BIS) and not to
       Metadata (i.e. Periodic advs )from broadcast source
     */
    public static final int SYNC_AUDIO = 1;
    /**
     * Input to {@link BleBroadcastAudioScanAssistManager#addBroadcastSource} method
     * where Application wants to synchronize to both  Broadcast Audio stream (i.e. BIS) and also to
     * Metadata (i.e. Periodic advs )from broadcast source
     */
    public static final int SYNC_METADATA_AUDIO = 2;

    private BluetoothAdapter mBluetoothAdapter;
    BleBroadcastAudioScanAssistCallback mAppCallback;
    BluetoothDevice mBluetoothDevice;
    int mSyncState = SYNC_METADATA;
    BluetoothSyncHelper mBluetoothSyncHelper = null;
    BleBroadcastSourceInfo mBroadcastAudioSourceInfo = null;
    private byte INVALID_SOURCE_ID = -1;

    /**
     * Intent used to broadcast the "Broadcast receiver State" information of a Scan delegator device.
     * Whenever there is a change in Broadcast source Information stored at Scan delegator device
     * this Itent will be delivered to Application layer
     *
     * {@link #BluetoothSyncHelper} profile need to be connected to the Scan delegator device
     * to get these notifications
     *
     * <p>This intent will have two extra:
     * <ul>
     * <li> {@link BluetoothDevice#EXTRA_DEVICE} - The remote device for which broadcast reciver
     * state information is broadcasted. It can
     * be null if no device is active. </li>
     * </ul>
     * <ul>
     * <li> {@link BleBroadcastSourceInfo#EXTRA_SOURCE_INFO} - The BleBroadcastSourceInfo Object
     * having information Broadcast receiver state </li>
     * </ul>
     * <ul>
     * <li> {@link BleBroadcastSourceInfo#EXTRA_SOURCE_INFO_INDEX} - Index of the BleBroadcastSourceInfo
     * object broadcasted </li>
     * </ul>
     * <ul>
     * <li> {@link BleBroadcastSourceInfo#EXTRA_MAX_NUM_SOURCE_INFOS} - Maximum number of source Informations
     * that this Broadcast receiver can hold </li>
     * </ul>
     *
     * <p>Requires {@link android.Manifest.permission#BLUETOOTH} permission to
     * receive.
     *
     * @hide
     */
    @SdkConstant(SdkConstantType.BROADCAST_INTENT_ACTION)
    public static final String ACTION_BROADCAST_SOURCE_INFO =
            "android.bluetooth.BroadcastAudioSAManager.action.BROADCAST_SOURCE_INFO";


    // These callbacks run on the main thread.
    private final class BassclientServiceListener
            implements BluetoothProfile.ServiceListener {

        public void onServiceConnected(int profile, BluetoothProfile proxy) {
            log(TAG, "BassService connected");
            onBluetoothSyncHelperStateChanged(true, proxy);

        }

        public void onServiceDisconnected(int profile) {
            log(TAG, "BassService disconnected");
            onBluetoothSyncHelperStateChanged(false, null);
        }
    }

    private void onBluetoothSyncHelperStateChanged(boolean on, BluetoothProfile proxy) {
        if (on) {
            mBluetoothSyncHelper = (BluetoothSyncHelper) proxy;
            mBluetoothSyncHelper.registerAppCallback(mBluetoothDevice, mAppCallback);
            this.notifyAll();
        } else {
            mBluetoothSyncHelper = null;
        }
    }

    /*package*/BleBroadcastAudioScanAssistManager(BluetoothSyncHelper scanOffloader, BluetoothDevice device,
                                                  BleBroadcastAudioScanAssistCallback callback
                                                 ) {
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        mAppCallback = callback;
        mBluetoothDevice = device;
        mBluetoothSyncHelper = scanOffloader;
    }


    /*finalize method to cleanup*/
    protected void finalize() {
        log(TAG, "finalize()");
        if (mBluetoothSyncHelper != null) {
            mBluetoothSyncHelper.unregisterAppCallback(mBluetoothDevice, mAppCallback);
        }
    }

    /**
     * Search for Le Audio Broadcasters on behalf of the Scan delegator with which this
     * {@ BleBroadcastAudioScanAssistManager} is instantiated
     *
     *  search results will be delivered to application using
     * {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastSourceFound}
     *
     * @return returns true if It is successfully initiated the Search for Audio broadcasters,
     *         false otherwise
     * @hide
     */
    public boolean searchforLeAudioBroadcasters () {
        log(TAG, "searchforLeAudioBroadcasters: ");
        if (mBluetoothSyncHelper != null) {
            return mBluetoothSyncHelper.searchforLeAudioBroadcasters(mBluetoothDevice);
        } else {
            Log.e(TAG, "searchforLeAudioBroadcasters: mBluetoothSyncHelper is null");
        }
        return false;
      }
    /**
     * Stops an ongoing Bluetooth LE Search for Audio Broadcasters.
     *
     * @return returns true if It is successfully initiated the Stopped the Search for Audio broadcasters
     *         false otherwise
     *
     *@hide
     */
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADMIN)
    public boolean stopSearchforLeAudioBroadcasters() {
        log(TAG, "stopSearchforLeAudioBroadcasters()");
        if (mBluetoothSyncHelper != null) {
            return mBluetoothSyncHelper.stopSearchforLeAudioBroadcasters(mBluetoothDevice);
        } else {
            Log.e(TAG, "stopSearchforLeAudioBroadcasters: mBluetoothSyncHelper is null");
        }
        return false;

    }

    /* Internal helper function to convert user input sync state to required internal
     * format
     */
    private int convertMetadataSyncState(int syncState) {
        if (syncState == SYNC_METADATA_AUDIO || syncState == SYNC_METADATA) {
            return BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC;
        }
        return BleBroadcastSourceInfo.BROADCAST_ASSIST_PA_SYNC_STATE_IDLE;
    }

    /* Internal helper function to convert user input sync state to required internal
     * format
     */
    private int convertAudioDataSyncState(int syncState) {
        if (syncState == SYNC_METADATA_AUDIO || syncState == SYNC_AUDIO) {
            return BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED;
        } else {
            Log.e(TAG, "searchforLeAudioBroadcasters: mBluetoothSyncHelper is null");
        }
        return BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED;
    }

    /**
     * Selects broadcast source for the Scan delegator. This internally performs Periodic
     * synchronization to the given Broadcast source device, upon acquision of Synchronization information,
     * It will be notified with avaiable Broadcast source channels that can be synchronized in the remote
     * device.
     * Application should select set of Broadcast channels that need to be synchronized and follow up
     * with a call to {@link #addBroadcastSource} operation
     *
     * Result of selction of Broadcast source  will be delivered through
     * {@link BleBroadcastAudioScanAssistCallback#OnBroadcastAudioSourceSelected}
     *
     * If this operation need to be performed over all the members of coordinated set members, isGroupOp
     * will be set to true. Select broadcast source operation will be performed on behalf of
     * all the Coordinated set devices
     *
     *
     *  @param ScanResult {@link #ScanResult} of the Broadcasting source,
     *  this is the result obtained from the {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastSourceFound}
     *  @param isGroupOp set to true If Application wants to perform this operation for the whole
     *  coordinated set members
     *
     * @return returns true if It is successfully initiated select Broadcast source operation
     *         false otherwise
     * @hide
     */
    public boolean selectBroadcastSource(ScanResult scanRes, boolean isGroupOp) {
        if (scanRes == null) {
            Log.e(TAG, "selectBroadcastSource: Invalid scan res");
            return false;
        }
        log(TAG, "selectBroadcastSource: " + scanRes);
        if (mBluetoothSyncHelper != null) {
            return mBluetoothSyncHelper.selectBroadcastSource(mBluetoothDevice, scanRes, isGroupOp);
        } else {
            Log.e(TAG, "selectBroadcastSource: mBluetoothSyncHelper is null");
        }
        return false;
    }


    private boolean isValidBroadcastSourceInfo(BleBroadcastSourceInfo srcInfo) {
        boolean ret = true;
        List<BleBroadcastSourceInfo> currentSourceInfos =
            mBluetoothSyncHelper.getAllBroadcastSourceInformation(mBluetoothDevice);
        if (currentSourceInfos == null) {
            Log.e(TAG, "no source info details for remote");
            ret = false;
        } else {
            for (int i=0; i<currentSourceInfos.size(); i++) {
                if (srcInfo.matches(currentSourceInfos.get(i))) {
                    ret = false;
                    break;
                }
            }
        }

        log(TAG, "isValidBroadcastSourceInfo returns: " + ret);
        return ret;
    }

    private boolean isValidSourceId (byte sourceId) {
        boolean retVal = false;
        List<BleBroadcastSourceInfo> currentSourceInfos =
        mBluetoothSyncHelper.getAllBroadcastSourceInformation(mBluetoothDevice);
        if (currentSourceInfos == null) {
            retVal = false;
        } else {
            for (int i=0; i<currentSourceInfos.size(); i++) {
                if (currentSourceInfos.get(i).getSourceId() == sourceId) {
                    retVal = true;
                    break;
                }
            }
        }
        log(TAG, "isValidSourceId returns: " + retVal);
        return retVal;
    }

    private void printSelectedIndicies(List<BleBroadcastSourceChannel> selectedBISIndicies) {
        if (selectedBISIndicies == null) {
            log(TAG, "printSelectedIndicies : no selected indicies");
            return;
        }
        for (int i=0; i<selectedBISIndicies.size(); i++) {
            log(TAG, selectedBISIndicies.get(i).getDescription() + ": " + selectedBISIndicies.get(i).getStatus());
        }
    }
    /**
     * Adds a broadcast source information to the Scan delegator. This internally performs Periodic
     * synchronization to the given Broadcast source device, upon acquision of Synchronization information,
     * It will be written on to the "Scan delegators" Characteristics
     *
     * Result of addition of Broadcast source to the scan delegator will be delivered through
     * {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastAudioSourceAdded}
     *
     * Successful addition Broadcast source will be indicated through Broadcast reciver state information
     * update intent through {@link #ACTION_BROADCAST_RECEIVER_STATE} intent
     *
     *
     * If this operation need to be performed over all the members of coordinated set members, isGroupOp
     * will be set to true. add broadcast source operation will be performed on behalf of
     * all the Coordinated set devices
     *
     * Same Broadcast source Information will be written on to all the members of Coordinated set and
     * PAST will be performed based on the request.
     *
     * In case of Group Operation, If there is any matching entry already present in any of coordinated set members,
     * Add Broadcast source opeation will be failed and result will notified through
     * {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastAudioSourceAdded}
     *
     *  @param audioSource {@link #BluetoothDevice} object selected as Source which need to be synchronized with
     *  @param ScanResult {@link #ScanResult} result obtained from the {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastSourceFound}
     *  @param syncState  can be one of {@link #SYNC_METADATA},
     *  {@link #SYNC_METADATA_AUDIO}
     *  @param selectedBroadcastChannels is a List of Broadcast channels that need to be synchronized with the given broadcast audio source
     *  from Avaialble Broadcast indicies.
     *  Avaiable broadcast indicies are notified application using {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastSourceSelected}
     *  BroadcastSourceChannel.mStatus set to be TRUE or FALSE based on the need of synchronization.
     *
     *
     *  null value of selectedBroadcastChannels resulting in syncing to all avaialble Broadcast channels.
     *  check {@link BleBroadcastSourceChannel} for more information
     *  @param isGroupOp set to true If Application wants to perform this operation for the whole
     *  coordinated set members, False otherwise
     *
     * @return returns true if It is successfully initiated add Broadcast source operation
     *         false otherwise
     * @hide
     */
     public boolean addBroadcastSource (BluetoothDevice audioSource,
                        @BroadcastAssistSyncState int syncState,
                        List<BleBroadcastSourceChannel> selectedBroadcastChannels,
                        boolean isGroupOp) {
        if (mBluetoothSyncHelper == null) {
            log(TAG, "addBroadcastSource: no BluetoothSyncHelper handle");
            return false;
        }

         if (syncState != SYNC_METADATA &&
              syncState != SYNC_METADATA_AUDIO) {
              log(TAG, "addBroadcastSource: Invalid syncState" + syncState);
             return false;
         }
         printSelectedIndicies(selectedBroadcastChannels);
         int metadataSyncState = -1;
         int audioSyncState = -1;
         mSyncState = syncState;
         metadataSyncState = convertMetadataSyncState (mSyncState);
         audioSyncState = convertAudioDataSyncState(mSyncState);
         if (mBroadcastAudioSourceInfo ==  null) {
             //all of these will be overriden at service layer later
            mBroadcastAudioSourceInfo = new BleBroadcastSourceInfo(
                                                            audioSource,
                                                            (byte)0xBB, /*advSid*/
                                                            BleBroadcastSourceInfo.BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC,
                                                            metadataSyncState,
                                                            audioSyncState,
                                                            selectedBroadcastChannels);
             if (mBroadcastAudioSourceInfo == null) {
                 Log.e(TAG, "addBroadcastSource: mBroadcastAudioSourceInfo instantiated failure");
                 return false;
             }
         }
         if(isValidBroadcastSourceInfo(mBroadcastAudioSourceInfo)) {
             mBluetoothSyncHelper.addBroadcastSource(mBluetoothDevice,
                                        mBroadcastAudioSourceInfo,
                                        isGroupOp
                                        );
         } else {
             log(TAG, "Similar source information already exists");
             return false;
         }
         return true;
    }
    /**
     * Updates a broadcast source information in the Scan delegator.
     * It will be written on to the Scan delegator's Characteristics
     *
     * Result of updating of Broadcast source to the scan delegator will be delivered through
     * {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastAudioSourceUpdated}
     *
     *  However Successful updating of Broadcast source information will be indicated through Broadcast reciver state information
     *  update intent through {@link #ACTION_BROADCAST_RECEIVER_STATE} intent
     *
     * If this operation need to be performed over all the members of coordinated set members, isGroupOp
     * will be set to true. Update broadcast source operation will be performed on behalf of
     * all the Coordinated set devices
     *
     * Same Broadcast source Information change will be written on to all the members of Coordinated set and
     * PAST will be performed based on the request from remote.
     *
     * In case of Group Operation, If there are no matching source Information present in any of coordinated set members,
     * Update Broadcast source opeation will be failed and result will notified through
     * {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastAudioSourceUpdated}
     *
     *  @param sourceId sourceId of the Broadcast Source information which need to be updated
     *  @param syncState  can be one of {@link #SYNC_METADATA},
     *  {@link #SYNC_AUDIO}, {@link #SYNC_METADATA_AUDIO}
     *
     *  @param selectedBroadcastChannels is a List of Broadcast channels that need to be synchronized with the given broadcast audio source
     *  from Avaialble Broadcast indicies.
     *  Avaiable broadcast indicies are notified application using {@link BleBroadcastAudioScanAssistCallback#onBleBroadcastSourceSelected}
     *  BroadcastSourceChannel.mStatus set to be TRUE or FALSE based on the need of synchronization.
     *
     *  null value of selectedBroadcastChannels resulting in syncing to all avaialble Broadcast channels.
     *  check {@link BleurceChannel} for more information
     *  @param isGroupOp set to true If Application wants to perform this operation for the whole
     *  coordinated set members, False otherwise
     *
     * @return returns true if It is successfully initiated update Broadcast source information
     *  operation
     *         false otherwise
     * @hide
     */
     public boolean updateBroadcastSource (byte sourceId, int syncState,
                                            List<BleBroadcastSourceChannel> selectedBroadcastChannels,
                                            boolean isGroupOp) {
           if (mBluetoothSyncHelper == null) {
               log(TAG, "updateBroadcastSource: no BluetoothSyncHelper handle");
               return false;
           }
           if (isValidSourceId(sourceId) == false) {
              log(TAG, "updateBroadcastSource: Invalid source Id");
              return false;
           }
           int audioSyncState = -1;
           int metadataSyncState = -1;
           log(TAG, "updateBroadcastSource: sourceId" + sourceId + ", syncState:" + syncState);

           mSyncState = syncState;
           metadataSyncState = convertMetadataSyncState (mSyncState);
           audioSyncState = convertAudioDataSyncState(mSyncState);

           printSelectedIndicies(selectedBroadcastChannels);

           log(TAG, "updateBroadcastSource: audioSyncState:" + audioSyncState);
           log(TAG, "updateBroadcastSource: metadataSyncState:" + metadataSyncState);

           BleBroadcastSourceInfo sourceInfo = new BleBroadcastSourceInfo(sourceId);
           if (sourceInfo != null) {
              sourceInfo.setMetadataSyncState(metadataSyncState);
              sourceInfo.setAudioSyncState(audioSyncState);
              sourceInfo.setSourceId(sourceId);
              sourceInfo.setBroadcastChannelsSyncStatus(selectedBroadcastChannels);
           } else {
              Log.e(TAG, "updateBroadcastSource: sourceInfo not created");
              return false;
           }
           return mBluetoothSyncHelper.updateBroadcastSource(mBluetoothDevice,
                                                  sourceInfo,
                                                  isGroupOp);
    }
    /**
      * Sets the Broadcast pin code to the Scan delegator so that It can decrypt
      * the synchronized audio at the reciver side
      *
      * It will be written on to the Scan delegator's Characteristics.
      * Result of Setting  of Broadcast PIN code to the scan delegator will be delivered through
      * {@link BleBroadcastAudioScanAssistCallback#onBroadcastPinUpdated}
      *
      * If this operation need to be performed over all the members of coordinated set members, isGroupOp
      * will be set to true. set Broadcast PIN operation will be performed on all the Coordinated set devices
      *
      * Same Broadcast PIN code will be written on to all the members of Coordinated set and
      * on the request from remote.
      *
      * In case of Group Operation, If there are no matching source Information(BD address, adv instance)
      * present in any of coordinated set members,
      * Set Broadcast PIN opeation will be failed and result will notified through
      * {@link BleBroadcastAudioScanAssistCallback#onBroadcastPinUpdated}
      *
      *
      * However, Successful updating of Broadcast PIN code will be indicated through Broadcast reciver state information
      * update intent through {@link #ACTION_BROADCAST_RECEIVER_STATE} intent.
      *
      *  @param sourceId sourceId of the Broadcast Source information which need to be updated
      *  @param broadcastCode is the String of maximum 16 characters in length
      *  @param isGroupOp set to true If Application wants to perform this operation for the whole
      *  coordinated set members, False otherwise
      *
      * @return returns true if It is successfully initiated set Broadcast code operation
      *         false otherwise
      * @hide
      */
    public boolean setBroadcastCode (byte sourceId, String broadcastCode, boolean isGroupOp) {
           if (mBluetoothSyncHelper == null) {
               log(TAG, "setBroadcastCode: no BluetoothSyncHelper handle");
               return false;
           }
           if (isValidSourceId(sourceId) == false) {
              log(TAG, "setBroadcastCode: Invalid source Id");
              return false;
           }

           log(TAG, "setBroadcastCode: " + "sourceId:"
                            + sourceId + "BroadcastCode:" + broadcastCode);
           BleBroadcastSourceInfo sourceInfo = new BleBroadcastSourceInfo(sourceId);
           if (sourceInfo != null) {
                sourceInfo.setSourceId(sourceId);
                sourceInfo.setBroadcastCode(broadcastCode);
           } else {
               Log.e(TAG, "setBroadcastCode: sourceInfo not created");
               return false;
           }
           return mBluetoothSyncHelper.setBroadcastCode(mBluetoothDevice,
                                                   sourceInfo,
                                                   isGroupOp);
    }
     /**
     * Removes the Broadcast Source Information from the Scan delegator
     * It will be written on to the "Scan delegators" Characteristics
     *
     * Result of removal of Broadcast source to the scan delegator will be delivered through
     * {@link BleBroadcastAudioScanAssistCallback#OnBroadcastAudioSourRemoved}
     *
     * If this operation need to be performed over all the members of coordinated set members, isGroupOp
     * will be set to true. remove broadcast operation will be performed on all the Coordinated set devices
     *
     * Remove Broadcast will be performed on to all the members of Coordinated set
     *
     * In case of Group Operation, If there are no matching source Information(BD address, adv instance)
     * present in any of coordinated set members.
     *
     * Set Broadcast PIN opeation will be failed and result will notified through
     * {@link BleBroadcastAudioScanAssistCallback#onBroadcastPinUpdated}
     * Successful removal of Brocast source information will be indicated through
     * Broadcast receiver state Information through
     * {@link #ACTION_BROADCAST_RECEIVER_STATE} intent
     *
     * @param sourceId sourceId of the Broadcast Source information which need to be updated
     *  @param isGroupOp set to true If Application wants to perform this operation for the whole
     *  coordinated set members, False otherwise
     *
     * @return returns true if It is successfully initiated remove broadcast source operation
     *         false otherwise
      * @hide
     */
    public boolean removeBroadcastSource (byte sourceId, boolean isGroupOp) {
           if (mBluetoothSyncHelper == null) {
               log(TAG, "removeBroadcastSource: no BluetoothSyncHelper handle");
               return false;
           }
           if (isValidSourceId(sourceId) == false) {
              log(TAG, "removeBroadcastSource: Invalid source Id");
              return false;
           }
           log(TAG, "removeBroadcastSource: sourceId" + sourceId);

           return mBluetoothSyncHelper.removeBroadcastSource(mBluetoothDevice,
                                                        sourceId,
                                                        isGroupOp);
    }
     /**
     * Get all the Broadcast Source Information stored in remote Scan delegators
     *
     * @return returns the List of Broadcast Source Information {@link #BleBroadcastSourceInfo} stored in
     * remote and its corresponding state or null in case if there are nothing
     *
     * @hide
     */
    public List<BleBroadcastSourceInfo> getAllBroadcastSourceInformation () {
            if (mBluetoothSyncHelper == null) {
                log(TAG, "GetNumberOfAcceptableBroadcastSources: no BluetoothSyncHelper handle");
                return null;
            }
            return mBluetoothSyncHelper.getAllBroadcastSourceInformation(mBluetoothDevice);
    }

    private static void log(String TAG, String msg) {
        BleBroadcastSourceInfo.BASS_Debug(TAG, msg);
    }
}
