/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */
package com.android.bluetooth.bc;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import java.util.UUID;
import java.util.Collection;
import android.os.UserHandle;

import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import java.nio.charset.StandardCharsets;

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
import java.util.NoSuchElementException;

import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.BluetoothLeScanner;
import java.util.UUID;
import android.os.Handler;
import android.os.ParcelUuid;
import android.os.SystemProperties;
import android.os.RemoteException;

import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BleBroadcastSourceChannel;
//import android.bluetooth.BluetoothBroadcast;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import com.android.bluetooth.btservice.ServiceFactory;
///*_BMS
import com.android.bluetooth.broadcast.BroadcastService;
//_BMS*/
import android.bluetooth.BluetoothCodecConfig;
/*_PACS
import com.android.bluetooth.pacsclient.PacsClientService;
_PACS*/
import android.bluetooth.IBleBroadcastAudioScanAssistCallback;

/**
 * Bass Utility functions
 */

final class BassUtils {
        private static final String TAG = "BassUtils";
        /*LE Scan related members*/
        private boolean mBroadcastersAround = false;
        private BluetoothAdapter mBluetoothAdapter = null;
        private BluetoothLeScanner mLeScanner = null;
        private BCService mBCService = null;

        ///*_BMS
        private BroadcastService mBAService = null;
        //_BMS*/
        public static final String BAAS_UUID = "00001852-0000-1000-8000-00805F9B34FB";
        private boolean mIsLocalBMSNotified = false;
        private ServiceFactory mFactory = new ServiceFactory();
        //Using ArrayList as KEY to hashmap. May be not risk
        //in this case as It is used to track the callback to cancel Scanning later
        private final Map<ArrayList<IBleBroadcastAudioScanAssistCallback>, ScanCallback> mLeAudioSourceScanCallbacks;
        private final Map<BluetoothDevice, ScanCallback> mBassAutoAssist;

        private static final int AA_START_SCAN = 1;
        private static final int AA_SCAN_SUCCESS = 2;
        private static final int AA_SCAN_FAILURE = 3;
        private static final int AA_SCAN_TIMEOUT = 4;
        //timeout for internal scan
        private static final int AA_SCAN_TIMEOUT_MS = 1000;

        /**
         * Stanadard Codec param types
         */
        static final  int LOCATION = 3;
        //sample rate
        static final int SAMPLE_RATE = 1;
        //frame duration
        static final int FRAME_DURATION = 2;
        //Octets per frame
        static final int OCTETS_PER_FRAME = 8;
        /*_PACS
        private PacsClientService mPacsClientService = PacsClientService.getPacsClientService();
        _PACS*/
        BassUtils (BCService service) {
            mBCService = service;
            mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
            mLeScanner = mBluetoothAdapter.getBluetoothLeScanner();
            mLeAudioSourceScanCallbacks = new HashMap<ArrayList<IBleBroadcastAudioScanAssistCallback>, ScanCallback>();
            mBassAutoAssist = new HashMap<BluetoothDevice, ScanCallback>();
            ///*_BMS
            mBAService = BroadcastService.getBroadcastService();
            //_BMS*/
        }

        private ScanCallback mPaSyncScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                log( "onScanResult:" + result);
            }
        };

        void cleanUp () {

              if (mLeAudioSourceScanCallbacks != null) {
                  mLeAudioSourceScanCallbacks.clear();
              }

              if (mBassAutoAssist != null) {
                  mBassAutoAssist.clear();
              }
        }

        boolean leScanControl(boolean on) {
            log("leScanControl:" + on);
            mLeScanner = mBluetoothAdapter.getBluetoothLeScanner();
            if (mLeScanner == null) {
                Log.e(TAG, "LeScan handle not available");
                return false;
            }

            if (on) {
                mLeScanner.startScan(mPaSyncScanCallback);
            } else {
                mLeScanner.stopScan(mPaSyncScanCallback);
            }

            return true;
         }

        /* private helper to check if the Local BLE Broadcast happening Or not */
         public boolean isLocalLEAudioBroadcasting() {
             boolean ret = false;
             /*String localLeABroadcast = SystemProperties.get("persist.vendor.btstack.isLocalLeAB");
             if (!localLeABroadcast.isEmpty() && "true".equals(localLeABroadcast)) {
                 ret = true;
             }
             log("property isLocalLEAudioBroadcasting returning " + ret);*/
             ///*_Broadcast
             if (mBAService == null) {
                 mBAService = BroadcastService.getBroadcastService();
             }
             if (mBAService != null) {
                 ret = mBAService.isBroadcastActive();
                 //ret = mBAService.isBroadcastStreaming();
                log("local broadcast streaming:" + ret);
             } else {
                log("BroadcastService is Null");
             }
             //_Broadcast*/
             log("isLocalLEAudioBroadcasting returning " + ret);
             return ret;
         }

        Handler mAutoAssistScanHandler = new Handler() {
            public void handleMessage(Message msg) {
                super.handleMessage(msg);
                switch (msg.what) {
                    case AA_START_SCAN:
                        BluetoothDevice dev = (BluetoothDevice) msg.obj;
                        Message m = obtainMessage(AA_SCAN_TIMEOUT);
                        m.obj = dev;
                        sendMessageDelayed(m, AA_SCAN_TIMEOUT_MS);
                        searchforLeAudioBroadcasters(dev, null);
                        break;
                    case AA_SCAN_SUCCESS:
                        //Able to find to desired desired Source Device
                        ScanResult scanRes = (ScanResult) msg.obj;
                        dev = scanRes.getDevice();
                        stopSearchforLeAudioBroadcasters(dev,null);
                        mBCService.selectBroadcastSource(dev, scanRes, false, true);
                        break;
                    case AA_SCAN_FAILURE:
                        //Not able to find the given source
                        //ignore
                        break;
                    case AA_SCAN_TIMEOUT:
                        dev = (BluetoothDevice)msg.obj;
                        stopSearchforLeAudioBroadcasters(dev, null);
                        break;
                }
            }
        };
        private void notifyLocalBroadcastSourceFound(ArrayList<IBleBroadcastAudioScanAssistCallback> cbs) {
            BluetoothDevice localDev =
                BluetoothAdapter.getDefaultAdapter().getRemoteDevice(mBluetoothAdapter.getAddress());
            String localName = BluetoothAdapter.getDefaultAdapter().getName();
            ScanRecord record = null;
            if (localName != null) {
                byte name_len = (byte)localName.length();
                byte[] bd_name = localName.getBytes(StandardCharsets.US_ASCII);
                byte[] name_key = new byte[] {++name_len, 0x09 }; //0x09 TYPE:Name
                byte[] scan_r = new byte[name_key.length + bd_name.length];
                System.arraycopy(name_key, 0, scan_r, 0, name_key.length);
                System.arraycopy(bd_name, 0, scan_r, name_key.length, bd_name.length);
                record = ScanRecord.parseFromBytes(scan_r);
                log ("Local name populated in fake Scan res:" + record.getDeviceName());
            }
            ScanResult scanRes = new ScanResult(localDev,
                1, 1, 1,2, 0, 0, 0, record, 0);
            if (cbs != null) {
                for (IBleBroadcastAudioScanAssistCallback cb : cbs) {
                    try {
                          cb.onBleBroadcastSourceFound(scanRes);
                    } catch (RemoteException e)  {
                          Log.e(TAG, "Exception while calling onBleBroadcastSourceFound");
                    }
                }
            }
        }
        public boolean searchforLeAudioBroadcasters (BluetoothDevice srcDevice,
                                       ArrayList<IBleBroadcastAudioScanAssistCallback> cbs
                                       ) {
           log( "searchforLeAudioBroadcasters: ");
           BluetoothLeScanner scanner = mBluetoothAdapter.getBluetoothLeScanner();
           mIsLocalBMSNotified = false;
           if (scanner == null) {
                Log.e(TAG, "startLeScan: cannot get BluetoothLeScanner");
                return false;
           }
           synchronized (mLeAudioSourceScanCallbacks) {
                if (mLeAudioSourceScanCallbacks.containsKey(cbs)) {
                    Log.e(TAG, "LE Scan has already started");
                    return false;
                }
                ScanCallback scanCallback = new ScanCallback() {
                   @Override
                    public void onScanResult(int callbackType, ScanResult result) {
                        log( "onScanResult:" + result);
                        if (callbackType != ScanSettings.CALLBACK_TYPE_ALL_MATCHES) {
                            // Should not happen.
                            Log.e(TAG, "LE Scan has already started");
                            return;
                        }
                        ScanRecord scanRecord = result.getScanRecord();
                        //int pInterval = result.getPeriodicAdvertisingInterval();
                        if (scanRecord != null) {
                            Map<ParcelUuid, byte[]> listOfUuids = scanRecord.getServiceData();
                            if (listOfUuids != null) {
                                //ParcelUuid bmsUuid = new ParcelUuid(BroadcastService.BAAS_UUID);
                                //boolean isBroadcastSource = listOfUuids.containsKey(bmsUuid);
                                boolean isBroadcastSource = listOfUuids.containsKey(ParcelUuid.fromString(BAAS_UUID));
                                log( "isBroadcastSource:" + isBroadcastSource);
                                if (isBroadcastSource) {
                                    log( "Broadcast Source Found:" + result.getDevice());
                                    if (cbs != null) {
                                        for (IBleBroadcastAudioScanAssistCallback cb : cbs) {
                                           try {
                                               cb.onBleBroadcastSourceFound(result);
                                           } catch (RemoteException e)  {
                                               Log.e(TAG, "Exception while calling onBleBroadcastSourceFound");
                                           }
                                        }
                                    } else {
                                        if (srcDevice.equals(result.getDevice())) {
                                            log("matching src Device found");
                                            Message msg = mAutoAssistScanHandler.obtainMessage(AA_SCAN_SUCCESS);
                                            msg.obj = result;
                                            mAutoAssistScanHandler.sendMessage(msg);
                                        }
                                    }
                                } else {
                                    log( "Broadcast Source UUID not preset, ignore");
                                }
                            } else {
                                Log.e(TAG, "Ignore no UUID");
                                return;
                            }
                        } else {
                            Log.e(TAG, "Scan record is null, ignoring this Scan res");
                            return;
                        }
                        //Before starting LE Scan, Call local APIs to find out if the local device
                        //is Broadcaster, then generate callback for Local device
                        if (!mIsLocalBMSNotified && isLocalLEAudioBroadcasting()) {
                        //Create a DUMMY scan result for colocated case
                            notifyLocalBroadcastSourceFound(cbs);
                            mIsLocalBMSNotified = true;
                        }
                       }

                     public void onScanFailed(int errorCode) {
                         Log.e(TAG, "Scan Failure:" + errorCode);
                     }
                };
         if (mBluetoothAdapter != null) {
             if (cbs != null) {
                 mLeAudioSourceScanCallbacks.put(cbs, scanCallback);
             } else {
                 //internal auto assist trigger remember it
                 //based on device
                 mBassAutoAssist.put(srcDevice, scanCallback);
             }

             ScanSettings settings = new ScanSettings.Builder().setCallbackType(
                 ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                 .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                 .setLegacy(false)
                 .build();
             ScanFilter.Builder filterBuilder = new ScanFilter.Builder();
                 ScanFilter srcFilter = filterBuilder.setServiceUuid(
                     ParcelUuid.fromString(BAAS_UUID)).build();
                     List<ScanFilter> filters = new ArrayList<ScanFilter>();
                 if (!mIsLocalBMSNotified && isLocalLEAudioBroadcasting()) {
                    //Create a DUMMY scan result for colocated case
                    notifyLocalBroadcastSourceFound(cbs);
                    mIsLocalBMSNotified = true;
                 }
                 scanner.startScan(filters, settings, scanCallback);
                 return true;
             } else {
                 Log.e(TAG, "searchforLeAudioBroadcasters: Adapter is NULL");
                 return false;
             }
         }
    }
    public boolean stopSearchforLeAudioBroadcasters(BluetoothDevice srcDev,
                                                     ArrayList<IBleBroadcastAudioScanAssistCallback> cbs) {
        log( "stopSearchforLeAudioBroadcasters()");
        BluetoothLeScanner scanner = mBluetoothAdapter.getBluetoothLeScanner();
        if (scanner == null) {
            return false;
        }
        ScanCallback scanCallback = null;
        if (cbs != null) {
            scanCallback = mLeAudioSourceScanCallbacks.remove(cbs);
        } else {
            scanCallback = mLeAudioSourceScanCallbacks.remove(srcDev);
        }

        if (scanCallback == null) {
            log( "scan not started yet");
            return false;
        }
        scanner.stopScan(scanCallback);
        return true;
    }

    private int convertConfigurationSRToCapabilitySR(byte sampleRate) {
        int ret = BluetoothCodecConfig.SAMPLE_RATE_NONE;
        switch (sampleRate) {
            case 1:
                ret = BluetoothCodecConfig.SAMPLE_RATE_NONE; break;
            case 2:
                ret = BluetoothCodecConfig.SAMPLE_RATE_NONE; break;
            case 3:
                ret = BluetoothCodecConfig.SAMPLE_RATE_NONE; break;
            case 4:
                //ret = BluetoothCodecConfig.SAMPLE_RATE_32000; break;
            case 5:
                ret = BluetoothCodecConfig.SAMPLE_RATE_44100; break;
            case 6:
                ret = BluetoothCodecConfig.SAMPLE_RATE_48000; break;
            }
        log("convertConfigurationSRToCapabilitySR returns:" + ret);
        return ret;
    }

    private boolean isSampleRateSupported(BluetoothDevice device, byte sampleRate) {
        boolean ret = false;
        /*_PACS
        BluetoothCodecConfig[]  supportedConfigs = mPacsClientService.getSinkPacs(device);
        int actualSampleRate = convertConfigurationSRToCapabilitySR(sampleRate);

        if (actualSampleRate == BluetoothCodecConfig.SAMPLE_RATE_NONE) {
            return false;
        }

        for (int i=0; i<supportedConfigs.length; i++) {
            if (actualSampleRate == supportedConfigs[i].getSampleRate()) {
                ret = true;
            }
        }

        log("isSampleRateSupported returns:" + ret);
        _PACS*/
        return ret;
    }
    public List<BleBroadcastSourceChannel> selectBises(BluetoothDevice device,
                                                 BleBroadcastSourceInfo srcInfo, BaseData base)  {
        boolean noPref = SystemProperties.getBoolean("persist.vendor.service.bt.bass_no_pref", false);
        if (noPref) {
            log("No pref selected");
            return null;
        } else {
        /*_PACS
        mPacsClientService = PacsClientService.getPacsClientService();
        List<BleBroadcastSourceChannel> bChannels = new ArrayList<BleBroadcastSourceChannel>();
        //if (mPacsClientService == null) {
            log("selectBises: Pacs Service is null, pick BISes apropriately");
            //Pacs not available
            if (base != null) {
                bChannels = base.pickAllBroadcastChannels();
            } else {
                bChannels = null;
            }
            return bChannels;
        //}
        if (mPacsClientService != null) {
            int supportedLocations = 1/*mPacsClientService.getSinkLocations(device);
            ArrayList<BaseData.BaseInformation> broadcastedCodecInfo = base.getBISIndexInfos();
            if (broadcastedCodecInfo != null) {
                for (int i=0; i<broadcastedCodecInfo.size(); i++) {
                    HashMap<Integer, String> consolidatedUniqueCodecInfo = broadcastedCodecInfo.get(i).consolidatedUniqueCodecInfo;
                    byte index = broadcastedCodecInfo.get(i).index;
                    if (consolidatedUniqueCodecInfo != null) {


                        byte[] bisChannelLocation = consolidatedUniqueCodecInfo.get(LOCATION).getBytes();
                        byte[] locationValue = new byte[4];
                        System.arraycopy(bisChannelLocation, 2, locationValue, 0, 4);
                        log ("locationValue>>> ");
                        printByteArray(locationValue);
                        ByteBuffer wrapped = ByteBuffer.wrap(locationValue);
                        int bisLocation = wrapped.getInt();
                        log("bisLocation: " + bisLocation);
                        int reversebisLoc = Integer.reverseBytes(bisLocation);
                        log("reversebisLoc: " + reversebisLoc);

                        byte[] bisSampleRate = consolidatedUniqueCodecInfo.get(SAMPLE_RATE).getBytes();
                        byte bisSR = bisSampleRate[2];

                        //using bitwise operand as Location can be bitmask
                        if (isSampleRateSupported(device, bisSR) && (reversebisLoc & supportedLocations) == supportedLocations) {
                             log("matching location: bisLocation " + reversebisLoc + ":: " + supportedLocations);
                             BleBroadcastSourceChannel bc = new BleBroadcastSourceChannel(index, String.valueOf(index), true);
                             bChannels.add(bc);
                        }
                     }
                }
            }
        }

        if (bChannels != null && bChannels.size() == 0) {
            log("selectBises: no channel are selected");
            bChannels = null;

        }
        return bChannels;
        _PACS*/
      }
      return null;
    }

    public void triggerAutoAssist (BleBroadcastSourceInfo srcInfo) {
        //searchforLeAudioBroadcasters (srcInfo.getSourceDevice(), null, AUTO_ASSIST_SCAN_TIMEOUT);
        BluetoothDevice dev = srcInfo.getSourceDevice();

        Message msg = mAutoAssistScanHandler.obtainMessage(AA_START_SCAN);
        msg.obj = srcInfo.getSourceDevice();
        mAutoAssistScanHandler.sendMessage(msg);
    }

    static void log(String msg) {
        if (BassClientStateMachine.BASS_DBG) {
           Log.d(TAG, msg);
        }
    }

    static void printByteArray(byte[] array) {
        log("Entire byte Array as string: " + Arrays.toString(array));
        log("printitng byte by bte");
        for (int i=0; i<array.length; i++) {
             log( "array[" + i + "] :" + Byte.toUnsignedInt(array[i]));
        }
    }
}
