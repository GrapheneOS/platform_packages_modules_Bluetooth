/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


package com.android.bluetooth.apm;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothAdapter;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.hfp.HeadsetSystemInterface;
import com.android.bluetooth.apm.ApmConst;
import com.android.bluetooth.cc.CCService;
import android.media.AudioManager;
import com.android.bluetooth.apm.ActiveDeviceManagerService;
import android.content.Context;
import android.content.Intent;
import android.os.UserHandle;
import android.net.Uri;
import android.telephony.PhoneNumberUtils;
import android.telecom.PhoneAccount;
import android.os.SystemProperties;

import android.util.Log;


public class CallControl {

    private static CallControl mCallControl;
    private static final String TAG = "CallControl";
    private static Context mContext;
    private static ActiveDeviceManagerService mActiveDeviceManager;
    private static boolean isCCEnabled = true;
    private CallControl(Context context) {
        Log.d(TAG, "Initialization");
        mContext = context;
    }

    public static void init(Context context) {
        if(mCallControl == null) {
            mCallControl = new CallControl(context);
         CallControlIntf.init(mCallControl);
        }
        isCCEnabled = SystemProperties.getBoolean("persist.vendor.service.bt.cc", true);
        Log.d(TAG, "isCCEnabled" + isCCEnabled);
    }

    public static CallControl get() {
        return mCallControl;
    }

    public void phoneStateChanged(Integer numActive, Integer numHeld, Integer callState, String number,
            Integer type, String name, Boolean isVirtualCall) {
       Log.d(TAG, "phoneStateChanged");
       if(isCCEnabled == true) {
         CCService.getCCService().phoneStateChanged(numActive, numHeld,callState,number,
                                    type, name, isVirtualCall);
       }
    }

    public void setVirtualCallActive(boolean state) {
       if(isCCEnabled == true) {
          CCService.getCCService().setVirtualCallActive(state);
       }
    }

   public void clccResponse(Integer index, Integer direction, Integer status, Integer mode, Boolean mpty,
                String number, Integer type) {
      Log.d(TAG, "clccResponse");
      if (isCCEnabled == true) {
        CCService.getCCService().clccResponse(index, direction, status, mode, mpty, number, type);
      }
    }

    public void updateBearerTechnology(Integer tech) {
       Log.d(TAG, "updateBearerTechnology");
       if (isCCEnabled == true) {
         CCService.getCCService().updateBearerProviderTechnology(tech);
       }
    }

    public void updateSignalStatus(Integer signal) {
       Log.d(TAG, "updateSignalStatus");
       if (isCCEnabled == true) {
         CCService.getCCService().updateSignalStrength(signal);
       }
    }

    public void updateBearerName(String name) {
       Log.d(TAG, "updateBearerProviderName");
       if (isCCEnabled == true) {
         CCService.getCCService().updateBearerProviderName(name);
       }
    }

    public void updateOriginateResult(BluetoothDevice device, Integer event, Integer res) {
       Log.d(TAG, "updateOriginateResult");
       if (isCCEnabled == true) {
         CCService.getCCService().updateOriginateResult(device, event, res);
       }
    }
    public static void listenForPhoneState (int events) {
        Log.d(TAG, "listenForPhoneState");
        BluetoothDevice dummyDevice = BluetoothAdapter.getDefaultAdapter().getRemoteDevice("CC:CC:CC:CC:CC:CC");
        HeadsetService.getHeadsetService().getSystemInterfaceObj().getHeadsetPhoneState().listenForPhoneState(dummyDevice, events);
    }

    public static void answerCall (BluetoothDevice device) {
        Log.d(TAG, "answerCall");
        HeadsetService.getHeadsetService().getSystemInterfaceObj().answerCall(device);
    }

    public static void hangupCall (BluetoothDevice device) {
        Log.d(TAG, "hangupCall");
        HeadsetService.getHeadsetService().getSystemInterfaceObj().hangupCall(device);
    }

    public static void terminateCall (BluetoothDevice device, int index) {
        Log.d(TAG, "terminateCall");
        HeadsetService.getHeadsetService().getSystemInterfaceObj().terminateCall(device, index);
    }

    public static boolean processChld (BluetoothDevice device, int chld) {
        Log.d(TAG, "processChld");
        return HeadsetService.getHeadsetService().getSystemInterfaceObj().processChld(chld);
    }

    public static boolean holdCall (BluetoothDevice device, int index) {
        Log.d(TAG, "holdCall");
        return HeadsetService.getHeadsetService().getSystemInterfaceObj().holdCall(index);
    }

    public static boolean listCurrentCalls () {
        Log.d(TAG, "listCurrentCalls");
        return HeadsetService.getHeadsetService().getSystemInterfaceObj().listCurrentCalls();
    }

   public static boolean dialOutgoingCall(BluetoothDevice fromDevice, String dialNumber) {
        Log.i(TAG, "dialOutgoingCall: from " + fromDevice);
        HeadsetService service = HeadsetService.getHeadsetService();
        if (service != null) {
            service.dialOutgoingCallInternal(fromDevice, dialNumber);
        }
        return true;
    }

    public static void dial (BluetoothDevice device, String dialNumber) {
        dialOutgoingCall(device, dialNumber);
    }

}
