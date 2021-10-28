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

package android.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.IBleBroadcastAudioScanAssistCallback;
import android.bluetooth.le.ScanResult;

/**
 * APIs for Bluetooth Bluetooth Scan offloader service
 *
 * @hide
 */
interface IBluetoothSyncHelper {
    // Public API
    boolean connect(in BluetoothDevice device);
    boolean disconnect(in BluetoothDevice device);
    List<BluetoothDevice> getConnectedDevices();
    List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states);
    int getConnectionState(in BluetoothDevice device);
    boolean setConnectionPolicy(in BluetoothDevice device, int connectionPolicy);
    int getConnectionPolicy(in BluetoothDevice device);
    boolean startScanOffload (in BluetoothDevice device,
                              in boolean groupOp);
    boolean stopScanOffload (in BluetoothDevice device,
                             in boolean groupOp);

    void registerAppCallback(in BluetoothDevice device,
                             in IBleBroadcastAudioScanAssistCallback cb);
    void unregisterAppCallback(in BluetoothDevice device,
                               in IBleBroadcastAudioScanAssistCallback cb);

    boolean searchforLeAudioBroadcasters (in BluetoothDevice device);
    boolean stopSearchforLeAudioBroadcasters(in BluetoothDevice device);

    boolean addBroadcastSource(in BluetoothDevice device,
                               in BleBroadcastSourceInfo srcInfo,
                               in boolean groupOp
                                );
    boolean selectBroadcastSource(in BluetoothDevice device,
                                  in ScanResult scanRes,
                                  in boolean groupOp
                                  );
    boolean updateBroadcastSource(in BluetoothDevice device,
                                  in BleBroadcastSourceInfo srcInfo,
                                  in boolean groupOp
                                  );
    boolean setBroadcastCode (in BluetoothDevice device,
                              in BleBroadcastSourceInfo srcInfo,
                              in boolean groupOp
                              );
    boolean removeBroadcastSource (in BluetoothDevice device,
                                   in byte SourceId,
                                   in boolean groupOp
                                   );
    List<BleBroadcastSourceInfo> getAllBroadcastSourceInformation(
                                             in BluetoothDevice device);
}
