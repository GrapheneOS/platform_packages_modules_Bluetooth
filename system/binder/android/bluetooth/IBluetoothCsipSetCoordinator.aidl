/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

package android.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.content.AttributionSource;
import android.os.ParcelUuid;
import android.bluetooth.IBluetoothCsipSetCoordinatorLockCallback;
import java.util.List;
import java.util.Map;

/**
 * APIs for Bluetooth CSIP Set Coordinator
 *
 * @hide
 */
interface IBluetoothCsipSetCoordinator {
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
  boolean connect(in BluetoothDevice device, in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
  boolean disconnect(in BluetoothDevice device, in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  List<BluetoothDevice> getConnectedDevices(in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states, in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  int getConnectionState(in BluetoothDevice device, in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
  boolean setConnectionPolicy(in BluetoothDevice device, int connectionPolicy, in AttributionSource attributionSource);
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
  int getConnectionPolicy(in BluetoothDevice device, in AttributionSource attributionSource);

  /**
    * Get the list of group identifiers for the given context {@var uuid}.
    * @return group identifiers as <code>List<Integer></code>
    */
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  List getAllGroupIds(in ParcelUuid uuid, in AttributionSource attributionSource);

  /**
    * Get all groups that {@var device} belongs to.
    * @return group identifiers and their context uuids as <code>Map<Integer, ParcelUuid></code>
    */
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  Map getGroupUuidMapByDevice(in BluetoothDevice device, in AttributionSource attributionSource);

  /**
   * Get the number of known group members or
   * {@link android.bluetooth.IBluetoothCsipSetCoordinator.CSIS_GROUP_SIZE_UNKNOWN} if unknown.
   * @return group size
   */
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  int getDesiredGroupSize(in int group_id, in AttributionSource attributionSource);

  /**
   * Lock group identified with {@var groupId}.
   * @return unique lock identifier required for unlocking
   */
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  ParcelUuid groupLock(int groupId, in IBluetoothCsipSetCoordinatorLockCallback callback, in AttributionSource attributionSource);

  /**
   * Unlock group using {@var lockUuid} acquired through
   * {@link android.bluetooth.IBluetoothCsipSetCoordinator.groupLock}.
   */
  @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
  void groupUnlock(in ParcelUuid lockUuid, in AttributionSource attributionSource);

  const int CSIS_GROUP_ID_INVALID = -1;
  const int CSIS_GROUP_SIZE_UNKNOWN = 1;
}
