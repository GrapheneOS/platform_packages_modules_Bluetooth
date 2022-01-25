/*
 * Copyright (C) 2021 The Android Open Source Project
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

import android.annotation.NonNull;
import android.annotation.SystemApi;
import android.annotation.SystemApi.Client;
import android.app.SystemServiceRegistry;
import android.content.Context;
import android.os.BluetoothServiceManager;

/**
 * Class for performing registration for Bluetooth service.
 *
 * @hide
 */
@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
public class BluetoothFrameworkInitializer {
  private BluetoothFrameworkInitializer() {}

  private static volatile BluetoothServiceManager sBluetoothServiceManager;

  /**
   * Sets an instance of {@link BluetoothServiceManager} that allows
   * the bluetooth mainline module to register/obtain bluetooth binder services. This is called
   * by the platform during the system initialization.
   *
   * @param bluetoothServiceManager instance of {@link BluetoothServiceManager} that allows
   * the bluetooth mainline module to register/obtain bluetoothd binder services.
   */
  public static void setBluetoothServiceManager(
      @NonNull BluetoothServiceManager bluetoothServiceManager) {
    if (sBluetoothServiceManager != null) {
      throw new IllegalStateException("setBluetoothServiceManager called twice!");
    }

    if (bluetoothServiceManager == null) {
      throw new NullPointerException("bluetoothServiceManager is null");
    }

    sBluetoothServiceManager = bluetoothServiceManager;
  }

  /** @hide */
  public static BluetoothServiceManager getBluetoothServiceManager() {
    return sBluetoothServiceManager;
  }

  /**
   * Called by {@link SystemServiceRegistry}'s static initializer and registers BT service
   * to {@link Context}, so that {@link Context#getSystemService} can return them.
   *
   * @throws IllegalStateException if this is called from anywhere besides
   * {@link SystemServiceRegistry}
   */
  public static void registerServiceWrappers() {
    SystemServiceRegistry.registerContextAwareService(Context.BLUETOOTH_SERVICE,
        BluetoothManager.class, context -> new BluetoothManager(context));
  }
}
