/*
 * Copyright 2023 The Android Open Source Project
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

import static com.google.common.truth.Truth.assertThat;

import android.content.ComponentName;
import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

/** Test cases for {@link BluetoothProfileConnector}. */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class BluetoothProfileConnectorTest {
    static class FakeBluetoothManager extends IBluetoothManager.Default {
        private IBluetoothStateChangeCallback mStateChangeCallback;
        private IBluetoothProfileServiceConnection mServiceConnection;

        @Override
        public void registerStateChangeCallback(IBluetoothStateChangeCallback callback) {
            mStateChangeCallback = callback;
        }

        @Override
        public void unregisterStateChangeCallback(IBluetoothStateChangeCallback callback)
                throws RemoteException {
            if (callback != mStateChangeCallback) throw new IllegalStateException();

            mStateChangeCallback.onBluetoothStateChange(false);

            mStateChangeCallback = null;
        }

        @Override
        public boolean bindBluetoothProfileService(
                int profile, String serviceName, IBluetoothProfileServiceConnection proxy) {
            mServiceConnection = proxy;
            return true;
        }

        @Override
        public void unbindBluetoothProfileService(
                int profile, IBluetoothProfileServiceConnection proxy) {
            if (proxy != mServiceConnection) throw new IllegalStateException();

            mServiceConnection = null;
        }
    }

    private BluetoothProfileConnector createBluetoothProfileConnector(
            IBluetoothManager bluetoothManager) {
        return new BluetoothProfileConnector(
                null, BluetoothProfile.HEADSET, "Headset", "HeadsetService", bluetoothManager) {
            public IBinder getServiceInterface(IBinder service) {
                return service;
            }
        };
    }

    @Test
    public void bind_registerServiceConnection() throws RemoteException {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);

        assertThat(bluetoothManager.mServiceConnection).isNotNull();
    }

    @Test
    public void unbind_unregisterServiceConnection() throws RemoteException {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        ComponentName componentName = new ComponentName("pkg", "cls");
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mServiceConnection.onServiceConnected(componentName, new Binder());
        bluetoothManager.mServiceConnection.onServiceDisconnected(componentName);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);

        assertThat(bluetoothManager.mServiceConnection).isNull();
    }

    @Test
    public void upThenDown_unregisterServiceConnection() throws RemoteException {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);

        // TODO(b/302092694): Should be isNull
        assertThat(bluetoothManager.mServiceConnection).isNotNull();
    }

    @Test
    public void disconnectAfterConnect_unregisterCallbacks() {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        connector.disconnect();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
    }

    @Test
    public void disconnectAfterBind_unregisterCallbacks() throws RemoteException {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        connector.disconnect();

        // TODO(b/302092694): Should be isNull
        assertThat(bluetoothManager.mServiceConnection).isNotNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
    }

    @Test
    public void disconnectAfterUnbind_unregisterCallbacks() throws RemoteException {
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager();
        BluetoothProfileConnector connector = createBluetoothProfileConnector(bluetoothManager);
        ComponentName componentName = new ComponentName("pkg", "cls");
        BluetoothProfile.ServiceListener listener = null;

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mServiceConnection.onServiceConnected(componentName, new Binder());
        bluetoothManager.mServiceConnection.onServiceDisconnected(componentName);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);
        connector.disconnect();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
    }
}
