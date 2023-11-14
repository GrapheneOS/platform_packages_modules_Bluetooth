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

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;

import android.content.ComponentName;
import android.os.Binder;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.os.test.TestLooper;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;

/** Test cases for {@link BluetoothProfileConnector}. */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class BluetoothProfileConnectorTest {
    static class FakeBluetoothManager extends IBluetoothManager.Default {
        private IBluetoothStateChangeCallback mStateChangeCallback;
        private IBluetoothProfileServiceConnection mServiceConnection;
        private final Handler mHandler;

        private FakeBluetoothManager(Looper looper) {
            mHandler = new Handler(looper);
        }

        Looper getLooper() {
            return mHandler.getLooper();
        }

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
                int profile, IBluetoothProfileServiceConnection proxy) {
            mServiceConnection = proxy;
            return true;
        }

        @Override
        public void unbindBluetoothProfileService(
                int profile, IBluetoothProfileServiceConnection proxy) {
            if (proxy != mServiceConnection) throw new IllegalStateException();

            mHandler.post(
                    () -> {
                        try {
                            proxy.onServiceDisconnected(new ComponentName("pkg", "cls"));
                        } catch (RemoteException e) {
                            throw new RuntimeException(e);
                        }
                    });

            mServiceConnection = null;
        }
    }

    private BluetoothProfileConnector createBluetoothProfileConnector(
            BluetoothProfile profile, FakeBluetoothManager bluetoothManager) {
        return new BluetoothProfileConnector(
                bluetoothManager.getLooper(), profile, BluetoothProfile.HEADSET, bluetoothManager);
    }

    @Test
    public void bind_registerServiceConnection() throws RemoteException {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(null, bluetoothManager);
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNotNull();
        verifyZeroInteractions(listener);
    }

    @Test
    public void unbind_unregisterServiceConnection() throws RemoteException {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfile profile = mock(BluetoothProfile.class);
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(profile, bluetoothManager);
        ComponentName componentName = new ComponentName("pkg", "cls");
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mServiceConnection.onServiceConnected(componentName, new Binder());
        looper.dispatchAll();
        bluetoothManager.mServiceConnection.onServiceDisconnected(componentName);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        InOrder order = inOrder(listener, profile);
        order.verify(profile).onServiceConnected(any());
        order.verify(listener).onServiceConnected(anyInt(), any());
        order.verify(profile).onServiceDisconnected();
        order.verify(listener).onServiceDisconnected(anyInt());
        verifyNoMoreInteractions(listener);
    }

    @Test
    public void upThenDown_unregisterServiceConnection() throws RemoteException {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfile profile = mock(BluetoothProfile.class);
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(profile, bluetoothManager);
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        verifyZeroInteractions(listener);
    }

    @Test
    public void disconnectAfterConnect_unregisterCallbacks() {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(null, bluetoothManager);
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        connector.disconnect();
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
        InOrder order = inOrder(listener);
        // TODO(b/309635805): This should not be here
        order.verify(listener).onServiceDisconnected(anyInt());
        verifyNoMoreInteractions(listener);
    }

    @Test
    public void disconnectAfterBind_unregisterCallbacks() throws RemoteException {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfile profile = mock(BluetoothProfile.class);
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(profile, bluetoothManager);
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        looper.dispatchAll();
        connector.disconnect();
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
        InOrder order = inOrder(listener, profile);
        // TODO(b/309635805): This should not be here
        order.verify(listener).onServiceDisconnected(anyInt());
        order.verify(profile).onServiceDisconnected();
        verifyNoMoreInteractions(listener);
    }

    @Test
    public void disconnectAfterUnbind_unregisterCallbacks() throws RemoteException {
        TestLooper looper = new TestLooper();
        FakeBluetoothManager bluetoothManager = new FakeBluetoothManager(looper.getLooper());
        BluetoothProfile profile = mock(BluetoothProfile.class);
        BluetoothProfileConnector connector =
                createBluetoothProfileConnector(profile, bluetoothManager);
        ComponentName componentName = new ComponentName("pkg", "cls");
        BluetoothProfile.ServiceListener listener = mock(BluetoothProfile.ServiceListener.class);

        connector.connect("test.package", listener);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(true);
        bluetoothManager.mServiceConnection.onServiceConnected(componentName, new Binder());
        looper.dispatchAll();
        bluetoothManager.mServiceConnection.onServiceDisconnected(componentName);
        bluetoothManager.mStateChangeCallback.onBluetoothStateChange(false);
        looper.dispatchAll();
        connector.disconnect();
        looper.dispatchAll();

        assertThat(bluetoothManager.mServiceConnection).isNull();
        assertThat(bluetoothManager.mStateChangeCallback).isNull();
        InOrder order = inOrder(listener, profile);
        order.verify(profile).onServiceConnected(any());
        order.verify(listener).onServiceConnected(anyInt(), any());
        order.verify(profile).onServiceDisconnected();
        // TODO(b/309635805): Should be only one
        order.verify(listener, times(2)).onServiceDisconnected(anyInt());
        verifyNoMoreInteractions(listener);
    }
}
