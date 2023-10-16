/*
 * Copyright (C) 2023 The Android Open Source Project
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

import android.util.Log;

import com.google.protobuf.Empty;

import io.grpc.ManagedChannel;
import io.grpc.okhttp.OkHttpChannelBuilder;

import org.junit.rules.ExternalResource;

import java.util.concurrent.TimeUnit;

import pandora.DckGrpc;
import pandora.HostGrpc;

public final class PandoraDevice extends ExternalResource {
    private static final String TAG = PandoraDevice.class.getSimpleName();

    private final String mAddress;
    private final int mPort;

    private ManagedChannel mChannel;

    public PandoraDevice(String address, int port) {
        mAddress = address;
        mPort = port;
    }

    public PandoraDevice() {
        this("localhost", 7999);
    }

    @Override
    protected void before() {
        Log.i(TAG, "factoryReset");
        // FactoryReset is killing the server and restarting all channels created before the server
        // restarted that cannot be reused
        ManagedChannel channel =
                OkHttpChannelBuilder.forAddress(mAddress, mPort).usePlaintext().build();

        HostGrpc.HostBlockingStub stub = HostGrpc.newBlockingStub(channel);
        stub.factoryReset(Empty.getDefaultInstance());

        try {
            // terminate the channel
            channel.shutdown().awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        mChannel = OkHttpChannelBuilder.forAddress(mAddress, mPort).usePlaintext().build();
        stub = HostGrpc.newBlockingStub(mChannel);

        stub.withWaitForReady().readLocalAddress(Empty.getDefaultInstance());
    }

    @Override
    protected void after() {
        Log.i(TAG, "shutdown");
        try {
            // terminate the channel
            mChannel.shutdown().awaitTermination(1, TimeUnit.SECONDS);
            mChannel = null;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /** Get Pandora Host service */
    public HostGrpc.HostStub host() {
        return HostGrpc.newStub(mChannel);
    }

    /** Get Pandora Host service */
    public HostGrpc.HostBlockingStub hostBlocking() {
        return HostGrpc.newBlockingStub(mChannel);
    }

    /** Get Pandora Dck service */
    public DckGrpc.DckStub dck() {
        return DckGrpc.newStub(mChannel);
    }

    /** Get Pandora Dck blocking service */
    public DckGrpc.DckBlockingStub dckBlocking() {
        return DckGrpc.newBlockingStub(mChannel);
    }
}
