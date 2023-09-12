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

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;

import io.grpc.ManagedChannel;
import io.grpc.okhttp.OkHttpChannelBuilder;

import java.util.concurrent.TimeUnit;

import pandora.HostGrpc;

public final class Utils {
    public static String addressStringFromByteString(ByteString bs) {
        StringBuilder refAddrBuilder = new StringBuilder();
        for (int i = 0; i < bs.size(); i++) {
            if (i != 0) {
                refAddrBuilder.append(':');
            }
            refAddrBuilder.append(String.format("%02X", bs.byteAt(i)));
        }
        return refAddrBuilder.toString();
    }

    public static ManagedChannel factoryResetAndCreateNewChannel() throws InterruptedException {
        // FactoryReset is killing the server and restarting all channels created before the server
        // restarted that cannot be reused
        ManagedChannel channel =
                OkHttpChannelBuilder.forAddress("localhost", 7999).usePlaintext().build();

        HostGrpc.HostBlockingStub stub = HostGrpc.newBlockingStub(channel);
        stub.factoryReset(Empty.getDefaultInstance());

        // terminate the channel
        channel.shutdown().awaitTermination(1, TimeUnit.SECONDS);

        // return new channel for future use
        return OkHttpChannelBuilder.forAddress("localhost", 7999).usePlaintext().build();
    }
}
