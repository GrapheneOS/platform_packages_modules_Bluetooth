package android.bluetooth;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;

import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.okhttp.OkHttpChannelBuilder;
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
        ManagedChannel channel = OkHttpChannelBuilder
                .forAddress("localhost", 7999)
                .usePlaintext()
                .build();

        HostGrpc.HostBlockingStub stub = HostGrpc.newBlockingStub(channel);
        stub.factoryReset(Empty.getDefaultInstance());

        // terminate the channel
        channel.shutdown().awaitTermination(1, TimeUnit.SECONDS);

        // return new channel for future use
        return OkHttpChannelBuilder.forAddress("localhost", 7999).usePlaintext().build();
    }
}
