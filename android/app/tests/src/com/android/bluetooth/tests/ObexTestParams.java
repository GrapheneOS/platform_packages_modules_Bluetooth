package com.android.bluetooth.tests;

public class ObexTestParams {

    public int packageSize;
    public int throttle;
    public long bytesToSend;

    public ObexTestParams(int packageSize, int throttle, long bytesToSend) {
        this.packageSize = packageSize;
        this.throttle = throttle;
        this.bytesToSend = bytesToSend;
    }
}
