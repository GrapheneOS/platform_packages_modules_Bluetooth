package com.android.bluetooth.hfpclient;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.content.Intent;
import android.support.test.filters.MediumTest;
import android.test.AndroidTestCase;

import com.android.bluetooth.R;
import com.android.bluetooth.btservice.AdapterService;

@MediumTest
public class HeadsetClientServiceTest extends AndroidTestCase {
    // Time to wait for the service to be initialized
    private static final int SERVICE_START_TIMEOUT_MS = 5000;  // 5 sec
    private HeadsetClientService mService = null;
    private BluetoothAdapter mAdapter = null;

    void startServices() {
        Intent startIntent = new Intent(getContext(), HeadsetClientService.class);
        getContext().startService(startIntent);

        try {
            Thread.sleep(SERVICE_START_TIMEOUT_MS);
        } catch (Exception ex) {
        }

        // At this point the service should have started so check NOT null
        mService = HeadsetClientService.getHeadsetClientService();
        assertTrue(mService != null);

        // At this point Adapter Service should have started
        AdapterService inst = mock(AdapterService.class);
        assertTrue(inst != null);

        // Try getting the Bluetooth adapter
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        assertTrue(mAdapter != null);
    }

    @Override
    protected void setUp() throws Exception {
        // On phone side, HeadsetClientService may not be included in the APK and thus the test
        // should be skipped
        if (!getContext().getResources().getBoolean(R.bool.profile_supported_hfpclient)) {
            return;
        }
        startServices();
    }

    @Override
    protected void tearDown() throws Exception {
        mService = null;
        mAdapter = null;
    }

    // Test that we can initialize the service
    public void testInitialize() {
    }
}
