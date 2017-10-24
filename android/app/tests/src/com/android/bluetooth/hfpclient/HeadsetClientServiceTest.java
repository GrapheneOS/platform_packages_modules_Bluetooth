package com.android.bluetooth.hfpclient;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.rule.ServiceTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import com.android.bluetooth.R;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.TimeoutException;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class HeadsetClientServiceTest {
    private static final String TAG = "HeadsetClientServiceTest";
    private HeadsetClientService mService = null;
    private BluetoothAdapter mAdapter = null;
    private Context mTargetContext;

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        // On phone side, HeadsetClientService may not be included in the APK and thus the test
        // should be skipped
        if (!mTargetContext.getResources().getBoolean(R.bool.profile_supported_hfpclient)) {
            return;
        }
        startServices();
    }

    @After
    public void tearDown() throws Exception {
        mService = null;
        mAdapter = null;
    }

    /**
     * Start HeadsetClientService in case that device is configured for Headset AG only
     */
    private void startServices() {
        Intent startIntent = new Intent(mTargetContext, HeadsetClientService.class);
        startIntent.putExtra(AdapterService.EXTRA_ACTION,
                AdapterService.ACTION_SERVICE_STATE_CHANGED);
        startIntent.putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_ON);
        try {
            mServiceRule.startService(startIntent);
        } catch (TimeoutException e) {
            Log.e(TAG, "startServices, timeout " + e);
            Assert.fail();
        }

        // At this point the service should have started so check NOT null
        mService = HeadsetClientService.getHeadsetClientService();
        Assert.assertNotNull(mService);

        // At this point Adapter Service should have started
        AdapterService inst = mock(AdapterService.class);
        Assert.assertNotNull(inst);

        // Try getting the Bluetooth adapter
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        Assert.assertNotNull(mAdapter);
    }

    @Test
    public void testInitialize() {
        // Test that we can initialize the service
        Log.i(TAG, "testInitialize, test passed");
    }
}
