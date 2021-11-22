package com.android.bluetooth.gatt;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.content.Context;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.btservice.AdapterService;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Test cases for {@link GattService}.
 */
@SmallTest
@RunWith(AndroidJUnit4.class)
public class GattServiceTest {
    private static final int TIMES_UP_AND_DOWN = 3;
    private static final int TIMEOUT_MS = 5_000;
    private Context mTargetContext;
    private GattService mService;

    @Rule public final ServiceTestRule mServiceRule = new ServiceTestRule();

    private BluetoothAdapter mAdapter;
    @Mock private AdapterService mAdapterService;
    @Mock private GattObjectsFactory mFactory;
    @Mock private GattNativeInterface mNativeInterface;
    private BluetoothDevice mCurrentDevice;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when GattService is not enabled", GattService.isEnabled());
        MockitoAnnotations.initMocks(this);
        TestUtils.setAdapterService(mAdapterService);
        doReturn(true).when(mAdapterService).isStartedProfile(anyString());

        GattObjectsFactory.setInstanceForTesting(mFactory);
        doReturn(mNativeInterface).when(mFactory).getNativeInterface();

        mAdapter = BluetoothAdapter.getDefaultAdapter();

        TestUtils.startService(mServiceRule, GattService.class);
        mService = GattService.getGattService();
        Assert.assertNotNull(mService);
    }

    @After
    public void tearDown() throws Exception {
        if (!GattService.isEnabled()) {
            return;
        }
        doReturn(false).when(mAdapterService).isStartedProfile(anyString());
        TestUtils.stopService(mServiceRule, GattService.class);
        mService = GattService.getGattService();
        Assert.assertNull(mService);
        TestUtils.clearAdapterService(mAdapterService);
        GattObjectsFactory.setInstanceForTesting(null);
    }

    @Test
    public void testInitialize() {
        Assert.assertEquals(mService, GattService.getGattService());
        verify(mNativeInterface).init(eq(mService));
    }

    @Test
    public void testServiceUpAndDown() throws Exception {
        for (int i = 0; i < TIMES_UP_AND_DOWN; i++) {
            GattService gattService = GattService.getGattService();
            doReturn(false).when(mAdapterService).isStartedProfile(anyString());
            TestUtils.stopService(mServiceRule, GattService.class);
            mService = GattService.getGattService();
            Assert.assertNull(mService);
            gattService.cleanup();
            TestUtils.clearAdapterService(mAdapterService);
            reset(mAdapterService);
            TestUtils.setAdapterService(mAdapterService);
            doReturn(true).when(mAdapterService).isStartedProfile(anyString());
            TestUtils.startService(mServiceRule, GattService.class);
            mService = GattService.getGattService();
            Assert.assertNotNull(mService);
        }
    }

    @Test
    public void testParseBatchTimestamp() {
        long timestampNanos = mService.parseTimestampNanos(new byte[]{
                -54, 7
        });
        Assert.assertEquals(99700000000L, timestampNanos);
    }
}
