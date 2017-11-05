package com.android.bluetooth.map;

import static org.mockito.Mockito.*;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.Looper;
import android.os.RemoteException;
import android.os.UserManager;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;
import android.telephony.TelephonyManager;
import android.test.mock.MockContentProvider;
import android.test.mock.MockContentResolver;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class BluetoothMapContentObserverTest {
    class ExceptionTestProvider extends MockContentProvider {
        public ExceptionTestProvider(Context context) {
            super(context);
        }

        @Override
        public Cursor query(Uri uri, String[] b, String s, String[] c, String d) {
            throw new SQLiteException();
        }
    }

    @Test
    public void testInitMsgList() {
        if (Looper.myLooper() == null) {
            Looper.prepare();
        }

        Context mockContext = mock(Context.class);
        MockContentResolver mockResolver = new MockContentResolver();
        ExceptionTestProvider mockProvider = new ExceptionTestProvider(mockContext);
        mockResolver.addProvider("sms", mockProvider);

        TelephonyManager mockTelephony = mock(TelephonyManager.class);
        UserManager mockUserService = mock(UserManager.class);
        BluetoothMapMasInstance mockMas = mock(BluetoothMapMasInstance.class);

        // Functions that get called when BluetoothMapContentObserver is created
        when(mockUserService.isUserUnlocked()).thenReturn(true);
        when(mockContext.getContentResolver()).thenReturn(mockResolver);
        when(mockContext.getSystemService(Context.TELEPHONY_SERVICE)).thenReturn(mockTelephony);
        when(mockContext.getSystemService(Context.USER_SERVICE)).thenReturn(mockUserService);

        BluetoothMapContentObserver observer;
        try {
            // The constructor of BluetoothMapContentObserver calls initMsgList
            observer = new BluetoothMapContentObserver(mockContext, null, mockMas, null, true);
        } catch (RemoteException e) {
            Assert.fail("Failed to created BluetoothMapContentObserver object");
        } catch (SQLiteException e) {
            Assert.fail("Threw SQLiteException instead of Assert.failing cleanly");
        }
    }
}
