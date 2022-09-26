/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.bluetooth.map;

import static com.google.common.truth.Truth.assertThat;

import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;

import androidx.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class BluetoothMapAccountItemTest {
    private static final String TEST_NAME = "test_name";
    private static final String TEST_PACKAGE_NAME = "test.package.name";
    private static final String TEST_ID = "1111";
    private static final String TEST_PROVIDER_AUTHORITY = "test.project.provider";
    private static final Drawable TEST_DRAWABLE = new ColorDrawable();
    private static final BluetoothMapUtils.TYPE TEST_TYPE = BluetoothMapUtils.TYPE.EMAIL;
    private static final String TEST_UCI = "uci";
    private static final String TEST_UCI_PREFIX = "uci_prefix";

    @Test
    public void create_withAllParameters() {
        BluetoothMapAccountItem accountItem = BluetoothMapAccountItem.create(TEST_ID, TEST_NAME,
                TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, TEST_UCI, TEST_UCI_PREFIX);
        assertThat(accountItem.getAccountId()).isEqualTo(Long.parseLong(TEST_ID));
        assertThat(accountItem.getName()).isEqualTo(TEST_NAME);
        assertThat(accountItem.getPackageName()).isEqualTo(TEST_PACKAGE_NAME);
        assertThat(accountItem.getProviderAuthority()).isEqualTo(TEST_PROVIDER_AUTHORITY);
        assertThat(accountItem.getType()).isEqualTo(TEST_TYPE);
        assertThat(accountItem.getUci()).isEqualTo(TEST_UCI);
        assertThat(accountItem.getUciPrefix()).isEqualTo(TEST_UCI_PREFIX);
    }

    @Test
    public void create_withoutIdAndUciData() {
        BluetoothMapAccountItem accountItem = BluetoothMapAccountItem.create(/*id=*/null, TEST_NAME,
                TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE, TEST_TYPE);
        assertThat(accountItem.getAccountId()).isEqualTo(-1);
        assertThat(accountItem.getName()).isEqualTo(TEST_NAME);
        assertThat(accountItem.getPackageName()).isEqualTo(TEST_PACKAGE_NAME);
        assertThat(accountItem.getProviderAuthority()).isEqualTo(TEST_PROVIDER_AUTHORITY);
        assertThat(accountItem.getType()).isEqualTo(TEST_TYPE);
        assertThat(accountItem.getUci()).isNull();
        assertThat(accountItem.getUciPrefix()).isNull();
    }

    @Test
    public void getUciFull() {
        BluetoothMapAccountItem accountItem = BluetoothMapAccountItem.create(TEST_ID, TEST_NAME,
                TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, TEST_UCI, TEST_UCI_PREFIX);

        BluetoothMapAccountItem accountItemWithoutUciPrefix = BluetoothMapAccountItem.create(
                TEST_ID, TEST_NAME, TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, TEST_UCI, null);

        BluetoothMapAccountItem accountItemWithoutUci = BluetoothMapAccountItem.create(TEST_ID,
                TEST_NAME, TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, null, null);

        assertThat(accountItem.getUciFull()).isEqualTo("uci_prefix:uci");
        assertThat(accountItemWithoutUciPrefix.getUciFull()).isNull();
        assertThat(accountItemWithoutUci.getUciFull()).isNull();
    }

    @Test
    public void compareIfTwoObjectsAreEqual_returnFalse_whenTypesAreDifferent() {
        BluetoothMapAccountItem accountItem = BluetoothMapAccountItem.create(TEST_ID, TEST_NAME,
                TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, TEST_UCI, TEST_UCI_PREFIX);

        BluetoothMapAccountItem accountItemWithDifferentType = BluetoothMapAccountItem.create(
                TEST_ID, TEST_NAME, TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                BluetoothMapUtils.TYPE.MMS);

        assertThat(accountItem.equals(accountItemWithDifferentType)).isFalse();
        assertThat(accountItem.compareTo(accountItemWithDifferentType)).isEqualTo(-1);
    }

    @Test
    public void compareIfTwoObjectsAreEqual_returnTrue_evenWhenUcisAreDifferent() {
        BluetoothMapAccountItem accountItem = BluetoothMapAccountItem.create(TEST_ID, TEST_NAME,
                TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE,
                TEST_TYPE, TEST_UCI, TEST_UCI_PREFIX);

        BluetoothMapAccountItem accountItemWithoutUciData = BluetoothMapAccountItem.create(TEST_ID,
                TEST_NAME, TEST_PACKAGE_NAME, TEST_PROVIDER_AUTHORITY, TEST_DRAWABLE, TEST_TYPE);

        assertThat(accountItem.equals(accountItemWithoutUciData)).isTrue();
        assertThat(accountItem.compareTo(accountItemWithoutUciData)).isEqualTo(0);
    }
}