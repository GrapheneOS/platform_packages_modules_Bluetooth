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

package android.bluetooth

import android.cts.statsdatom.lib.ConfigUtils
import android.cts.statsdatom.lib.DeviceUtils
import android.cts.statsdatom.lib.ReportUtils
import com.android.os.AtomsProto
import com.android.os.StatsLog
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(DeviceJUnit4ClassRunner::class)
class MetricsTest : BaseHostJUnit4Test() {

    companion object {
        private const val TAG = "BluetoothMetricsTests"
        private const val TEST_APP_PKG_NAME = "android.bluetooth"
        private const val TEST_APP_CLASS_NAME = ".BluetoothMetricsHelperTest"
    }

    @Before
    fun setUp() {
        ConfigUtils.removeConfig(getDevice())
        ReportUtils.clearReports(getDevice())
    }

    @Test
    fun aclMetricTest() {
        val data = uploadAtomConfigAndTriggerTest("incomingClassicConnectionTest")
        assertThat(data.size).isAtLeast(2)
        val atom1 = data.get(0).getAtom().getBluetoothAclConnectionStateChanged()
        assertThat(atom1.getState()).isEqualTo(ConnectionStateEnum.CONNECTION_STATE_CONNECTED)
        assertThat(atom1.getTransport()).isEqualTo(TransportTypeEnum.TRANSPORT_TYPE_BREDR)
        val atom2 = data.get(1).getAtom().getBluetoothAclConnectionStateChanged()
        assertThat(atom2.getState()).isEqualTo(ConnectionStateEnum.CONNECTION_STATE_DISCONNECTED)
        assertThat(atom2.getTransport()).isEqualTo(TransportTypeEnum.TRANSPORT_TYPE_BREDR)
        assertThat(atom2.getMetricId()).isEqualTo(atom1.getMetricId())
    }

    private fun uploadAtomConfigAndTriggerTest(testName: String): List<StatsLog.EventMetricData> {
        val device = getDevice()
        ConfigUtils.uploadConfigForPushedAtoms(
            device,
            TEST_APP_PKG_NAME,
            intArrayOf(AtomsProto.Atom.BLUETOOTH_ACL_CONNECTION_STATE_CHANGED_FIELD_NUMBER)
        )

        DeviceUtils.runDeviceTests(device, TEST_APP_PKG_NAME, TEST_APP_CLASS_NAME, testName)

        return ReportUtils.getEventMetricDataList(device)
    }
}
