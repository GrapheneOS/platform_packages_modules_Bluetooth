# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import sys
import time

from mobly import test_runner, base_test, asserts
from grpc import RpcError

from avatar.controllers import pandora_device

import google.protobuf.descriptor_pool

# Reset protobuf descriptor_pool as we are reimporting
# a module with the same package
google.protobuf.descriptor_pool.Default().__init__()

from pandora_experimental.host_grpc import Host


class ExampleTest(base_test.BaseTestClass):

    def setup_class(self):
        self.pandora_devices = self.register_controller(pandora_device)
        self.dut = self.pandora_devices[0]
        self.ref = self.pandora_devices[1]

    def setup_test(self):
        Host(self.dut.channel).HardReset()
        # TODO: wait for server
        time.sleep(3)

    def test_classic_connect(self):
        dut_address = self.dut.address
        self.dut.log.info(f'Address: {dut_address}')
        response = self.ref.host.Connect(address=dut_address)
        assert response.WhichOneof("result") == "connection"


if __name__ == '__main__':
    # MoblyBinaryHostTest pass test_runner arguments after a "--"
    # to make it work with rewrite argv to skip the "--"
    index = sys.argv.index('--')
    sys.argv = sys.argv[:1] + sys.argv[index + 1:]
    logging.basicConfig(level=logging.DEBUG)
    test_runner.main()
