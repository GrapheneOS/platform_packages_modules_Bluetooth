#!/usr/bin/env python3
#
#   Copyright 2019 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import importlib
import traceback

from functools import wraps
from grpc import RpcError

from acts import asserts, signals
from acts.context import get_current_context
from acts.base_test import BaseTestClass

from cert.gd_device import MOBLY_CONTROLLER_CONFIG_NAME as CONTROLLER_CONFIG_NAME
from cert.gd_base_test_lib import setup_rootcanal
from cert.gd_base_test_lib import teardown_rootcanal
from cert.gd_base_test_lib import dump_crashes_core
from cert.gd_device_lib import generate_coverage_report_for_host

from facade import rootservice_pb2 as facade_rootservice


class GdBaseTestClass(BaseTestClass):

    SUBPROCESS_WAIT_TIMEOUT_SECONDS = 10

    def setup_class(self, dut_module, cert_module):
        self.dut_module = dut_module
        self.cert_module = cert_module
        self.dut_coverage_info = None
        self.cert_coverage_info = None

    def teardown_class(self):
        # assume each test runs the same binary for dut and cert
        # generate coverage report after running all tests in a class
        if self.dut_coverage_info:
            generate_coverage_report_for_host(self.dut_coverage_info)
            self.dut_coverage_info = None
        if self.cert_coverage_info:
            generate_coverage_report_for_host(self.cert_coverage_info)
            self.cert_coverage_info = None

    def setup_test(self):
        self.log_path_base = get_current_context().get_full_output_path()
        self.verbose_mode = bool(self.user_params.get('verbose_mode', False))
        for config in self.controller_configs[CONTROLLER_CONFIG_NAME]:
            config['verbose_mode'] = self.verbose_mode

        try:
            controller_properties_file = self.controller_properties_file
        except AttributeError:
            controller_properties_file = ''

        self.info = setup_rootcanal(
            dut_module=self.dut_module,
            cert_module=self.cert_module,
            verbose_mode=self.verbose_mode,
            log_path_base=self.log_path_base,
            controller_configs=self.controller_configs,
            controller_properties_file=controller_properties_file)
        self.rootcanal_running = self.info['rootcanal_running']
        self.rootcanal_logpath = self.info['rootcanal_logpath']
        self.rootcanal_process = self.info['rootcanal_process']
        self.rootcanal_logger = self.info['rootcanal_logger']

        if 'rootcanal' in self.controller_configs:
            asserts.assert_true(self.info['rootcanal_exist'],
                                "Root canal does not exist at %s" % self.info['rootcanal'])
            asserts.assert_true(self.info['make_rootcanal_ports_available'],
                                "Failed to make root canal ports available")

            self.log.debug("Running %s" % " ".join(self.info['rootcanal_cmd']))
            asserts.assert_true(
                self.info['is_rootcanal_process_started'],
                msg="Cannot start root-canal at " + str(self.info['rootcanal']))
            asserts.assert_true(self.info['is_subprocess_alive'], msg="root-canal stopped immediately after running")

            self.controller_configs = self.info['controller_configs']

        # Parse and construct GD device objects
        self.register_controller(importlib.import_module('cert.gd_device'), builtin=True)
        self.dut = self.gd_devices[1]
        self.cert = self.gd_devices[0]
        if self.dut.host_only_device:
            new_dut_coverage_info = self.dut.get_coverage_info()
            if self.dut_coverage_info:
                asserts.assert_true(
                    self.dut_coverage_info == new_dut_coverage_info,
                    msg="DUT coverage info must be the same for each test run, old: {}, new: {}".format(
                        self.dut_coverage_info, new_dut_coverage_info))
            self.dut_coverage_info = new_dut_coverage_info
        if self.cert.host_only_device:
            new_cert_coverage_info = self.cert.get_coverage_info()
            if self.cert_coverage_info:
                asserts.assert_true(
                    self.cert_coverage_info == new_cert_coverage_info,
                    msg="CERT coverage info must be the same for each test run, old: {}, new: {}".format(
                        self.cert_coverage_info, new_cert_coverage_info))
            self.cert_coverage_info = new_cert_coverage_info

        try:
            self.dut.rootservice.StartStack(
                facade_rootservice.StartStackRequest(
                    module_under_test=facade_rootservice.BluetoothModule.Value(self.dut_module)))
        except RpcError as rpc_error:
            asserts.fail("Failed to start DUT stack, RpcError={!r}".format(rpc_error))
        try:
            self.cert.rootservice.StartStack(
                facade_rootservice.StartStackRequest(
                    module_under_test=facade_rootservice.BluetoothModule.Value(self.cert_module)))
        except RpcError as rpc_error:
            asserts.fail("Failed to start CERT stack, RpcError={!r}".format(rpc_error))
        self.dut.wait_channel_ready()
        self.cert.wait_channel_ready()

    def teardown_test(self):
        try:
            self.cert.rootservice.StopStack(facade_rootservice.StopStackRequest())
        except RpcError as rpc_error:
            asserts.fail("Failed to stop CERT stack, RpcError={!r}".format(rpc_error))
        try:
            self.dut.rootservice.StopStack(facade_rootservice.StopStackRequest())
        except RpcError as rpc_error:
            asserts.fail("Failed to stop DUT stack, RpcError={!r}".format(rpc_error))
        # Destroy GD device objects
        self._controller_manager.unregister_controllers()
        teardown_rootcanal(
            rootcanal_running=self.rootcanal_running,
            rootcanal_process=self.rootcanal_process,
            rootcanal_logger=self.rootcanal_logger,
            subprocess_wait_timeout_seconds=self.SUBPROCESS_WAIT_TIMEOUT_SECONDS)

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if not callable(attr) or not GdBaseTestClass.__is_entry_function(name):
            return attr

        @wraps(attr)
        def __wrapped(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except RpcError as e:
                exception_info = "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
                raise signals.TestFailure(
                    "RpcError during test\n\nRpcError:\n\n%s\n%s" % (exception_info, self.__dump_crashes()))

        return __wrapped

    __ENTRY_METHODS = {"setup_class", "teardown_class", "setup_test", "teardown_test"}

    @staticmethod
    def __is_entry_function(name):
        return name.startswith("test_") or name in GdBaseTestClass.__ENTRY_METHODS

    def __dump_crashes(self):
        """
        return: formatted stack traces if found, or last few lines of log
        """
        crash_detail = dump_crashes_core(
            dut=self.dut,
            cert=self.cert,
            rootcanal_running=self.rootcanal_running,
            rootcanal_process=self.rootcanal_process,
            rootcanal_logpath=self.rootcanal_logpath)
        return crash_detail
