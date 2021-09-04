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

from abc import ABC
from datetime import datetime
import inspect
import logging
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import time
from typing import List

import grpc

from acts import asserts
from acts import utils
from acts.context import get_current_context
from acts.controllers.adb import AdbProxy
from acts.controllers.adb import AdbError
from acts.controllers.adb_lib.error import AdbCommandError

from cert.async_subprocess_logger import AsyncSubprocessLogger
from cert.gd_device_lib import create_core
from cert.gd_device_lib import destroy_core
from cert.gd_device_lib import get_info
from cert.gd_device_lib import replace_vars
from cert.gd_device_lib import GdDeviceBaseCore
from cert.gd_device_lib import get_coverage_profdata_path_for_host
from cert.gd_device_lib import merge_coverage_profdata_for_host
from cert.gd_device_lib import MOBLY_CONTROLLER_CONFIG_NAME
from cert.gd_device_lib import ACTS_CONTROLLER_REFERENCE_NAME
from cert.logging_client_interceptor import LoggingClientInterceptor
from cert.os_utils import get_gd_root
from cert.os_utils import read_crash_snippet_and_log_tail
from cert.os_utils import is_subprocess_alive
from cert.os_utils import make_ports_available
from cert.os_utils import TerminalColor
from facade import rootservice_pb2_grpc as facade_rootservice_pb2_grpc


def create(configs):
    create_core(configs)
    return get_instances_with_configs(configs)


def destroy(devices):
    destroy_core(devices)


def get_instances_with_configs(configs):
    print(configs)
    devices = []
    for config in configs:
        resolved_cmd = []
        for arg in config["cmd"]:
            logging.debug(arg)
            resolved_cmd.append(replace_vars(arg, config))
        verbose_mode = bool(config.get('verbose_mode', False))
        if config.get("serial_number"):
            device = GdAndroidDevice(config["grpc_port"], config["grpc_root_server_port"], config["signal_port"],
                                     resolved_cmd, config["label"], MOBLY_CONTROLLER_CONFIG_NAME, config["name"],
                                     config["serial_number"], verbose_mode)
        else:
            device = GdHostOnlyDevice(config["grpc_port"], config["grpc_root_server_port"], config["signal_port"],
                                      resolved_cmd, config["label"], MOBLY_CONTROLLER_CONFIG_NAME, config["name"],
                                      verbose_mode)
        device.setup()
        devices.append(device)
    return devices


class GdDeviceBase(GdDeviceBaseCore):
    """
    Base GD device class that covers common traits which assumes that the
    device must be driven by a driver-like backing process that takes following
    command line arguments:
    --grpc-port: main entry port for facade services
    --root-server-port: management port for starting and stopping services
    --btsnoop: path to btsnoop HCI log
    --signal-port: signaling port to indicate that backing process is started
    --rootcanal-port: root-canal HCI port, optional
    """

    def __init__(self, grpc_port: str, grpc_root_server_port: str, signal_port: str, cmd: List[str], label: str,
                 type_identifier: str, name: str, verbose_mode: bool):
        """Verify arguments and log path, initialize Base GD device, common traits
         for both device based and host only GD cert tests
        :param grpc_port: main gRPC service port
        :param grpc_root_server_port: gRPC root server port
        :param signal_port: signaling port for backing process start up
        :param cmd: list of arguments to run in backing process
        :param label: device label used in logs
        :param type_identifier: device type identifier used in logs
        :param name: name of device used in logs
        """
        # Must be at the first line of __init__ method
        values = locals()
        arguments = [values[arg] for arg in inspect.getfullargspec(GdDeviceBase.__init__).args if arg != "verbose_mode"]
        asserts.assert_true(all(arguments), "All arguments to GdDeviceBase must not be None nor empty")
        asserts.assert_true(all(cmd), "cmd list should not have None nor empty component")

        # logging.log_path only exists when this is used in an ACTS test run.
        self.log_path_base = get_current_context().get_full_output_path()
        self.test_runner_base_path = \
            get_current_context().get_base_output_path()

        GdDeviceBaseCore.__init__(self, grpc_port, grpc_root_server_port, signal_port, cmd, label, type_identifier,
                                  name, verbose_mode, self.log_path_base, self.test_runner_base_path)

    def setup(self):
        """Inherited setup method from base class to set up this device for test,
        ensure signal port is available and backing process is started and alive,
        must run before using this device
        - After calling this, teardown() must be called when test finishes
        - Should be executed after children classes' setup() methods
        :return:
        """
        GdDeviceBaseCore.setup(self)
        # Ensure signal port is available
        # signal port is the only port that always listen on the host machine
        asserts.assert_true(self.signal_port_available, "[%s] Failed to make signal port available" % self.label)

        # Ensure backing process is started and alive
        asserts.assert_true(self.backing_process, msg="Cannot start backing_process at " + " ".join(self.cmd))
        asserts.assert_true(
            self.is_backing_process_alive,
            msg="backing_process stopped immediately after running " + " ".join(self.cmd))

    def get_crash_snippet_and_log_tail(self):
        GdDeviceBaseCore.get_crash_snippet_and_log_tail(self)

    def teardown(self):
        """Inherited teardown method from base class to tear down this device
        and clean up any resources.
        - Must be called after setup()
        - Should be executed before children classes' teardown()
        :return:
        """
        GdDeviceBaseCore.teardown(self)

    def wait_channel_ready(self):
        try:
            GdDeviceBaseCore.wait_channel_ready(self)
        except grpc.FutureTimeoutError:
            asserts.fail("[%s] wait channel ready timeout" % self.label)


class GdHostOnlyDevice(GdDeviceBase):
    """
    Host only device where the backing process is running on the host machine
    """

    def __init__(self, grpc_port: str, grpc_root_server_port: str, signal_port: str, cmd: List[str], label: str,
                 type_identifier: str, name: str, verbose_mode: bool):
        super().__init__(grpc_port, grpc_root_server_port, signal_port, cmd, label, MOBLY_CONTROLLER_CONFIG_NAME, name,
                         verbose_mode)
        self.host_only_device = True
        # Enable LLVM code coverage output for host only tests
        self.backing_process_profraw_path = pathlib.Path(self.log_path_base).joinpath(
            "%s_%s_backing_coverage.profraw" % (self.type_identifier, self.label))
        self.environment["LLVM_PROFILE_FILE"] = str(self.backing_process_profraw_path)
        llvm_binutils = pathlib.Path(get_gd_root()).joinpath("llvm_binutils").joinpath("bin")
        llvm_symbolizer = llvm_binutils.joinpath("llvm-symbolizer")
        if llvm_symbolizer.is_file():
            self.environment["ASAN_SYMBOLIZER_PATH"] = llvm_symbolizer
        else:
            logging.warning("[%s] Cannot find LLVM symbolizer at %s" % (self.label, str(llvm_symbolizer)))
        self.profdata_path = get_coverage_profdata_path_for_host(self.test_runner_base_path, self.type_identifier,
                                                                 self.label)

    def teardown(self):
        super().teardown()
        merge_coverage_profdata_for_host(self.backing_process_profraw_path, self.profdata_path, self.label)

    def get_coverage_info(self):
        """
        Get information needed for coverage reporting
        :return: a dictionary with all information needed for coverage reporting
        """
        return {
            "profdata_path": self.profdata_path,
            "label": self.label,
            "test_runner_base_path": self.test_runner_base_path,
            "type_identifier": self.type_identifier,
            "stack_bin": self.cmd[0]
        }

    def setup(self):
        # Ensure ports are available
        # Only check on host only test, for Android devices, these ports will
        # be opened on Android device and host machine ports will be occupied
        # by sshd or adb forwarding
        asserts.assert_true(
            make_ports_available((self.grpc_port, self.grpc_root_server_port)),
            "[%s] Failed to make backing process ports available" % self.label)
        super().setup()


class GdAndroidDevice(GdDeviceBase):
    """Real Android device where the backing process is running on it
    """

    WAIT_FOR_DEVICE_TIMEOUT_SECONDS = 180

    def __init__(self, grpc_port: str, grpc_root_server_port: str, signal_port: str, cmd: List[str], label: str,
                 type_identifier: str, name: str, serial_number: str, verbose_mode: bool):
        super().__init__(grpc_port, grpc_root_server_port, signal_port, cmd, label, type_identifier, name, verbose_mode)
        asserts.assert_true(serial_number, "serial_number must not be None nor empty")
        self.serial_number = serial_number
        self.adb = AdbProxy(serial_number)

    def setup(self):
        logging.info("Setting up device %s %s" % (self.label, self.serial_number))
        asserts.assert_true(self.adb.ensure_root(), "device %s cannot run as root", self.serial_number)
        self.ensure_verity_disabled()

        # Try freeing ports and ignore results
        self.cleanup_port_forwarding()
        self.sync_device_time()

        # Set up port forwarding or reverse or die
        self.tcp_forward_or_die(self.grpc_port, self.grpc_port)
        self.tcp_forward_or_die(self.grpc_root_server_port, self.grpc_root_server_port)
        self.tcp_reverse_or_die(self.signal_port, self.signal_port)

        # Push test binaries
        self.push_or_die(os.path.join(get_gd_root(), "target", "bluetooth_stack_with_facade"), "system/bin")
        self.push_or_die(
            os.path.join(get_gd_root(), "target", "android.system.suspend.control-V1-ndk.so"), "system/lib64")
        self.push_or_die(os.path.join(get_gd_root(), "target", "libbluetooth_gd.so"), "system/lib64")
        self.push_or_die(os.path.join(get_gd_root(), "target", "libgrpc++_unsecure.so"), "system/lib64")
        self.push_or_die(os.path.join(get_gd_root(), "target", "libgrpc++.so"), "system/lib64")
        self.push_or_die(os.path.join(get_gd_root(), "target", "libgrpc_wrap.so"), "system/lib64")
        self.push_or_die(os.path.join(get_gd_root(), "target", "libstatslog.so"), "system/lib64")

        try:
            self.adb.shell("rm /data/misc/bluetooth/logs/btsnoop_hci.log")
        except AdbCommandError as error:
            if "No such file or directory" not in str(error):
                logging.error("Error during setup: " + str(error))

        try:
            self.adb.shell("rm /data/misc/bluetooth/logs/btsnooz_hci.log")
        except AdbCommandError as error:
            if "No such file or directory" not in str(error):
                logging.error("Error during setup: " + str(error))

        try:
            self.adb.shell("rm /data/misc/bluedroid/bt_config.conf")
        except AdbCommandError as error:
            if "No such file or directory" not in str(error):
                logging.error("Error during setup: " + str(error))

        try:
            self.adb.shell("rm /data/misc/bluedroid/bt_config.bak")
        except AdbCommandError as error:
            if "No such file or directory" not in str(error):
                logging.error("Error during setup: " + str(error))

        self.ensure_no_output(self.adb.shell("svc bluetooth disable"))

        # Start logcat logging
        self.logcat_output_path = os.path.join(
            self.log_path_base, '%s_%s_%s_logcat_logs.txt' % (self.type_identifier, self.label, self.serial_number))
        self.logcat_cmd = ["adb", "-s", self.serial_number, "logcat", "-T", "1", "-v", "year", "-v", "uid"]
        logging.debug("Running %s", " ".join(self.logcat_cmd))
        self.logcat_process = subprocess.Popen(
            self.logcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        asserts.assert_true(self.logcat_process, msg="Cannot start logcat_process at " + " ".join(self.logcat_cmd))
        asserts.assert_true(
            is_subprocess_alive(self.logcat_process),
            msg="logcat_process stopped immediately after running " + " ".join(self.logcat_cmd))
        self.logcat_logger = AsyncSubprocessLogger(
            self.logcat_process, [self.logcat_output_path],
            log_to_stdout=self.verbose_mode,
            tag="%s_%s" % (self.label, self.serial_number),
            color=self.terminal_color)

        # Done run parent setup
        logging.info("Done preparation for %s, starting backing process" % self.serial_number)
        super().setup()

    def teardown(self):
        super().teardown()
        stop_signal = signal.SIGINT
        self.logcat_process.send_signal(stop_signal)
        try:
            return_code = self.logcat_process.wait(timeout=self.WAIT_CHANNEL_READY_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            logging.error("[%s_%s] Failed to interrupt logcat process via SIGINT, sending SIGKILL" %
                          (self.label, self.serial_number))
            stop_signal = signal.SIGKILL
            self.logcat_process.kill()
            try:
                return_code = self.logcat_process.wait(timeout=self.WAIT_CHANNEL_READY_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                logging.error("Failed to kill logcat_process %s %s" % (self.label, self.serial_number))
                return_code = -65536
        if return_code not in [-stop_signal, 0]:
            logging.error("logcat_process %s_%s stopped with code: %d" % (self.label, self.serial_number, return_code))
        self.logcat_logger.stop()
        self.cleanup_port_forwarding()
        try:
            self.adb.pull("/data/misc/bluetooth/logs/btsnoop_hci.log %s" % os.path.join(
                self.log_path_base, "%s_btsnoop_hci.log" % self.label))
        except AdbError as error:
            # Some tests have no snoop logs, and that's OK
            if "No such file or directory" not in str(error):
                logging.error("While trying to pull log files" + str(error))
        try:
            self.adb.pull("/data/misc/bluedroid/bt_config.conf %s" % os.path.join(self.log_path_base,
                                                                                  "%s_bt_config.conf" % self.label))
        except AdbError as error:
            # Some tests have no config file, and that's OK
            if "No such file or directory" not in str(error):
                logging.error("While trying to pull log files" + str(error))
        try:
            self.adb.pull("/data/misc/bluedroid/bt_config.bak %s" % os.path.join(self.log_path_base,
                                                                                 "%s_bt_config.bak" % self.label))
        except AdbError as error:
            # Some tests have no config.bak file, and that's OK
            if "No such file or directory" not in str(error):
                logging.error("While trying to pull log files" + str(error))

    def cleanup_port_forwarding(self):
        try:
            self.adb.remove_tcp_forward(self.grpc_port)
        except AdbError as error:
            msg = "During port forwarding cleanup: " + str(error)
            if "not found" in msg:
                logging.info(msg)
            else:
                logging.error(msg)

        try:
            self.adb.remove_tcp_forward(self.grpc_root_server_port)
        except AdbError as error:
            msg = "During port forwarding cleanup: " + str(error)
            if "not found" in msg:
                logging.info(msg)
            else:
                logging.error(msg)

        try:
            self.adb.reverse("--remove tcp:%d" % self.signal_port)
        except AdbError as error:
            msg = "During port forwarding cleanup: " + str(error)
            if "not found" in msg:
                logging.info(msg)
            else:
                logging.error(msg)

    @staticmethod
    def ensure_no_output(result):
        """
        Ensure a command has not output
        """
        asserts.assert_true(
            result is None or len(result) == 0, msg="command returned something when it shouldn't: %s" % result)

    def sync_device_time(self):
        self.adb.shell("settings put global auto_time 0")
        self.adb.shell("settings put global auto_time_zone 0")
        device_tz = self.adb.shell("date +%z")
        asserts.assert_true(device_tz, "date +%z must return device timezone, "
                            "but returned {} instead".format(device_tz))
        host_tz = time.strftime("%z")
        if device_tz != host_tz:
            target_timezone = utils.get_timezone_olson_id()
            logging.debug("Device timezone %s does not match host timezone %s, "
                          "syncing them by setting timezone to %s" % (device_tz, host_tz, target_timezone))
            self.adb.shell("setprop persist.sys.timezone %s" % target_timezone)
            self.reboot()
            self.adb.remount()
            device_tz = self.adb.shell("date +%z")
            asserts.assert_equal(
                host_tz, device_tz, "Device timezone %s still does not match host "
                "timezone %s after reset" % (device_tz, host_tz))
        self.adb.shell("date %s" % time.strftime("%m%d%H%M%Y.%S"))
        datetime_format = "%Y-%m-%dT%H:%M:%S%z"
        try:
            device_time = datetime.strptime(self.adb.shell("date +'%s'" % datetime_format), datetime_format)
        except ValueError:
            asserts.fail("Failed to get time after sync")
            return
        # Include ADB delay that might be longer in SSH environment
        max_delta_seconds = 3
        host_time = datetime.now(tz=device_time.tzinfo)
        asserts.assert_almost_equal(
            (device_time - host_time).total_seconds(),
            0,
            msg="Device time %s and host time %s off by >%dms after sync" %
            (device_time.isoformat(), host_time.isoformat(), int(max_delta_seconds * 1000)),
            delta=max_delta_seconds)

    def push_or_die(self, src_file_path, dst_file_path, push_timeout=300):
        """Pushes a file to the Android device

        Args:
            src_file_path: The path to the file to install.
            dst_file_path: The destination of the file.
            push_timeout: How long to wait for the push to finish in seconds
        """
        out = self.adb.push('%s %s' % (src_file_path, dst_file_path), timeout=push_timeout)
        if 'error' in out:
            asserts.fail('Unable to push file %s to %s due to %s' % (src_file_path, dst_file_path, out))

    def tcp_forward_or_die(self, host_port, device_port, num_retry=1):
        """
        Forward a TCP port from host to device or fail
        :param host_port: host port, int, 0 for adb to assign one
        :param device_port: device port, int
        :param num_retry: number of times to reboot and retry this before dying
        :return: host port int
        """
        error_or_port = self.adb.tcp_forward(host_port, device_port)
        if not error_or_port:
            logging.debug("host port %d was already forwarded" % host_port)
            return host_port
        if not isinstance(error_or_port, int):
            if num_retry > 0:
                # If requested, reboot an retry
                num_retry -= 1
                logging.warning(
                    "[%s] Failed to TCP forward host port %d to "
                    "device port %d, num_retries left is %d" % (self.label, host_port, device_port, num_retry))
                self.reboot()
                self.adb.remount()
                return self.tcp_forward_or_die(host_port, device_port, num_retry=num_retry)
            asserts.fail(
                'Unable to forward host port %d to device port %d, error %s' % (host_port, device_port, error_or_port))
        return error_or_port

    def tcp_reverse_or_die(self, device_port, host_port, num_retry=1):
        """
        Forward a TCP port from device to host or fail
        :param device_port: device port, int, 0 for adb to assign one
        :param host_port: host port, int
        :param num_retry: number of times to reboot and retry this before dying
        :return: device port int
        """
        error_or_port = self.adb.reverse("tcp:%d tcp:%d" % (device_port, host_port))
        if not error_or_port:
            logging.debug("device port %d was already reversed" % device_port)
            return device_port
        try:
            error_or_port = int(error_or_port)
        except ValueError:
            if num_retry > 0:
                # If requested, reboot an retry
                num_retry -= 1
                logging.warning(
                    "[%s] Failed to TCP reverse device port %d to "
                    "host port %d, num_retries left is %d" % (self.label, device_port, host_port, num_retry))
                self.reboot()
                self.adb.remount()
                return self.tcp_reverse_or_die(device_port, host_port, num_retry=num_retry)
            asserts.fail(
                'Unable to reverse device port %d to host port %d, error %s' % (device_port, host_port, error_or_port))
        return error_or_port

    def ensure_verity_disabled(self):
        """Ensures that verity is enabled.

        If verity is not enabled, this call will reboot the phone. Note that
        this only works on debuggable builds.
        """
        logging.debug("Disabling verity and remount for %s", self.serial_number)
        # The below properties will only exist if verity has been enabled.
        system_verity = self.adb.getprop('partition.system.verified')
        vendor_verity = self.adb.getprop('partition.vendor.verified')
        if system_verity or vendor_verity:
            self.adb.disable_verity()
            self.reboot()
        self.adb.remount()
        self.adb.wait_for_device(timeout=self.WAIT_FOR_DEVICE_TIMEOUT_SECONDS)

    def reboot(self, timeout_minutes=15.0):
        """Reboots the device.

        Reboot the device, wait for device to complete booting.
        """
        logging.debug("Rebooting %s", self.serial_number)
        self.adb.reboot()

        timeout_start = time.time()
        timeout = timeout_minutes * 60
        # Android sometimes return early after `adb reboot` is called. This
        # means subsequent calls may make it to the device before the reboot
        # goes through, return false positives for getprops such as
        # sys.boot_completed.
        while time.time() < timeout_start + timeout:
            try:
                self.adb.get_state()
                time.sleep(.1)
            except AdbError:
                # get_state will raise an error if the device is not found. We
                # want the device to be missing to prove the device has kicked
                # off the reboot.
                break
        minutes_left = timeout_minutes - (time.time() - timeout_start) / 60.0
        self.wait_for_boot_completion(timeout_minutes=minutes_left)
        asserts.assert_true(self.adb.ensure_root(), "device %s cannot run as root after reboot", self.serial_number)

    def wait_for_boot_completion(self, timeout_minutes=15.0):
        """
        Waits for Android framework to broadcast ACTION_BOOT_COMPLETED.
        :param timeout_minutes: number of minutes to wait
        """
        timeout_start = time.time()
        timeout = timeout_minutes * 60

        self.adb.wait_for_device(timeout=self.WAIT_FOR_DEVICE_TIMEOUT_SECONDS)
        while time.time() < timeout_start + timeout:
            try:
                completed = self.adb.getprop("sys.boot_completed")
                if completed == '1':
                    return
            except AdbError:
                # adb shell calls may fail during certain period of booting
                # process, which is normal. Ignoring these errors.
                pass
            time.sleep(5)
        asserts.fail(msg='Device %s booting process timed out.' % self.serial_number)
