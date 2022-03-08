#!/usr/bin/env python3
#
#   Copyright 2021 - The Android Open Source Project
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

import queue
import logging

from google.protobuf import empty_pb2 as empty_proto

from bluetooth_packets_python3 import hci_packets
from blueberry.tests.gd_sl4a.lib.bt_constants import ble_scan_settings_modes, ble_address_types, scan_result, ble_scan_settings_phys
from blueberry.tests.gd_sl4a.lib.ble_lib import generate_ble_scan_objects
from blueberry.tests.gd_sl4a.lib.gd_sl4a_base_test import GdSl4aBaseTestClass
from blueberry.facade.hci import le_advertising_manager_facade_pb2 as le_advertising_facade
from blueberry.facade.hci import le_initiator_address_facade_pb2 as le_initiator_address_facade
from blueberry.facade import common_pb2 as common


class LeAdvancedScanningTest(GdSl4aBaseTestClass):

    def setup_class(self):
        super().setup_class(cert_module='HCI_INTERFACES')
        self.default_timeout = 60  # seconds

    def setup_test(self):
        super().setup_test()

    def teardown_test(self):
        super().teardown_test()

    def set_cert_privacy_policy_with_random_address(self, random_address):
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_STATIC_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=bytes(random_address, encoding='utf8')),
                type=common.RANDOM_DEVICE_ADDRESS))
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)

    def set_cert_privacy_policy_with_random_address_but_advertise_resolvable(self, irk):
        random_address_bytes = "DD:34:02:05:5C:EE".encode()
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_RESOLVABLE_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=random_address_bytes), type=common.RANDOM_DEVICE_ADDRESS),
            rotation_irk=irk)
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)
        # Bluetooth MAC address must be upper case
        return random_address_bytes.decode('utf-8').upper()

    def set_cert_privacy_policy_with_public_address(self):
        public_address_bytes = self.cert.hci_controller.GetMacAddress(empty_proto.Empty()).address
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_PUBLIC_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=public_address_bytes), type=common.PUBLIC_DEVICE_ADDRESS))
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)
        # Bluetooth MAC address must be upper case
        return public_address_bytes.decode('utf-8').upper()

    def set_cert_privacy_policy_with_public_address_but_advertise_resolvable(self, irk):
        public_address_bytes = self.cert.hci_controller.GetMacAddress(empty_proto.Empty()).address
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_RESOLVABLE_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=public_address_bytes), type=common.PUBLIC_DEVICE_ADDRESS),
            rotation_irk=irk)
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)
        # Bluetooth MAC address must be upper case
        return public_address_bytes.decode('utf-8').upper()

    def test_scan_filter_device_public_address_with_irk_legacy_pdu(self):
        """
        The cert side will advertise an RPA derived from the adapter's public address.
        """
        data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        byteArrayObject = bytearray(data)
        irk = bytes(byteArrayObject)

        DEVICE_NAME = 'Im_The_CERT!'
        logging.info("Getting public address")
        PUBLIC_ADDRESS = self.set_cert_privacy_policy_with_public_address_but_advertise_resolvable(irk)
        logging.info("Done %s" % PUBLIC_ADDRESS)

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            include_tx_power=True,
            connectable=True,
            legacy_pdus=True,
            advertising_config=config,
            secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d and IRK %s" %
                     (PUBLIC_ADDRESS, addr_type, irk.decode("utf-8")))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressTypeAndIrk(PUBLIC_ADDRESS, int(addr_type), irk.decode("utf-8"))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_public_address_with_irk_legacy_pdu_pending_intent(self):
        """
        The cert side will advertise an RPA derived from the adapter's public address.
        """
        data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        byteArrayObject = bytearray(data)
        irk = bytes(byteArrayObject)

        DEVICE_NAME = 'Im_The_CERT!'
        logging.info("Getting public address")
        PUBLIC_ADDRESS = self.set_cert_privacy_policy_with_public_address_but_advertise_resolvable(irk)
        logging.info("Done %s" % PUBLIC_ADDRESS)

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            include_tx_power=True,
            connectable=True,
            legacy_pdus=True,
            advertising_config=config,
            secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d and IRK %s" %
                     (PUBLIC_ADDRESS, addr_type, irk.decode("utf-8")))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        # The event name needs to be set to this otherwise the index iterates from the scancallbacks
        # being run consecutively.  This is a Pending Intent callback but it hooks into the
        # ScanCallback and uses just the 1 for the index.
        expected_event_name = "BleScan1onScanResults"

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressTypeAndIrk(PUBLIC_ADDRESS, int(addr_type), irk.decode("utf-8"))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScanPendingIntent(filter_list, scan_settings)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_public_address_with_irk_extended_pdu(self):
        """
        The cert side will advertise an RPA derived from the adapter's public address.
        """
        data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        byteArrayObject = bytearray(data)
        irk = bytes(byteArrayObject)

        DEVICE_NAME = 'Im_The_CERT!'
        logging.info("Getting public address")
        PUBLIC_ADDRESS = self.set_cert_privacy_policy_with_public_address_but_advertise_resolvable(irk)
        logging.info("Done %s" % PUBLIC_ADDRESS)

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            include_tx_power=True,
            connectable=True,
            legacy_pdus=False,
            advertising_config=config,
            secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d and IRK %s" %
                     (PUBLIC_ADDRESS, addr_type, irk.decode("utf-8")))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        self.dut.sl4a.bleSetScanSettingsLegacy(False)
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressTypeAndIrk(PUBLIC_ADDRESS, int(addr_type), irk.decode("utf-8"))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_name_legacy_pdu(self):
        # Use public address on cert side
        logging.info("Setting public address")
        DEVICE_NAME = 'Im_The_CERT!'
        public_address = self.set_cert_privacy_policy_with_public_address()
        logging.info("Set public address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_PUBLIC_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES,
            tx_power=20)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.CreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        logging.info("Start scanning with public address %s" % public_address)
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceName(DEVICE_NAME)
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_random_address_legacy_pdu(self):
        # Use random address on cert side
        logging.info("Setting random address")
        RANDOM_ADDRESS = 'D0:05:04:03:02:01'
        DEVICE_NAME = 'Im_The_CERT!'
        self.set_cert_privacy_policy_with_random_address(RANDOM_ADDRESS)
        logging.info("Set random address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.CreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["random"]
        logging.info("Start scanning for RANDOM_ADDRESS %s with address type %d" % (RANDOM_ADDRESS, addr_type))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressAndType(RANDOM_ADDRESS, int(addr_type))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_public_address_extended_pdu(self):
        # Use public address on cert side
        logging.info("Setting public address")
        DEVICE_NAME = 'Im_The_CERT!'
        public_address = self.set_cert_privacy_policy_with_public_address()
        logging.info("Set public address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_PUBLIC_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            advertising_config=config, secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d" % (public_address, addr_type))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        self.dut.sl4a.bleSetScanSettingsLegacy(False)
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressAndType(public_address, int(addr_type))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_public_address_with_irk_extended_pdu_pending_intent(self):
        """
        The cert side will advertise an RPA derived from the adapter's public address.
        """
        data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        byteArrayObject = bytearray(data)
        irk = bytes(byteArrayObject)

        DEVICE_NAME = 'Im_The_CERT!'
        logging.info("Getting public address")
        PUBLIC_ADDRESS = self.set_cert_privacy_policy_with_public_address_but_advertise_resolvable(irk)
        logging.info("Done %s" % PUBLIC_ADDRESS)

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            include_tx_power=True,
            connectable=True,
            legacy_pdus=False,
            advertising_config=config,
            secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d and IRK %s" %
                     (PUBLIC_ADDRESS, addr_type, irk.decode("utf-8")))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        self.dut.sl4a.bleSetScanSettingsLegacy(False)
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        # Hard code here since callback index iterates and will cause this to fail if ran
        # Second as the impl in SL4A sends this since its a single callback for broadcast.
        expected_event_name = "BleScan1onScanResults"

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressTypeAndIrk(PUBLIC_ADDRESS, int(addr_type), irk.decode("utf-8"))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScanPendingIntent(filter_list, scan_settings)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_random_address_with_irk_extended_pdu(self):
        """
        The CERT side will advertise an RPA derived from the IRK.

        The DUT (SL4A) side will scan for a RPA with matching IRK.
        """
        data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        byteArrayObject = bytearray(data)
        irk = bytes(byteArrayObject)

        DEVICE_NAME = 'Im_The_CERT!'
        logging.info("Getting public address")
        RANDOM_ADDRESS = self.set_cert_privacy_policy_with_random_address_but_advertise_resolvable(irk)
        logging.info("Done %s" % RANDOM_ADDRESS)

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)

        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            include_tx_power=True,
            connectable=True,
            legacy_pdus=False,
            advertising_config=config,
            secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["random"]
        logging.info("Start scanning for RANDOM_ADDRESS %s with address type %d and IRK %s" %
                     (RANDOM_ADDRESS, addr_type, irk.decode("utf-8")))
        self.dut.sl4a.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        self.dut.sl4a.bleSetScanSettingsLegacy(False)
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.sl4a)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.sl4a.bleSetScanFilterDeviceAddressTypeAndIrk(RANDOM_ADDRESS, int(addr_type), irk.decode("utf-8"))
        self.dut.sl4a.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.sl4a.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            logging.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        logging.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.sl4a.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True
