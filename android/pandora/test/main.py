from mobly import suite_runner
from avatar import bumble_server

import example
import gatt_test

import logging
import sys

from bumble_experimental.gatt import GATTService
from pandora_experimental.gatt_grpc_aio import add_GATTServicer_to_server

_TEST_CLASSES_LIST = [example.ExampleTest, gatt_test.GattTest]


def _bumble_servicer_hook(server: bumble_server.Server) -> None:
  add_GATTServicer_to_server(GATTService(server.bumble.device), server.server)


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  # This is a hack because of `b/166468397`
  argv = sys.argv[idx+1:] if (idx := sys.argv.index('--')) else sys.argv[1:]

  # Mobly tradefed is using these arguments for specific java tests
  argv = [arg for arg in argv if not arg.startswith(('--device_serial', '--log_path'))]

  # register experimental bumble servicers hook.
  bumble_server.register_servicer_hook(_bumble_servicer_hook)

  suite_runner.run_suite(
      argv=argv,
      test_classes=_TEST_CLASSES_LIST,
  )
