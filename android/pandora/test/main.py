from mobly import suite_runner

import example

import logging
import sys

_TEST_CLASSES_LIST = [example.ExampleTest]


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  # This is a hack because of `b/166468397`
  argv = sys.argv[idx+1:] if (idx := sys.argv.index('--')) else sys.argv[1:]

  # Mobly tradefed is using these arguments for specific java tests
  argv = [arg for arg in argv if not arg.startswith(('--device_serial', '--log_path'))]

  suite_runner.run_suite(
      argv=argv,
      test_classes=_TEST_CLASSES_LIST,
  )
