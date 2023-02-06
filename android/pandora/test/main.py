from mobly import suite_runner

import example

import logging
import sys

_TEST_CLASSES_LIST = [example.ExampleTest]


def _valid_argument(arg: str) -> bool:
  return arg.startswith(("--config", "-c", "--tests", "--test_case"))


if __name__ == "__main__":
  logging.basicConfig(level=logging.DEBUG)
  suite_runner.run_suite(
      argv=[arg for arg in sys.argv if _valid_argument(arg)],
      test_classes=_TEST_CLASSES_LIST,
  )
