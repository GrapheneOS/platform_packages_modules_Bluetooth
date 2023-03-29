import site

site.main()

import asha_test
import example
import gatt_test
import le_advertising_test
import logging
import sys

from mobly import suite_runner

_TEST_CLASSES_LIST = [
    example.ExampleTest,
    asha_test.ASHATest,
    gatt_test.GattTest,
    le_advertising_test.LeAdvertisingTest,
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # This is a hack for `tradefed` because of `b/166468397`.
    if '--' in sys.argv:
        index = sys.argv.index('--')
        sys.argv = sys.argv[:1] + sys.argv[index + 1 :]

    # Run the test suite.
    suite_runner.run_suite(_TEST_CLASSES_LIST)  # type: ignore
