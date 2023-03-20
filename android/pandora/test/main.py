import site

site.main()

import argparse
import asha_test
import example
import gatt_test
import le_advertising_test
import logging
import os
import sys

from collections import OrderedDict
from mobly import base_test, config_parser, signals, suite_runner, test_runner
from typing import Any, List, Optional, Type

_TEST_CLASSES_LIST = [
    example.ExampleTest,
    asha_test.ASHATest,
    gatt_test.GattTest,
    le_advertising_test.LeAdvertisingTest,
]


def _parse_cli_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Mobly Suite Executable.')
    parser.add_argument('-c', '--config', type=str, metavar='<PATH>', help='Path to the test configuration file.')
    parser.add_argument(
        '-l',
        '--list',
        action='store_true',
        help='Print the names of the tests defined in a script without executing them.',
    )
    parser.add_argument(
        '-b',
        '--test_bed',
        nargs='+',
        type=str,
        metavar='[<TEST BED NAME1> <TEST BED NAME2> ...]',
        help='Specify which test beds to run tests on.',
    )
    parser.add_argument(
        '-t',
        '--tests',
        nargs='+',
        type=str,
        metavar='[ClassA[.test_a] ClassB[.test_b] ...]',
        help='A list of test classes and optional tests to execute.',
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Set console logger level to DEBUG')
    parser.add_argument('-o', '--log', '--log_path', type=str, metavar='<PATH>', help='Path where to store log files')
    parser.add_argument(
        '-s', '--serial', '--device_serial', type=str, metavar='<SERIAL>', help='Android device serial'
    )
    if not argv:
        argv = sys.argv[1:]
    return parser.parse_args(argv)


def run(test_classes: List[Any], argv: List[str]) -> None:
    args = _parse_cli_args(argv)

    # Check the classes that were passed in
    for test_class in test_classes:
        if not issubclass(test_class, base_test.BaseTestClass):
            logging.error('Test class %s does not extend ' 'mobly.base_test.BaseTestClass', test_class)
            sys.exit(1)

    # Find the full list of tests to execute
    selected_tests: OrderedDict[
        Type[base_test.BaseTestClass], Optional[List[str]]
    ] = suite_runner.compute_selected_tests(  # type: ignore
        test_classes, args.tests
    )
    if args.list:
        for (test_class, test_names) in selected_tests.items():
            test = test_class(config_parser.TestRunConfig())
            _test_names: List[str] = test_names or test.get_existing_test_names()  # type: ignore
            for name in _test_names:
                print(f"{test.TAG}.{name}")
        sys.exit(0)

    # Execute the suite
    ok = True
    try:
        # Load test config file.
        test_configs: List[config_parser.TestRunConfig] = config_parser.load_test_config_file(
            args.config, args.test_bed
        )  # type: ignore

        console_level = logging.DEBUG if args.verbose else logging.INFO
        for config in test_configs:
            runner = test_runner.TestRunner(config.log_path, config.testbed_name)
            with runner.mobly_logger(console_level=console_level):
                for (test_class, tests) in selected_tests.items():
                    runner.add_test_class(config, test_class, tests)  # type: ignore
                try:
                    runner.run()
                    ok = runner.results.is_all_pass and ok
                except signals.TestAbortAll:  # type: ignore
                    pass
                except Exception:
                    logging.exception('Exception when executing %s.', config.testbed_name)
                    ok = False
    except KeyboardInterrupt:
        ok = False
    except:
        logging.exception('Test suite failed.')
        ok = False
    finally:
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # This is a hack for `atest` because of `b/166468397`.
    argv = sys.argv[2:] if len(sys.argv) > 1 and sys.argv[1] == '--' else sys.argv[1:]

    # Default configuration file & `PandoraServer.apk`.
    root = str(os.path.dirname(__file__))
    default_argv = ['-c', os.path.join(root, 'config.yml')]

    # Run the test suite.
    run(_TEST_CLASSES_LIST, default_argv + argv)
