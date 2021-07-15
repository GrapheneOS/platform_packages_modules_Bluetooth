#!/usr/bin/env python3

#  Copyright 2021 Google, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at:
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
""" Bootstrap script to help set up Linux build. """

import argparse
import os
import subprocess

PLATFORM2_GIT = 'https://chromium.googlesource.com/chromiumos/platform2'
RUST_CRATES_GIT = 'https://chromium.googlesource.com/chromiumos/third_party/rust_crates'
PROTO_LOGGING_GIT = 'https://android.googlesource.com/platform/frameworks/proto_logging'

# List of packages required for linux build
REQUIRED_APT_PACKAGES = [
    'bison',
    'build-essential',
    'curl',
    'flatbuffers-compiler',
    'flex',
    'g++-multilib',
    'gcc-multilib',
    'generate-ninja',
    'gnupg',
    'gperf',
    'libc++-dev',
    'libdbus-1-dev',
    'libevent-dev',
    'libevent-dev',
    'libflatbuffers-dev',
    'libflatbuffers1',
    'libgl1-mesa-dev',
    'libglib2.0-dev',
    'liblz4-tool',
    'libncurses5',
    'libnss3-dev',
    'libprotobuf-dev',
    'libre2-9',
    'libssl-dev',
    'libtinyxml2-dev',
    'libx11-dev',
    'libxml2-utils',
    'ninja-build',
    'openssl',
    'protobuf-compiler',
    'unzip',
    'x11proto-core-dev',
    'xsltproc',
    'zip',
    'zlib1g-dev',
]

# List of cargo packages required for linux build
REQUIRED_CARGO_PACKAGES = ['cxxbridge-cmd']

APT_PKG_LIST = ['apt', '-qq', 'list']
CARGO_PKG_LIST = ['cargo', 'install', '--list']


class Bootstrap():

    def __init__(self, base_dir, bt_dir):
        """ Construct bootstrapper.

        Args:
            base_dir: Where to stage everything.
            bt_dir: Where bluetooth source is kept (will be symlinked)
        """
        self.base_dir = os.path.abspath(base_dir)
        self.bt_dir = os.path.abspath(bt_dir)

        if not os.path.isdir(self.base_dir):
            raise Exception('{} is not a valid directory'.format(self.base_dir))

        if not os.path.isdir(self.bt_dir):
            raise Exception('{} is not a valid directory'.format(self.bt_dir))

        self.git_dir = os.path.join(self.base_dir, 'repos')
        self.staging_dir = os.path.join(self.base_dir, 'staging')
        self.output_dir = os.path.join(self.base_dir, 'output')
        self.external_dir = os.path.join(self.base_dir, 'staging', 'external')

        self.dir_setup_complete = os.path.join(self.base_dir, '.setup-complete')

    def _setup_platform2(self):
        """ Set up platform2.

        This will check out all the git repos and symlink everything correctly.
        """

        # If already set up, exit early
        if os.path.isfile(self.dir_setup_complete):
            print('{} is already set-up'.format(self.base_dir))
            return

        # Create all directories we will need to use
        for dirpath in [self.git_dir, self.staging_dir, self.output_dir, self.external_dir]:
            os.makedirs(dirpath)

        # Check out all repos in git directory
        for repo in [PLATFORM2_GIT, RUST_CRATES_GIT, PROTO_LOGGING_GIT]:
            subprocess.check_call(['git', 'clone', repo], cwd=self.git_dir)

        # Symlink things
        symlinks = [
            (os.path.join(self.git_dir, 'platform2', 'common-mk'), os.path.join(self.staging_dir, 'common-mk')),
            (os.path.join(self.git_dir, 'platform2', '.gn'), os.path.join(self.staging_dir, '.gn')),
            (os.path.join(self.bt_dir), os.path.join(self.staging_dir, 'bt')),
            (os.path.join(self.git_dir, 'rust_crates'), os.path.join(self.external_dir, 'rust')),
            (os.path.join(self.git_dir, 'proto_logging'), os.path.join(self.external_dir, 'proto_logging')),
        ]

        # Create symlinks
        for pairs in symlinks:
            (src, dst) = pairs
            os.symlink(src, dst)

        # Write to setup complete file so we don't repeat this step
        with open(self.dir_setup_complete, 'w') as f:
            f.write('Setup complete.')

    def _pretty_print_install(self, install_cmd, packages, line_limit=80):
        """ Pretty print an install command.

        Args:
            install_cmd: Prefixed install command.
            packages: Enumerate packages and append them to install command.
            line_limit: Number of characters per line.

        Return:
            Array of lines to join and print.
        """
        install = [install_cmd]
        line = '  '
        # Remainder needed = space + len(pkg) + space + \
        # Assuming 80 character lines, that's 80 - 3 = 77
        line_limit = line_limit - 3
        for pkg in packages:
            if len(line) + len(pkg) < line_limit:
                line = '{}{} '.format(line, pkg)
            else:
                install.append(line)
                line = '  {} '.format(pkg)

        if len(line) > 0:
            install.append(line)

        return install

    def _check_package_installed(self, package, cmd, predicate):
        """Check that the given package is installed.

        Args:
            package: Check that this package is installed.
            cmd: Command prefix to check if installed (package appended to end)
            predicate: Function/lambda to check if package is installed based
                       on output. Takes string output and returns boolean.

        Return:
            True if package is installed.
        """
        try:
            output = subprocess.check_output(cmd + [package], stderr=subprocess.STDOUT)
            is_installed = predicate(output.decode('utf-8'))
            print('  {} is {}'.format(package, 'installed' if is_installed else 'missing'))

            return is_installed
        except Exception as e:
            print(e)
            return False

    def _print_missing_packages(self):
        """Print any missing packages found via apt.

        This will find any missing packages necessary for build using apt and
        print it out as an apt-get install printf.
        """
        print('Checking for any missing packages...')
        need_packages = []
        for pkg in REQUIRED_APT_PACKAGES:
            if not self._check_package_installed(pkg, APT_PKG_LIST, lambda output: 'installed' in output):
                need_packages.append(pkg)

        # No packages need to be installed
        if len(need_packages) == 0:
            print('All required packages are installed')
            return

        install = self._pretty_print_install('sudo apt-get install', need_packages)

        # Print all lines so they can be run in cmdline
        print('Missing system packages. Run the following command: ')
        print(' \\\n'.join(install))

    def _print_missing_rust_packages(self):
        """Print any missing packages found via cargo.

        This will find any missing packages necessary for build using cargo and
        print it out as a cargo-install printf.
        """
        print('Checking for any missing cargo packages...')
        need_packages = []

        for pkg in REQUIRED_CARGO_PACKAGES:
            if not self._check_package_installed(pkg, CARGO_PKG_LIST, lambda output: pkg in output):
                need_packages.append(pkg)

        # No packages to be installed
        if len(need_packages) == 0:
            print('All required cargo packages are installed')
            return

        install = self._pretty_print_install('cargo install', need_packages)
        print('Missing cargo packages. Run the following command: ')
        print(' \\\n'.join(install))

    def bootstrap(self):
        """ Bootstrap the Linux build."""
        self._setup_platform2()
        self._print_missing_packages()
        self._print_missing_rust_packages()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootstrap Linux build')
    parser.add_argument('--base-dir', help='Where to create build directories.', required=True)
    parser.add_argument('--bt-dir', help='Path to packages/modules/Bluetooth/system', required=True)

    args = parser.parse_args()
    bootstrap = Bootstrap(args.base_dir, args.bt_dir)
    bootstrap.bootstrap()
