#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys


class FlossDockerRunner:
    """Runs Floss build inside docker container."""

    # Commands to run for build
    BUILD_COMMANDS = [
        # First run bootstrap to get latest code + create symlinks
        ['/root/src/build.py', '--run-bootstrap'],

        # Clean up any previous artifacts inside the volume
        ['/root/src/build.py', '--target', 'clean'],

        # Run normal code builder
        ['/root/src/build.py', '--target', 'all'],

        # Run tests
        ['/root/src/build.py', '--target', 'test'],
    ]

    def __init__(self, workdir, rootdir, image_tag, volume_tag):
        """ Constructor.

        Args:
            workdir: Current working directory (should be the script path).
            rootdir: Root directory for Bluetooth.
            build_tag: Tag for docker image used for building.
        """
        self.workdir = workdir
        self.rootdir = rootdir
        self.image_tag = image_tag
        self.env = os.environ.copy()

        # Name of running container
        self.container_name = 'floss-docker-runner'

        # Name of volume where we'll send build output
        self.volume_name = volume_tag

    def run_command(self, target, args, cwd=None, env=None, ignore_rc=False):
        """ Run command and stream the output.
        """
        # Set some defaults
        if not cwd:
            cwd = self.workdir
        if not env:
            env = self.env

        rc = 0
        process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE)
        while True:
            line = process.stdout.readline()
            print(line.decode('utf-8'), end="")
            if not line:
                rc = process.poll()
                if rc is not None:
                    break

                time.sleep(0.1)

        if rc != 0 and not ignore_rc:
            raise Exception("{} failed. Return code is {}".format(target, rc))

    def _create_volume_if_needed(self):
        # Check if the volume exists. Otherwise create it.
        try:
            subprocess.check_output(['docker', 'volume', 'inspect', self.volume_name])
        finally:
            self.run_command('docker volume create', ['docker', 'volume', 'create', self.volume_name])

    def start_container(self):
        """Starts the docker container with correct mounts."""
        # Stop any previously started container.
        self.stop_container(ignore_error=True)

        # Create volume and create mount string
        self._create_volume_if_needed()
        mount_output_volume = 'type=volume,src={},dst=/root/.floss'.format(self.volume_name)

        # Mount the source directory
        mount_src_dir = 'type=bind,src={},dst=/root/src'.format(self.rootdir)

        # Run the docker image. It will run `tail` indefinitely so the container
        # doesn't close and we can run `docker exec` on it.
        self.run_command('docker run', [
            'docker', 'run', '--name', self.container_name, '--mount', mount_output_volume, '--mount', mount_src_dir,
            '-d', self.image_tag, 'tail', '-f', '/dev/null'
        ])

    def stop_container(self, ignore_error=False):
        """Stops the docker container for build."""
        self.run_command('docker stop', ['docker', 'stop', '-t', '1', self.container_name], ignore_rc=ignore_error)
        self.run_command('docker rm', ['docker', 'rm', self.container_name], ignore_rc=ignore_error)

    def do_build(self):
        """Runs the basic build commands."""
        # Start container before building
        self.start_container()

        # Run all commands
        for i, cmd in enumerate(self.BUILD_COMMANDS):
            self.run_command('docker exec #{}'.format(i), ['docker', 'exec', '-it', self.container_name] + cmd)

        # Stop container before exiting
        self.stop_container()

    def print_do_build(self):
        """Prints the commands for building."""
        docker_exec = ['docker', 'exec', '-it', self.container_name]
        print('Normally, build would run the following commands: \n')
        for cmd in self.BUILD_COMMANDS:
            print(' '.join(docker_exec + cmd))

    def check_docker_runnable(self):
        try:
            subprocess.check_output(['docker', 'ps'], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            if 'denied' in err.output.decode('utf-8'):
                print('Run script as sudo')
            else:
                print('Unexpected error: {}'.format(err.output.decode('utf-8')))

            return False

        # No exception means docker is ok
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser('Builder Floss inside docker image.')
    parser.add_argument(
        '--only-start',
        action='store_true',
        default=False,
        help='Only start the container. Prints the commands it would have ran.')
    parser.add_argument('--only-stop', action='store_true', default=False, help='Only stop the container and exit.')
    parser.add_argument('--image-tag', default='floss:latest', help='Docker image to use to build.')
    parser.add_argument('--volume-tag', default='floss-out', help='Name of volume to use.')
    args = parser.parse_args()

    # cwd should be set to same directory as this script (that's where Dockerfile
    # is kept).
    workdir = os.path.dirname(os.path.abspath(sys.argv[0]))
    rootdir = os.path.abspath(os.path.join(workdir, '../..'))

    fdr = FlossDockerRunner(workdir, rootdir, args.image_tag, args.volume_tag)

    # Make sure docker is runnable before continuing
    if fdr.check_docker_runnable():
        # Handle some flags
        if args.only_start:
            fdr.start_container()
            fdr.print_do_build()
        elif args.only_stop:
            fdr.stop_container()
        else:
            fdr.do_build()
