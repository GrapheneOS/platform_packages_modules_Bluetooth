#
# Copyright 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Script for sending testing parameters and commands to a Bluetooth device.

This script provides a simple shell interface for sending data at run-time to a
Bluetooth device. It is intended to be used in tandem with the test vendor
library project.

Usage:
  Option A: Script
    1. Run build_and_run.sh in scripts/ with the --test-channel flag set and the
    port to use for the test channel.
  Option B: Manual
    1. Choose a port to use for the test channel. Use 'adb forward tcp:<port>
    tcp:<port>' to forward the port to the device.
    2. In a separate shell, build and push the test vendor library to the device
    using the script mentioned in option A (i.e. without the --test-channel flag
    set).
    3. Once logcat has started, turn Bluetooth on from the device.
    4. Run this program, in the shell from step 1, with address 'localhost' and
    the port, also from step 1, as arguments.
"""

#!/usr/bin/env python

import cmd
import socket
import struct
import sys

class Connection(object):
  """Simple wrapper class for a socket object.

  Attributes:
    socket: The underlying socket created for the specified address and port.
  """

  def __init__(self, address, port):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._socket.connect((address, port))

  def close(self):
    self._socket.close()

  def send(self, data):
    self._socket.send(data)

class TestChannel(cmd.Cmd):
  """Shell for sending test channel data to controller.

  Manages the connection for the test channel to the controller and defines a
  set of commands the user can send to the controller as well. These commands
  are processed parallel to commands sent from the device stack and used to
  provide additional debugging/testing capabilities.

  Attributes:
    connection: The communication channel to send data to the controller.
  """

  def __init__(self, address, port):
    print 'Type \'help\' for more information.'
    cmd.Cmd.__init__(self)
    self._connection = Connection(address, port)

  def do_hci_reset(self, arg):
    """Sends an HCIReset command to the controller."""
    self._connection.send(struct.pack('4b', 1, 3, 0xC, 0))

  def do_quit(self, arg):
    """Exits the test channel."""
    self._connection.close()
    print 'Goodbye.'
    return True

def main(argv):
  if len(argv) != 3:
    print 'Usage: python test_channel.py [address] [port]'
    return
  try:
    address = str(argv[1])
    port = int(argv[2])
  except ValueError:
    print 'Error parsing address or port.'
  else:
    try:
      test_channel = TestChannel(address, port)
    except socket.error, e:
      print 'Error connecting to socket: %s' % e
    except:
      print 'Error creating test channel (check arguments).'
    else:
      test_channel.prompt = '$ '
      test_channel.cmdloop()

if __name__ == '__main__':
  main(sys.argv)
