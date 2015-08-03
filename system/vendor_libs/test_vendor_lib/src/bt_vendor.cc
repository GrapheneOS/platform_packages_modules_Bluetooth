//
// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#define LOG_TAG "bt_vendor"

#include "hci/include/bt_vendor_lib.h"
#include "vendor_libs/test_vendor_lib/include/bredr_controller.h"
#include "vendor_libs/test_vendor_lib/include/hci_handler.h"
#include "vendor_libs/test_vendor_lib/include/hci_transport.h"

#include <pthread.h>

extern "C" {
#include "osi/include/log.h"

#include <assert.h>
#include <unistd.h>
}  // extern "C"

namespace {
bt_vendor_callbacks_t* vendor_callbacks;

// Wrapper for kicking off HciTransport listening on its own thread.
void* ListenEntryPoint(void* context) {
  while ((static_cast<test_vendor_lib::HciTransport*>(context))->Listen());
  LOG_INFO(LOG_TAG, "HciTransport stopped listening.");
  return NULL;
}
}  // namespace

namespace test_vendor_lib {

// Initializes event handler for test device. |p_cb| are the callbacks to be
// used by event handler. |local_bdaddr| points to the address of the Bluetooth
// device. Returns 0 on success, -1 on error.
static int TestVendorInitialize(const bt_vendor_callbacks_t* p_cb,
                          unsigned char* /* local_bdaddr */) {
  LOG_INFO(LOG_TAG, "Initializing test controller.");

  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(p_cb);
  vendor_callbacks = const_cast<bt_vendor_callbacks_t*>(p_cb);

  // Initialize global objects. The order of initialization does not matter,
  // however all global objects should be initialized before any other work is
  // done by the vendor library.
  test_vendor_lib::HciTransport::Initialize();
  test_vendor_lib::HciHandler::Initialize();
  test_vendor_lib::BREDRController::Initialize();

  // Create the connection to be used for communication between the HCI and
  // the HciTransport object.
  HciTransport* transporter = HciTransport::Get();
  if (!transporter->Connect()) {
    LOG_ERROR(LOG_TAG, "Error connecting HciTransport object to HCI.");
    return -1;
  }

  // Start HciTransport listening on its own thread.
  pthread_t transporter_thread;
  pthread_create(&transporter_thread, NULL, &ListenEntryPoint, transporter);
  return 0;
}

// Vendor specific operations. |opcode| is the opcode for Bluedroid's vendor op
// definitions. |param| points to operation specific arguments. Return value is
// dependent on the operation invoked, or -1 on error.
static int TestVendorOp(bt_vendor_opcode_t opcode, void* param) {
  LOG_INFO(LOG_TAG, "Opcode received in vendor library: %d", opcode);

  HciTransport* transporter = HciTransport::Get();
  if (!transporter) {
    LOG_ERROR(LOG_TAG, "HciTransport was not initialized");
    return -1;
  }

  switch (opcode) {
    case BT_VND_OP_POWER_CTRL: {
      LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_POWER_CTRL");
      int* state = static_cast<int*>(param);
      if (*state == BT_VND_PWR_OFF) {
        LOG_INFO(LOG_TAG, "Turning Bluetooth off.");
      } else if (*state == BT_VND_PWR_ON) {
        LOG_INFO(LOG_TAG, "Turning Bluetooth on.");
      }
      return 0;
    }

    // Give the HCI its fd to communicate with the HciTransport.
    case BT_VND_OP_USERIAL_OPEN: {
      LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_USERIAL_OPEN");
      int* transporter_fd = static_cast<int*>(param);
      transporter_fd[0] = transporter->GetHciFd();
      LOG_INFO(LOG_TAG, "Setting HCI's fd to: %d", transporter_fd[0]);
      return 1;
    }

    // Close the HCI's file descriptor.
    case BT_VND_OP_USERIAL_CLOSE:
      LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_USERIAL_CLOSE");
      LOG_INFO(LOG_TAG, "Closing HCI's fd (fd: %d)", transporter->GetHciFd());
      close(transporter->GetHciFd());
      return 1;

    case BT_VND_OP_FW_CFG:
      LOG_INFO(LOG_TAG, "Unsupported op: BT_VND_OP_FW_CFG");
      vendor_callbacks->fwcfg_cb(BT_VND_OP_RESULT_FAIL);
      return -1;

    default:
      LOG_INFO(LOG_TAG, "Op not recognized.");
      return -1;
  }
  return 0;
}

// Closes the vendor interface and destroys global objects.
static void TestVendorCleanUp(void) {
  LOG_INFO(LOG_TAG, "Cleaning up vendor library.");
  test_vendor_lib::BREDRController::CleanUp();
  test_vendor_lib::HciHandler::CleanUp();
  test_vendor_lib::HciTransport::CleanUp();
}

}  // namespace test_vendor_lib

// Entry point of DLib.
const bt_vendor_interface_t BLUETOOTH_VENDOR_LIB_INTERFACE = {
  sizeof(bt_vendor_interface_t),
  test_vendor_lib::TestVendorInitialize,
  test_vendor_lib::TestVendorOp,
  test_vendor_lib::TestVendorCleanUp
};
