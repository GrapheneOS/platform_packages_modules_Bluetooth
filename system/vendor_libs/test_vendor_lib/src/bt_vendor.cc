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

#include <unistd.h>
#include <memory>

#include <base/logging.h>
#include "osi/include/log.h"
#include "vendor_manager.h"

namespace test_vendor_lib {

class BtVendor {
 public:
  // Initializes vendor manager for test controller. |p_cb| are the callbacks to
  // be in TestVendorOp(). |local_bdaddr| points to the address of the Bluetooth
  // device. Returns 0 on success, -1 on error.
  static int Initialize(const bt_vendor_callbacks_t* p_cb,
                        unsigned char* /* local_bdaddr */) {
    LOG_INFO(LOG_TAG, "Initializing test controller.");
    CHECK(p_cb);

    vendor_callbacks_ = *p_cb;

    vendor_manager_.reset(new VendorManager());
    return vendor_manager_->Initialize() ? 0 : 1;
  }

  // Vendor specific operations. |opcode| is the opcode for Bluedroid's vendor
  // op definitions. |param| points to operation specific arguments. Return
  // value is dependent on the operation invoked, or -1 on error.
  static int Op(bt_vendor_opcode_t opcode, void* param) {
    LOG_INFO(LOG_TAG, "Opcode received in vendor library: %d", opcode);

    switch (opcode) {
      case BT_VND_OP_POWER_CTRL: {
        LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_POWER_CTRL");
        int* state = static_cast<int*>(param);
        if (*state == BT_VND_PWR_OFF)
          LOG_INFO(LOG_TAG, "Turning Bluetooth off.");
        else if (*state == BT_VND_PWR_ON)
          LOG_INFO(LOG_TAG, "Turning Bluetooth on.");
        return 0;
      }

      // Give the HCI its fd to communicate with the HciTransport.
      case BT_VND_OP_USERIAL_OPEN: {
        LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_USERIAL_OPEN");
        CHECK(vendor_manager_);
        int* fd_list = static_cast<int*>(param);
        fd_list[0] = vendor_manager_->GetHciFd();
        LOG_INFO(LOG_TAG, "Setting HCI's fd to: %d", fd_list[0]);
        return 1;
      }

      // Close the HCI's file descriptor.
      case BT_VND_OP_USERIAL_CLOSE:
        LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_USERIAL_CLOSE");
        CHECK(vendor_manager_);
        LOG_INFO(LOG_TAG, "Closing HCI's fd (fd: %d)",
                 vendor_manager_->GetHciFd());
        vendor_manager_->CloseHciFd();
        return 1;

      case BT_VND_OP_FW_CFG:
        LOG_INFO(LOG_TAG, "BT_VND_OP_FW_CFG (Does nothing)");
        vendor_callbacks_.fwcfg_cb(BT_VND_OP_RESULT_SUCCESS);
        return 0;

      case BT_VND_OP_SCO_CFG:
        LOG_INFO(LOG_TAG, "BT_VND_OP_SCO_CFG (Does nothing)");
        vendor_callbacks_.scocfg_cb(BT_VND_OP_RESULT_SUCCESS);
        return 0;

      case BT_VND_OP_GET_LPM_IDLE_TIMEOUT:
        LOG_INFO(LOG_TAG, "Doing op: BT_VND_OP_SCO_CFG");
        *((uint32_t*)param) = 1000;
        return 0;

      case BT_VND_OP_LPM_SET_MODE:
        LOG_INFO(LOG_TAG, "BT_VND_OP_LPM_SET_MODE (Does nothing)");
        vendor_callbacks_.lpm_cb(BT_VND_OP_RESULT_SUCCESS);
        return 0;

      case BT_VND_OP_LPM_WAKE_SET_STATE:
        LOG_INFO(LOG_TAG, "BT_VND_OP_LPM_WAKE_SET_STATE (Does nothing)");
        return 0;

      case BT_VND_OP_SET_AUDIO_STATE:
        LOG_INFO(LOG_TAG, "BT_VND_OP_SET_AUDIO_STATE (Does nothing)");
        return 0;

      case BT_VND_OP_EPILOG:
        LOG_INFO(LOG_TAG, "BT_VND_OP_EPILOG (Does nothing)");
        vendor_callbacks_.epilog_cb(BT_VND_OP_RESULT_SUCCESS);
        return 0;

      default:
        LOG_INFO(LOG_TAG, "Op not recognized.");
        return -1;
    }
    return 0;
  }

  // Closes the vendor interface and cleans up the global vendor manager object.
  static void CleanUp(void) {
    LOG_INFO(LOG_TAG, "Cleaning up vendor library.");
    CHECK(vendor_manager_);
    vendor_manager_->CleanUp();
    vendor_manager_.reset();
  }

 private:
  static std::unique_ptr<VendorManager> vendor_manager_;
  static bt_vendor_callbacks_t vendor_callbacks_;
};

// Definition of static class members
std::unique_ptr<VendorManager> BtVendor::vendor_manager_;
bt_vendor_callbacks_t BtVendor::vendor_callbacks_;

}  // namespace test_vendor_lib

// Entry point of DLib.
EXPORT_SYMBOL
const bt_vendor_interface_t BLUETOOTH_VENDOR_LIB_INTERFACE = {
    sizeof(bt_vendor_interface_t), test_vendor_lib::BtVendor::Initialize,
    test_vendor_lib::BtVendor::Op, test_vendor_lib::BtVendor::CleanUp};
