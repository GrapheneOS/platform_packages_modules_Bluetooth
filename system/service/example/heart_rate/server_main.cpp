//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>

#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>

#include "service/example/heart_rate/heart_rate_server.h"
#include "service/ipc/binder/IBluetooth.h"

using android::sp;
using ipc::binder::IBluetooth;

std::atomic_bool g_keep_running(true);

class BluetoothDeathRecipient : public android::IBinder::DeathRecipient {
 public:
  BluetoothDeathRecipient() = default;
  ~BluetoothDeathRecipient() override = default;

  // android::IBinder::DeathRecipient override:
  void binderDied(const android::wp<android::IBinder>& /* who */) override {
    LOG(ERROR) << "The Bluetooth daemon has died. Aborting.";
    g_keep_running = false;
    android::IPCThreadState::self()->stopProcess();
  }
};

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  logging::LoggingSettings log_settings;

  if (!logging::InitLogging(log_settings)) {
    LOG(ERROR) << "Failed to set up logging";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Starting GATT Heart Rate Service sample";

  sp<IBluetooth> bluetooth = IBluetooth::getClientInterface();
  if (!bluetooth.get()) {
    LOG(ERROR) << "Failed to obtain a handle on IBluetooth";
    return EXIT_FAILURE;
  }

  if (!bluetooth->IsEnabled()) {
    LOG(ERROR) << "Bluetooth is not enabled";
    return EXIT_FAILURE;
  }

  sp<BluetoothDeathRecipient> dr(new BluetoothDeathRecipient());
  if (android::IInterface::asBinder(bluetooth.get())->linkToDeath(dr) !=
      android::NO_ERROR) {
    LOG(ERROR) << "Failed to register DeathRecipient for IBluetooth";
    return EXIT_FAILURE;
  }

  // Initialize the Binder process thread pool. We have to set this up,
  // otherwise, incoming callbacks from the Bluetooth daemon would block the
  // main thread (in other words, we have to do this as we are a "Binder
  // server").
  android::ProcessState::self()->startThreadPool();

  auto callback = [&](bool success) {
    if (success) {
      LOG(INFO) << "Heart Rate service started successfully";
      return;
    }

    LOG(ERROR) << "Starting Heart Rate server failed asynchronously";
    g_keep_running = false;
  };

  std::unique_ptr<heart_rate::HeartRateServer> hr(
      new heart_rate::HeartRateServer(bluetooth));
  if (!hr->Run(callback)) {
    LOG(ERROR) << "Failed to start Heart Rate server";
    return EXIT_FAILURE;
  }

  // TODO(armansito): Use a message loop as we'll have scheduled notifications
  // for heart rate.
  while (g_keep_running.load());

  LOG(INFO) << "Exiting";
  return EXIT_SUCCESS;
}
