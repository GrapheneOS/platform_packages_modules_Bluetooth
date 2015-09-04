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

#include <iostream>
#include <string>

#include <base/logging.h>
#include <base/macros.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>

#include "service/adapter_state.h"
#include "service/ipc/binder/IBluetooth.h"
#include "service/ipc/binder/IBluetoothCallback.h"
#include "service/low_energy_constants.h"

using namespace std;

using android::sp;

using ipc::binder::IBluetooth;
using ipc::binder::IBluetoothLowEnergy;

namespace {

#define COLOR_OFF         "\x1B[0m"
#define COLOR_RED         "\x1B[0;91m"
#define COLOR_GREEN       "\x1B[0;92m"
#define COLOR_YELLOW      "\x1B[0;93m"
#define COLOR_BLUE        "\x1B[0;94m"
#define COLOR_MAGENTA     "\x1B[0;95m"
#define COLOR_BOLDGRAY    "\x1B[1;30m"
#define COLOR_BOLDWHITE   "\x1B[1;37m"
#define COLOR_BOLDYELLOW  "\x1B[1;93m"

const char kCommandDisable[] = "disable";
const char kCommandEnable[] = "enable";
const char kCommandGetState[] = "get-state";
const char kCommandIsEnabled[] = "is-enabled";

#define CHECK_ARGS_COUNT(args, op, num, msg) \
  if (!(args.size() op num)) { \
    PrintError(msg); \
    return; \
  }
#define CHECK_NO_ARGS(args) \
  CHECK_ARGS_COUNT(args, ==, 0, "Expected no arguments")

// TODO(armansito): Clean up this code. Right now everything is in this
// monolithic file. We should organize this into different classes for command
// handling, console output/printing, callback handling, etc.
// (See http://b/23387611)

// Used to synchronize the printing of the command-line prompt and incoming
// Binder callbacks.
std::atomic_bool showing_prompt(false);

// The registered IBluetoothLowEnergy client handle. If |ble_registering| is
// true then an operation to register the client is in progress.
std::atomic_bool ble_registering(false);
std::atomic_int ble_client_if(0);

// True if the remote process has died and we should exit.
std::atomic_bool should_exit(false);

void PrintPrompt() {
  cout << COLOR_BLUE "[FCLI] " COLOR_OFF << flush;
}

void PrintError(const string& message) {
  cout << COLOR_RED << message << COLOR_OFF << endl;
}

class CLIBluetoothCallback : public ipc::binder::BnBluetoothCallback {
 public:
  CLIBluetoothCallback() = default;
  ~CLIBluetoothCallback() override = default;

  // IBluetoothCallback overrides:
  void OnBluetoothStateChange(
      bluetooth::AdapterState prev_state,
      bluetooth::AdapterState new_state) override {
    if (showing_prompt.load())
      cout << endl;
    cout << COLOR_BOLDWHITE "Adapter state changed: " COLOR_OFF
         << COLOR_MAGENTA << AdapterStateToString(prev_state) << COLOR_OFF
         << COLOR_BOLDWHITE " -> " COLOR_OFF
         << COLOR_BOLDYELLOW << AdapterStateToString(new_state) << COLOR_OFF
         << endl << endl;
    if (showing_prompt.load())
      PrintPrompt();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CLIBluetoothCallback);
};

class CLIBluetoothLowEnergyCallback
    : public ipc::binder::BnBluetoothLowEnergyCallback {
 public:
  CLIBluetoothLowEnergyCallback() = default;
  ~CLIBluetoothLowEnergyCallback() = default;

  // IBluetoothLowEnergyCallback overrides:
  void OnClientRegistered(int status, int client_if) override {
    if (showing_prompt.load())
      cout << endl;
    if (status != bluetooth::BLE_STATUS_SUCCESS) {
      PrintError("Failed to register BLE client");
    } else {
      ble_client_if = client_if;
      cout << COLOR_BOLDWHITE "Registered BLE client with ID: " COLOR_OFF
           << COLOR_GREEN << client_if << COLOR_OFF << endl << endl;
    }
    if (showing_prompt.load())
      PrintPrompt();

    ble_registering = false;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CLIBluetoothLowEnergyCallback);
};

void PrintCommandStatus(bool status) {
  cout << COLOR_BOLDWHITE "Command status: " COLOR_OFF
       << (status ? (COLOR_GREEN "success") : (COLOR_RED "failure"))
       << COLOR_OFF << endl << endl;
}

void PrintFieldAndValue(const string& field, const string& value) {
  cout << COLOR_BOLDWHITE << field << ": " << COLOR_BOLDYELLOW << value
       << COLOR_OFF << endl;
}

void PrintFieldAndBoolValue(const string& field, bool value) {
  PrintFieldAndValue(field, (value ? "true" : "false"));
}

void HandleDisable(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  PrintCommandStatus(bt_iface->Disable());
}

void HandleEnable(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  PrintCommandStatus(bt_iface->Enable());
}

void HandleGetState(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  bluetooth::AdapterState state = static_cast<bluetooth::AdapterState>(
      bt_iface->GetState());
  PrintFieldAndValue("Adapter state", bluetooth::AdapterStateToString(state));
}

void HandleIsEnabled(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  bool enabled = bt_iface->IsEnabled();
  PrintFieldAndBoolValue("Adapter enabled", enabled);
}

void HandleGetLocalAddress(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  string address = bt_iface->GetAddress();
  PrintFieldAndValue("Adapter address", address);
}

void HandleSetLocalName(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_ARGS_COUNT(args, >=, 1, "No name was given");

  std::string name;
  for (const auto& arg : args)
    name += arg + " ";

  base::TrimWhitespaceASCII(name, base::TRIM_TRAILING, &name);

  PrintCommandStatus(bt_iface->SetName(name));
}

void HandleGetLocalName(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);
  string name = bt_iface->GetName();
  PrintFieldAndValue("Adapter name", name);
}

void HandleAdapterInfo(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);

  cout << COLOR_BOLDWHITE "Adapter Properties: " COLOR_OFF << endl;

  PrintFieldAndValue("\tAddress", bt_iface->GetAddress());
  PrintFieldAndValue("\tState", bluetooth::AdapterStateToString(
      static_cast<bluetooth::AdapterState>(bt_iface->GetState())));
  PrintFieldAndValue("\tName", bt_iface->GetName());
  PrintFieldAndBoolValue("\tMulti-Adv. supported",
                         bt_iface->IsMultiAdvertisementSupported());
}

void HandleSupportsMultiAdv(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);

  bool status = bt_iface->IsMultiAdvertisementSupported();
  PrintFieldAndBoolValue("Multi-advertisement support", status);
}

void HandleRegisterBLE(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);

  if (ble_registering.load()) {
    PrintError("In progress");
    return;
  }

  if (ble_client_if.load()) {
    PrintError("Already registered");
    return;
  }

  sp<IBluetoothLowEnergy> ble_iface = bt_iface->GetLowEnergyInterface();
  if (!ble_iface.get()) {
    PrintError("Failed to obtain handle to Bluetooth Low Energy interface");
    return;
  }

  ble_iface->RegisterClient(new CLIBluetoothLowEnergyCallback());
  ble_registering = true;
  PrintCommandStatus(true);
}

void HandleUnregisterBLE(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);

  if (!ble_client_if.load()) {
    PrintError("Not registered");
    return;
  }

  sp<IBluetoothLowEnergy> ble_iface = bt_iface->GetLowEnergyInterface();
  if (!ble_iface.get()) {
    PrintError("Failed to obtain handle to Bluetooth Low Energy interface");
    return;
  }

  ble_iface->UnregisterClient(ble_client_if.load());
  ble_client_if = 0;
  PrintCommandStatus(true);
}

void HandleUnregisterAllBLE(IBluetooth* bt_iface, const vector<string>& args) {
  CHECK_NO_ARGS(args);

  sp<IBluetoothLowEnergy> ble_iface = bt_iface->GetLowEnergyInterface();
  if (!ble_iface.get()) {
    PrintError("Failed to obtain handle to Bluetooth Low Energy interface");
    return;
  }

  ble_iface->UnregisterAll();
  PrintCommandStatus(true);
}

void HandleHelp(IBluetooth* bt_iface, const vector<string>& args);

struct {
  string command;
  void (*func)(IBluetooth*, const vector<string>& args);
  string help;
} kCommandMap[] = {
  { "help", HandleHelp, "\t\t\tDisplay this message" },
  { "disable", HandleDisable, "\t\t\tDisable Bluetooth" },
  { "enable", HandleEnable, "\t\t\tEnable Bluetooth" },
  { "get-state", HandleGetState, "\t\tGet the current adapter state" },
  { "is-enabled", HandleIsEnabled, "\t\tReturn if Bluetooth is enabled" },
  { "get-local-address", HandleGetLocalAddress,
    "\tGet the local adapter address" },
  { "set-local-name", HandleSetLocalName, "\t\tSet the local adapter name" },
  { "get-local-name", HandleGetLocalName, "\t\tGet the local adapter name" },
  { "adapter-info", HandleAdapterInfo, "\t\tPrint adapter properties" },
  { "supports-multi-adv", HandleSupportsMultiAdv,
    "\tWhether multi-advertisement is currently supported" },
  { "register-ble", HandleRegisterBLE,
    "\t\tRegister with the Bluetooth Low Energy interface" },
  { "unregister-ble", HandleUnregisterBLE,
    "\t\tUnregister from the Bluetooth Low Energy interface" },
  { "unregister-all-ble", HandleUnregisterAllBLE,
    "\tUnregister all clients from the Bluetooth Low Energy interface" },
  {},
};

void HandleHelp(IBluetooth* /* bt_iface */, const vector<string>& /* args */) {
  cout << endl;
  for (int i = 0; kCommandMap[i].func; i++)
    cout << "\t" << kCommandMap[i].command << kCommandMap[i].help << endl;
  cout << endl;
}

}  // namespace

class BluetoothDeathRecipient : public android::IBinder::DeathRecipient {
 public:
  BluetoothDeathRecipient() = default;
  ~BluetoothDeathRecipient() override = default;

  // android::IBinder::DeathRecipient override:
  void binderDied(const android::wp<android::IBinder>& /* who */) override {
    if (showing_prompt.load())
      cout << endl;
    cout << COLOR_BOLDWHITE "The Bluetooth daemon has died" COLOR_OFF << endl;
    cout << "\nPress 'ENTER' to exit." << endl;
    if (showing_prompt.load())
      PrintPrompt();

    android::IPCThreadState::self()->stopProcess();
    should_exit = true;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(BluetoothDeathRecipient);
};

int main() {
  sp<IBluetooth> bt_iface = IBluetooth::getClientInterface();
  if (!bt_iface.get()) {
    LOG(ERROR) << "Failed to obtain handle on IBluetooth";
    return EXIT_FAILURE;
  }

  sp<BluetoothDeathRecipient> dr(new BluetoothDeathRecipient());
  if (android::IInterface::asBinder(bt_iface.get())->linkToDeath(dr) !=
      android::NO_ERROR) {
    LOG(ERROR) << "Failed to register DeathRecipient for IBluetooth";
    return EXIT_FAILURE;
  }

  // Initialize the Binder process thread pool. We have to set this up,
  // otherwise, incoming callbacks from IBluetoothCallback will block the main
  // thread (in other words, we have to do this as we are a "Binder server").
  android::ProcessState::self()->startThreadPool();

  // Register Adapter state-change callback
  sp<CLIBluetoothCallback> callback = new CLIBluetoothCallback();
  bt_iface->RegisterCallback(callback);

  cout << COLOR_BOLDWHITE << "Fluoride Command-Line Interface\n" << COLOR_OFF
       << endl
       << "Type \"help\" to see possible commands.\n"
       << endl;

  while (true) {
    string command;

    PrintPrompt();

    showing_prompt = true;
    getline(cin, command);
    showing_prompt = false;

    if (should_exit.load())
      return EXIT_SUCCESS;

    vector<string> args;
    base::SplitString(command, ' ', &args);

    if (args.empty())
      continue;

    // The first argument is the command while the remaning are what we pass to
    // the handler functions.
    command = args[0];
    args.erase(args.begin());

    bool command_handled = false;
    for (int i = 0; kCommandMap[i].func && !command_handled; i++) {
      if (command == kCommandMap[i].command) {
        kCommandMap[i].func(bt_iface.get(), args);
        command_handled = true;
      }
    }

    if (!command_handled)
      cout << "Unrecognized command: " << command << endl;
  }

  return EXIT_SUCCESS;
}
