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

#include "service/adapter_state.h"
#include "service/ipc/binder/IBluetooth.h"

using namespace std;

using android::sp;

using ipc::binder::IBluetooth;

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

void PrintCommandStatus(bool status) {
  cout << COLOR_BOLDWHITE "Command status: " COLOR_OFF
       << (status ? (COLOR_GREEN "success") : (COLOR_RED "failure"))
       << COLOR_OFF << endl << endl;
}

void HandleDisable(IBluetooth* bt_iface) {
  PrintCommandStatus(bt_iface->Disable());
}

void HandleEnable(IBluetooth* bt_iface) {
  PrintCommandStatus(bt_iface->Enable());
}

void HandleGetState(IBluetooth* bt_iface) {
  bluetooth::AdapterState state = static_cast<bluetooth::AdapterState>(
      bt_iface->GetState());
  cout << COLOR_BOLDWHITE "Adapter state: " COLOR_OFF
       << COLOR_BOLDYELLOW << bluetooth::AdapterStateToString(state)
       << COLOR_OFF << endl << endl;
}

void HandleIsEnabled(IBluetooth* bt_iface) {
  bool enabled = bt_iface->IsEnabled();
  cout << COLOR_BOLDWHITE "Adapter enabled: " COLOR_OFF
       << (enabled ? "true" : "false") << endl
       << endl;
}

void HandleHelp(IBluetooth* bt_iface);

struct {
  string command;
  void (*func)(IBluetooth*);
  string help;
} kCommandMap[] = {
  { "help", HandleHelp, "\t\tDisplay this message" },
  { "disable", HandleDisable, "\t\tDisable Bluetooth" },
  { "enable", HandleEnable, "\t\tEnable Bluetooth" },
  { "get-state", HandleGetState, "\tGet the current adapter state" },
  { "is-enabled", HandleIsEnabled, "\tReturn if Bluetooth is enabled" },
  {},
};

void HandleHelp(IBluetooth* /* bt_iface */) {
  cout << endl;
  for (int i = 0; kCommandMap[i].func; i++)
    cout << "\t" << kCommandMap[i].command << kCommandMap[i].help << endl;
  cout << endl;
}

}  // namespace

int main() {
  sp<IBluetooth> bt_iface = IBluetooth::getClientInterface();
  if (!bt_iface.get()) {
    LOG(ERROR) << "Failed to obtain handle on IBluetooth";
    return EXIT_FAILURE;
  }

  cout << COLOR_BOLDWHITE << "Fluoride Command-Line Interface\n" << COLOR_OFF
       << endl
       << "Type \"help\" to see possible commands.\n"
       << endl;

  while (true) {
    string command;
    cout << COLOR_BLUE << "[FCLI] " << COLOR_OFF;
    getline(cin, command);

    bool command_handled = false;
    for (int i = 0; kCommandMap[i].func && !command_handled; i++) {
      if (command == kCommandMap[i].command) {
        kCommandMap[i].func(bt_iface.get());
        command_handled = true;
      }
    }

    if (!command_handled)
      cout << "Unrecognized command: " << command << endl;
  }

  return EXIT_SUCCESS;
}
