/******************************************************************************
 *
 *  Copyright (C) 2015 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
  #include "base.h"
  #include "btcore/include/bdaddr.h"
  #include "cases/cases.h"
  #include "osi/include/config.h"
  #include "support/callbacks.h"
  #include "support/hal.h"
  #include "support/gatt.h"
  #include "support/pan.h"
  #include "support/rfcomm.h"
}

static const char *CONFIG_FILE_PATH = "/data/misc/bluedroid/bt_config.conf";

const bt_interface_t *bt_interface;
bt_bdaddr_t bt_remote_bdaddr;

class CommsTest : public ::testing::Test {
    protected : CommsTest() { }
    ~CommsTest() { }
    virtual void SetUp() {
        callbacks_init();
    }
    virtual void TearDown() {
        callbacks_cleanup();
    }
};

void first_time_setup() {
    config_t *config = config_new(CONFIG_FILE_PATH);
    if (!config) {
        printf("Error: unable to open stack config file.\n");
        FAIL();
    }
    for (const config_section_node_t *node = config_section_begin(config); node != config_section_end(config); node = config_section_next(node)) {
        const char *name = config_section_name(node);
        if (config_has_key(config, name, "LinkKey") && string_to_bdaddr(name, &bt_remote_bdaddr)) {
            break;
        }
    }
    config_free(config);
    if (bdaddr_is_empty(&bt_remote_bdaddr)) {
        printf("Error: unable to find paired device in config file.\n");
        FAIL();
    } else if (!hal_open(callbacks_get_adapter_struct())) {
        printf("Unable to open Bluetooth HAL.\n");
        FAIL();
    } else if (!btsocket_init()) {
        printf("Unable to initialize Bluetooth sockets.\n");
        FAIL();
    } else if (!pan_init()) {
        printf("Unable to initialize PAN.\n");
        FAIL();
    } else if (!gatt_init()) {
        printf("Unable to initialize GATT.\n");
        FAIL();
    }
}

void setup() {
    CALL_AND_WAIT(bt_interface->enable(), adapter_state_changed);
}

void cleanup() {
    CALL_AND_WAIT(bt_interface->disable(), adapter_state_changed);
}

TEST_F(CommsTest, initial_setup) {
    first_time_setup();
}

TEST_F(CommsTest, adapter_enable_disable) {
    EXPECT_TRUE(sanity_suite[0].function());
}

TEST_F(CommsTest, adapter_repeated_enable_disable) {
    EXPECT_TRUE(sanity_suite[1].function());
}

TEST_F(CommsTest, adapter_set_name) {
    setup();
    EXPECT_TRUE(test_suite[0].function());
    cleanup();
}

TEST_F(CommsTest, adapter_get_name) {
    setup();
    EXPECT_TRUE(test_suite[1].function());
    cleanup();
}

TEST_F(CommsTest, adapter_start_discovery) {
    setup();
    EXPECT_TRUE(test_suite[2].function());
    cleanup();
}

TEST_F(CommsTest, adapter_cancel_discovery) {
    setup();
    EXPECT_TRUE(test_suite[3].function());
    cleanup();
}

TEST_F(CommsTest, rfcomm_connect) {
    setup();
    EXPECT_TRUE(test_suite[4].function());
    cleanup();
}

TEST_F(CommsTest, rfcomm_repeated_connect) {
    setup();
    EXPECT_TRUE(test_suite[5].function());
    cleanup();
}

TEST_F(CommsTest, pan_enable) {
    setup();
    EXPECT_TRUE(test_suite[6].function());
    cleanup();
}

TEST_F(CommsTest, pan_connect) {
    setup();
    EXPECT_TRUE(test_suite[7].function());
    cleanup();
}

TEST_F(CommsTest, pan_disconnect) {
    setup();
    EXPECT_TRUE(test_suite[8].function());
    cleanup();
}

TEST_F(CommsTest, gatt_client_register) {
    setup();
    EXPECT_TRUE(test_suite[9].function());
    cleanup();
}

TEST_F(CommsTest, gatt_client_scan) {
    setup();
    EXPECT_TRUE(test_suite[10].function());
    cleanup();
}

TEST_F(CommsTest, gatt_client_advertise) {
    setup();
    EXPECT_TRUE(test_suite[11].function());
    cleanup();
}

TEST_F(CommsTest, gatt_server_register) {
    setup();
    EXPECT_TRUE(test_suite[12].function());
    cleanup();
}

TEST_F(CommsTest, gatt_server_build) {
    setup();
    EXPECT_TRUE(test_suite[13].function());
    cleanup();
}
