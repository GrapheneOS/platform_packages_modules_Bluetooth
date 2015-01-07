/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
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

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include "osi/test/AllocationTestHarness.h"

extern "C" {
#include "btcore/include/device_class.h"
#include "btcore/include/property.h"
}  // "C"

class PropertyTest : public AllocationTestHarness {};

TEST_F(PropertyTest, device_class) {
  bt_device_class_t dc0 = {{ 0x01, 0x23, 0x45 }};
  bt_property_t *property = property_new_device_class(&dc0);

  const bt_device_class_t *dc1 = property_extract_device_class(property);
  int dc_int = device_class_to_int(dc1);
  EXPECT_EQ(0x452301, dc_int);

  property_free(property);
}
