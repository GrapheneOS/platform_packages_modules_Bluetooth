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

#include <assert.h>
#include "osi/include/allocator.h"
#include "btcore/include/property.h"
#include "btcore/include/bdaddr.h"
#include "btcore/include/device_class.h"

bt_property_t *property_copy_array(const bt_property_t *properties, size_t count) {
  assert(properties != NULL);
  bt_property_t *clone = osi_calloc(sizeof(bt_property_t) * count);
  if (!clone) {
    return NULL;
  }

  memcpy(&clone[0], &properties[0], sizeof(bt_property_t) * count);
  for (size_t i = 0; i < count; ++i) {
    clone[i].val = osi_calloc(clone[i].len);
    memcpy(clone[i].val, properties[i].val, clone[i].len);
  }

  return clone;
}

bt_property_t *property_copy(bt_property_t *dest, const bt_property_t *src) {
  assert(dest != NULL);
  assert(src != NULL);
  return (bt_property_t *)memcpy(dest, src, sizeof(bt_property_t));
}

bt_property_t *property_new_name(const char *name) {
  assert(name != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  bt_bdname_t *bdname = osi_calloc(sizeof(bt_bdname_t));
  assert(bdname != NULL);
  strlcpy((char *)bdname->name, name, sizeof(bdname->name));

  property->type = BT_PROPERTY_BDNAME;
  property->val = (void *)bdname;
  property->len = sizeof(bt_bdname_t);

  return property;
}

bt_property_t *property_new_addr(const bt_bdaddr_t *addr) {
  assert(addr != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  bt_bdaddr_t *bdaddr = osi_calloc(sizeof(bt_bdaddr_t));
  assert(bdaddr != NULL);
  bdaddr_copy(bdaddr, addr);

  property->type = BT_PROPERTY_BDADDR;
  property->val = (void *)bdaddr;
  property->len = sizeof(bt_bdaddr_t);

  return property;
}

bt_property_t *property_new_device_class(const bt_device_class_t *dc) {
  assert(dc != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  bt_device_class_t *device_class = osi_calloc(sizeof(bt_device_class_t));
  assert(device_class != NULL);
  device_class_copy(device_class, dc);

  property->type = BT_PROPERTY_CLASS_OF_DEVICE;
  property->val = (void *)device_class;
  property->len = sizeof(bt_device_class_t);

  return property;
}

bt_property_t *property_new_device_type(bt_device_type_t *type) {
  assert(type != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  bt_device_type_t *device_type = (bt_device_type_t *)osi_calloc(sizeof(bt_device_type_t));
  assert(device_type != NULL);
  *device_type = *type;

  property->type = BT_PROPERTY_TYPE_OF_DEVICE;
  property->val = (void *)device_type;
  property->len = sizeof(bt_device_type_t);

  return property;
}

bt_property_t *property_new_rssi(int8_t *rssi) {
  assert(rssi != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  int *val = (int *)osi_calloc(sizeof(rssi));
  assert(val != NULL);
  *val = *rssi;

  property->type = BT_PROPERTY_REMOTE_RSSI;
  property->val = (void *)val;
  property->len = sizeof(int);

  return property;
}

bt_property_t *property_new_discovery_timeout(uint32_t *timeout) {
  assert(timeout != NULL);

  bt_property_t *property = osi_calloc(sizeof(bt_property_t));
  assert(property != NULL);

  uint32_t *val = osi_calloc(sizeof(uint32_t));
  assert(val != NULL);
  *val = *timeout;

  property->type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT;
  property->val = val;
  property->len = sizeof(uint32_t);

  return property;
}

bt_property_t *property_new_scan_mode(bt_scan_mode_t scan_mode) {
  bt_scan_mode_t *val = osi_malloc(sizeof(bt_scan_mode_t));
  bt_property_t *property = osi_malloc(sizeof(bt_property_t));

  property->type = BT_PROPERTY_ADAPTER_SCAN_MODE;
  property->val = val;
  property->len = sizeof(bt_scan_mode_t);

  *val = scan_mode;

  return property;
}

// Warning: not thread safe.
const char *property_extract_name(const bt_property_t *property) {
  static char name[250] = { 0 };
  if (!property || property->type != BT_PROPERTY_BDNAME || !property->val) {
    return NULL;
  }

  strncpy(name, (const char *)((bt_bdname_t *)property->val)->name, property->len);
  name[sizeof(name) - 1] = '\0';

  return name;
}

const bt_bdaddr_t *property_extract_bdaddr(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_BDADDR || !property->val) {
    return NULL;
  }
  return (const bt_bdaddr_t *)property->val;
}

const bt_bdname_t *property_extract_bdname(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_BDNAME || !property->val) {
    return NULL;
  }
  return (const bt_bdname_t *)property->val;
}

const bt_device_class_t *property_extract_device_class(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_CLASS_OF_DEVICE || !property->val) {
    return 0;
  }
  return (const bt_device_class_t *)property->val;
}

const bt_device_type_t *property_extract_device_type(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_TYPE_OF_DEVICE || !property->val) {
    return NULL;
  }
  return (const bt_device_type_t*)property->val;
}

int32_t property_extract_remote_rssi(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_REMOTE_RSSI || !property->val) {
    return 0;
  }
  return *(const int32_t*)property->val;
}

const bt_uuid_t *property_extract_uuid(const bt_property_t *property) {
  if (!property || property->type != BT_PROPERTY_UUIDS || !property->val) {
    return NULL;
  }
  return (const bt_uuid_t *)property->val;
}

bool property_equals(const bt_property_t *p1, const bt_property_t *p2) {
  // Two null properties are not the same. May need to revisit that
  // decision when we have a test case that exercises that condition.
  if (!p1 || !p2 || p1->type != p2->type) {
    return false;
  }

  // Although the Bluetooth name is a 249-byte array, the implementation
  // treats it like a variable-length array with its size specified in the
  // property's `len` field. We special-case the equivalence of BDNAME
  // types here by truncating the larger, zero-padded name to its string
  // length and comparing against the shorter name.
  //
  // Note: it may be the case that both strings are zero-padded but that
  // hasn't come up yet so this implementation doesn't handle it.
  if (p1->type == BT_PROPERTY_BDNAME && p1->len != p2->len) {
    const bt_property_t *shorter = p1, *longer = p2;
    if (p1->len > p2->len) {
      shorter = p2;
      longer = p1;
    }
    return strlen((const char *)longer->val) == (size_t)shorter->len && !memcmp(longer->val, shorter->val, shorter->len);
  }

  return p1->len == p2->len && !memcmp(p1->val, p2->val, p1->len);
}

void property_free(bt_property_t *property) {
  property_free_array(property, 1);
}

void property_free_array(bt_property_t *properties, size_t count) {
  if (properties == NULL)
    return;

  for (size_t i = 0; i < count; ++i) {
    osi_free(properties[i].val);
  }

  osi_free(properties);
}
