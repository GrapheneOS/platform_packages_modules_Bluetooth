#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "base.h"
#include "support/gatt.h"
#include "support/callbacks.h"

bt_uuid_t app_uuid;

static void assign_random_app_uuid(bt_uuid_t *uuid) {
  srand(42);
  for (int i = 0; i < 16; ++i) {
    uuid->uu[i] = (uint8_t) (rand() % 256);
  }
}

bool gatt_client_register() {
  TASSERT(gatt_interface != NULL, "Null GATT interface.");

  // Registers gatt client.
  assign_random_app_uuid(&app_uuid);
  CALL_AND_WAIT(gatt_interface->client->register_client(&app_uuid), btgattc_register_app_cb);
  TASSERT(gatt_get_status() == BT_STATUS_SUCCESS, "Error registering GATT client app callback.");

  // Unregisters gatt client. No callback is expected.
  gatt_interface->client->unregister_client(gatt_get_client_interface());

  return true;
}

bool gatt_client_scan() {
  TASSERT(gatt_interface != NULL, "Null GATT interface.");

  // Starts BLE scan. NB: This test assumes there is a BLE beacon advertising nearby.
  CALL_AND_WAIT(gatt_interface->client->scan(true), btgattc_scan_result_cb);

  // Ends BLE scan. No callback is expected.
  gatt_interface->client->scan(false);

  return true;
}

bool gatt_client_advertise() {
  TASSERT(gatt_interface != NULL, "Null GATT interface.");

  // Registers a new client app.
  assign_random_app_uuid(&app_uuid);
  CALL_AND_WAIT(gatt_interface->client->register_client(&app_uuid), btgattc_register_app_cb);
  TASSERT(gatt_get_status() == BT_STATUS_SUCCESS, "Error registering GATT client app callback.");

  // Starts advertising.
  CALL_AND_WAIT(gatt_interface->client->listen(gatt_get_client_interface(), true), btgattc_advertise_cb);
  TASSERT(gatt_get_status() == BT_STATUS_SUCCESS, "Error starting BLE advertisement.");

  // Stops advertising.
  CALL_AND_WAIT(gatt_interface->client->listen(gatt_get_client_interface(), false), btgattc_advertise_cb);
  TASSERT(gatt_get_status() == BT_STATUS_SUCCESS, "Error stopping BLE advertisement.");

  // Unregisters gatt server. No callback is expected.
  gatt_interface->client->unregister_client(gatt_get_client_interface());

  return true;
}

bool gatt_server_register() {
  TASSERT(gatt_interface != NULL, "Null GATT interface.");

  // Registers gatt server
  assign_random_app_uuid(&app_uuid);
  CALL_AND_WAIT(gatt_interface->server->register_server(&app_uuid), btgatts_register_app_cb);
  TASSERT(gatt_get_status() == BT_STATUS_SUCCESS, "Error registering GATT server app callback.");

  // Unregisters gatt server. No callback is expected.
  gatt_interface->server->unregister_server(gatt_get_server_interface());
  return true;
}