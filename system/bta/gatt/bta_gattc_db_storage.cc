/******************************************************************************
 *
 *  Copyright 2022 The Android Open Source Project
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

#include "bta/gatt/bta_gattc_int.h"

using gatt::StoredAttribute;

#define GATT_CACHE_PREFIX "/data/misc/bluetooth/gatt_cache_"
#define GATT_CACHE_VERSION 6

static void bta_gattc_generate_cache_file_name(char* buffer, size_t buffer_len,
                                               const RawAddress& bda) {
  snprintf(buffer, buffer_len, "%s%02x%02x%02x%02x%02x%02x", GATT_CACHE_PREFIX,
           bda.address[0], bda.address[1], bda.address[2], bda.address[3],
           bda.address[4], bda.address[5]);
}

/*******************************************************************************
 *
 * Function         bta_gattc_cache_load
 *
 * Description      Load GATT cache from storage for server.
 *
 * Parameter        p_srcb: pointer to server cache, that will
 *                          be filled from storage
 * Returns          true on success, false otherwise
 *
 ******************************************************************************/
bool bta_gattc_cache_load(tBTA_GATTC_SERV* p_srcb) {
  char fname[255] = {0};
  bta_gattc_generate_cache_file_name(fname, sizeof(fname), p_srcb->server_bda);

  FILE* fd = fopen(fname, "rb");
  if (!fd) {
    LOG(ERROR) << __func__ << ": can't open GATT cache file " << fname
               << " for reading, error: " << strerror(errno);
    return false;
  }

  uint16_t cache_ver = 0;
  bool success = false;
  uint16_t num_attr = 0;

  if (fread(&cache_ver, sizeof(uint16_t), 1, fd) != 1) {
    LOG(ERROR) << __func__ << ": can't read GATT cache version from: " << fname;
    goto done;
  }

  if (cache_ver != GATT_CACHE_VERSION) {
    LOG(ERROR) << __func__ << ": wrong GATT cache version: " << fname;
    goto done;
  }

  if (fread(&num_attr, sizeof(uint16_t), 1, fd) != 1) {
    LOG(ERROR) << __func__
               << ": can't read number of GATT attributes: " << fname;
    goto done;
  }

  {
    std::vector<StoredAttribute> attr(num_attr);

    if (fread(attr.data(), sizeof(StoredAttribute), num_attr, fd) != num_attr) {
      LOG(ERROR) << __func__ << "s: can't read GATT attributes: " << fname;
      goto done;
    }

    p_srcb->gatt_database = gatt::Database::Deserialize(attr, &success);
  }

done:
  fclose(fd);
  return success;
}

/*******************************************************************************
 *
 * Function         bta_gattc_cache_write
 *
 * Description      This callout function is executed by GATT when a server
 *                  cache is available to save.
 *
 * Parameter        server_bda: server bd address of this cache belongs to
 *                  attr: attributes to save.
 * Returns
 *
 ******************************************************************************/
void bta_gattc_cache_write(const RawAddress& server_bda,
                           const std::vector<StoredAttribute>& attr) {
  char fname[255] = {0};
  bta_gattc_generate_cache_file_name(fname, sizeof(fname), server_bda);

  FILE* fd = fopen(fname, "wb");
  if (!fd) {
    LOG(ERROR) << __func__
               << ": can't open GATT cache file for writing: " << fname;
    return;
  }

  uint16_t cache_ver = GATT_CACHE_VERSION;
  if (fwrite(&cache_ver, sizeof(uint16_t), 1, fd) != 1) {
    LOG(ERROR) << __func__ << ": can't write GATT cache version: " << fname;
    fclose(fd);
    return;
  }

  uint16_t num_attr = attr.size();
  if (fwrite(&num_attr, sizeof(uint16_t), 1, fd) != 1) {
    LOG(ERROR) << __func__
               << ": can't write GATT cache attribute count: " << fname;
    fclose(fd);
    return;
  }

  if (fwrite(attr.data(), sizeof(StoredAttribute), num_attr, fd) != num_attr) {
    LOG(ERROR) << __func__ << ": can't write GATT cache attributes: " << fname;
    fclose(fd);
    return;
  }

  fclose(fd);
}

/*******************************************************************************
 *
 * Function         bta_gattc_cache_reset
 *
 * Description      This callout function is executed by GATTC to reset cache in
 *                  application
 *
 * Parameter        server_bda: server bd address of this cache belongs to
 *
 * Returns          void.
 *
 ******************************************************************************/
void bta_gattc_cache_reset(const RawAddress& server_bda) {
  VLOG(1) << __func__;
  char fname[255] = {0};
  bta_gattc_generate_cache_file_name(fname, sizeof(fname), server_bda);
  unlink(fname);
}
