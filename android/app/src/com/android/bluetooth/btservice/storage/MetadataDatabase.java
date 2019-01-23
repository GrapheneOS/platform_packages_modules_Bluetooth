/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.bluetooth.btservice;

import androidx.room.Database;
import androidx.room.RoomDatabase;

import java.util.List;

@Database(entities = {Metadata.class}, exportSchema = false, version = 100)
abstract class MetadataDatabase extends RoomDatabase {
    public static final String DATABASE_NAME = "bluetooth_db";

    protected abstract MetadataDao mMetadataDao();

    public void insert(Metadata... metadata) {
        mMetadataDao().insert(metadata);
    }

    public List<Metadata> load() {
        return mMetadataDao().load();
    }

    public void delete(String address) {
        mMetadataDao().delete(address);
    }

    public void deleteAll() {
        mMetadataDao().deleteAll();
    }
}
