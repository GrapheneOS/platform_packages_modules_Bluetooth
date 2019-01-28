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

package com.android.bluetooth.btservice.storage;

import androidx.room.Database;
import androidx.room.RoomDatabase;

import java.util.List;

/**
 * MetadataDatabase is a Room database stores Bluetooth persistence data
 */
@Database(entities = {Metadata.class}, exportSchema = false, version = 100)
public abstract class MetadataDatabase extends RoomDatabase {
    /**
     * The database file name
     */
    public static final String DATABASE_NAME = "bluetooth_db";

    protected abstract MetadataDao mMetadataDao();

    /**
     * Insert a {@link Metadata} to database
     *
     * @param metadata the data wish to put into storage
     */
    public void insert(Metadata... metadata) {
        mMetadataDao().insert(metadata);
    }

    /**
     * Load all data from database as a {@link List} of {@link Metadata}
     *
     * @return a {@link List} of {@link Metadata}
     */
    public List<Metadata> load() {
        return mMetadataDao().load();
    }

    /**
     * Delete one of the {@link Metadata} contains in database
     *
     * @param address the address of Metadata to delete
     */
    public void delete(String address) {
        mMetadataDao().delete(address);
    }

    /**
     * Clear database.
     */
    public void deleteAll() {
        mMetadataDao().deleteAll();
    }
}
