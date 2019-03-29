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

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.room.migration.Migration;
import androidx.sqlite.db.SupportSQLiteDatabase;

import java.util.List;

/**
 * MetadataDatabase is a Room database stores Bluetooth persistence data
 */
@Database(entities = {Metadata.class}, exportSchema = false, version = 101)
public abstract class MetadataDatabase extends RoomDatabase {
    /**
     * The database file name
     */
    public static final String DATABASE_NAME = "bluetooth_db";

    protected abstract MetadataDao mMetadataDao();

    /**
     * Create a {@link MetadataDatabase} database with migrations
     *
     * @param context the Context to create database
     * @return the created {@link MetadataDatabase}
     */
    public static MetadataDatabase createDatabase(Context context) {
        return Room.databaseBuilder(context,
                MetadataDatabase.class, DATABASE_NAME)
                .addMigrations(MIGRATION_100_101)
                .build();
    }

    /**
     * Create a {@link MetadataDatabase} database without migration, database
     * would be reset if any load failure happens
     *
     * @param context the Context to create database
     * @return the created {@link MetadataDatabase}
     */
    public static MetadataDatabase createDatabaseWithoutMigration(Context context) {
        return Room.databaseBuilder(context,
                MetadataDatabase.class, DATABASE_NAME)
                .fallbackToDestructiveMigration()
                .build();
    }

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

    private static final Migration MIGRATION_100_101 = new Migration(100, 101) {
        @Override
        public void migrate(SupportSQLiteDatabase database) {
                database.execSQL("ALTER TABLE metadata ADD COLUMN `pbap_client_priority` INTEGER");
        }
    };
}
