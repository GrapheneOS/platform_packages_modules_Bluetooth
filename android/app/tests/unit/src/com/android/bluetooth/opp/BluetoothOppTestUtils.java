/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.bluetooth.opp;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;

import android.database.Cursor;

import org.mockito.internal.util.MockUtil;

import java.util.List;
import java.util.Objects;

public class BluetoothOppTestUtils {

    /**
     * A class containing the data to be return by a cursor. Intended to be use with setUpMockCursor
     *
     * @attr columnName is name of column to be used as a parameter in cursor.getColumnIndexOrThrow
     * @attr mIndex should be returned from cursor.getColumnIndexOrThrow
     * @attr mValue should be returned from cursor.getInt() or cursor.getString() or
     * cursor.getLong()
     */
    public static class CursorMockData {
        public final String mColumnName;
        public final int mColumnIndex;
        public final Object mValue;

        public CursorMockData(String columnName, int index, Object value) {
            mColumnName = columnName;
            mColumnIndex = index;
            mValue = value;
        }
    }

    /**
     * Set up a mock single-row Cursor that work for common use cases in the OPP package.
     * It mocks the database column index and value of the cell in that column of the current row
     *
     * <pre>
     *  cursorMockDataList.add(
     *     new CursorMockData(BluetoothShare.DIRECTION, 2, BluetoothShare.DIRECTION_INBOUND
     *     );
     *     ...
     *  setUpMockCursor(cursor, cursorMockDataList);
     *  // This will return 2
     *  int index = cursor.getColumnIndexOrThrow(BluetoothShare.DIRECTION);
     *  int direction = cursor.getInt(index); // This will return BluetoothShare.DIRECTION_INBOUND
     * </pre>
     *
     * @param cursor a mock/spy cursor to be setup
     * @param cursorMockDataList a list representing what cursor will return
     */
    public static void setUpMockCursor(
            Cursor cursor, List<CursorMockData> cursorMockDataList) {
        assert(MockUtil.isMock(cursor));

        doAnswer(invocation -> {
            String name = invocation.getArgument(0);
            return cursorMockDataList.stream().filter(
                    mockCursorData -> Objects.equals(mockCursorData.mColumnName, name)
            ).findFirst().orElse(new CursorMockData("", -1, null)).mColumnIndex;
        }).when(cursor).getColumnIndexOrThrow(anyString());

        doAnswer(invocation -> {
            int index = invocation.getArgument(0);
            return cursorMockDataList.stream().filter(
                    mockCursorData -> mockCursorData.mColumnIndex == index
            ).findFirst().orElse(new CursorMockData("", -1, -1)).mValue;
        }).when(cursor).getInt(anyInt());

        doAnswer(invocation -> {
            int index = invocation.getArgument(0);
            return cursorMockDataList.stream().filter(
                    mockCursorData -> mockCursorData.mColumnIndex == index
            ).findFirst().orElse(new CursorMockData("", -1, -1)).mValue;
        }).when(cursor).getLong(anyInt());

        doAnswer(invocation -> {
            int index = invocation.getArgument(0);
            return cursorMockDataList.stream().filter(
                    mockCursorData -> mockCursorData.mColumnIndex == index
            ).findFirst().orElse(new CursorMockData("", -1, null)).mValue;
        }).when(cursor).getString(anyInt());
    }
}

