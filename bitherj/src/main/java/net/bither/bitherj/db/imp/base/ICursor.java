/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.db.imp.base;

public interface ICursor {
    int getCount();

//    int getPosition();

//    boolean move(int var1);

//    boolean moveToPosition(int var1);
//
//    boolean moveToFirst();
//
//    boolean moveToLast();

    boolean moveToNext();

//    boolean moveToPrevious();

//    boolean isFirst();
//
//    boolean isLast();
//
//    boolean isBeforeFirst();
//
//    boolean isAfterLast();

    int getColumnIndex(String var1);

    int getColumnIndexOrThrow(String var1) throws IllegalArgumentException;

//    String getColumnName(int var1);
//
//    String[] getColumnNames();
//
//    int getColumnCount();

    byte[] getBlob(int var1);

    String getString(int var1);

    short getShort(int var1);

    int getInt(int var1);

    long getLong(int var1);

    float getFloat(int var1);

    double getDouble(int var1);

    int getType(int var1);

    boolean isNull(int var1);

    void close();

    boolean isClosed();
}
