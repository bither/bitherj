package net.bither.bitherj.db.imp.base;

public interface ICursor {
    int getCount();

//    int getPosition();

    boolean move(int var1);

    boolean moveToPosition(int var1);

    boolean moveToFirst();

    boolean moveToLast();

    boolean moveToNext();

    boolean moveToPrevious();

    boolean isFirst();

    boolean isLast();

    boolean isBeforeFirst();

    boolean isAfterLast();

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
