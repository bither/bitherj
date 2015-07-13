package net.bither.bitherj.db.imp.base;

public interface IDb {
    void beginTransaction();
    void endTransaction();
    void close();
}
