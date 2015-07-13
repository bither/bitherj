package net.bither.bitherj.db.imp.base;

import com.google.common.base.Function;

public interface IProvider {
    IDb getReadDb();
    IDb getWriteDb();

    void execUpdate(String sql, String[] params);
    void execQueryOneRecord(String sql, String[] params, Function<ICursor, Void> func);
    void execQueryLoop(String sql, String[] params, Function<ICursor, Void> func);

    void execUpdate(IDb db, String sql, String[] params);
    void execQueryOneRecord(IDb db, String sql, String[] params, Function<ICursor, Void> func);
    void execQueryLoop(IDb db, String sql, String[] params, Function<ICursor, Void> func);
}
