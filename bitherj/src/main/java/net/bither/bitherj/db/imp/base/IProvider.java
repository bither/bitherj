package net.bither.bitherj.db.imp.base;

import com.google.common.base.Function;

public interface IProvider {
    void execUpdate(String sql, String[] params);
    void execQueryOneRecord(String sql, String[] params, Function func);
    void execQueryLoop(String sql, String[] params, Function<ICursor, Void> func);
}
