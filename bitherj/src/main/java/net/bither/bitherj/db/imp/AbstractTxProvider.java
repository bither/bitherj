package net.bither.bitherj.db.imp;

import android.database.sqlite.SQLiteDatabase;

import com.google.common.base.Function;

import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.ITxProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IProvider;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractTxProvider implements IProvider, ITxProvider {
    @Override
    public void unConfirmTxByBlockNo(int blockNo) {
        String sql = "update txs set block_no=null where block_no>=?";
        this.execUpdate(sql, new String[]{Integer.toString(blockNo)});
    }

    @Override
    public List<Tx> getUnspendTxWithAddress(String address) {
        String unspendOutSql = "select a.*,b.tx_ver,b.tx_locktime,b.tx_time,b.block_no,b.source,ifnull(b.block_no,0)*a.out_value coin_depth " +
                "from outs a,txs b where a.tx_hash=b.tx_hash" +
                " and a.out_address=? and a.out_status=?";
        final List<Tx> txItemList = new ArrayList<Tx>();

        this.execQueryLoop(unspendOutSql, new String[]{address, Integer.toString(Out.OutStatus.unspent.getValue())}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("coin_depth");

                Tx txItem = applyCursor(c);
                Out outItem = applyCursorOut(c);
                if (idColumn != -1) {
                    outItem.setCoinDepth(c.getLong(idColumn));
                }
                outItem.setTx(txItem);
                txItem.setOuts(new ArrayList<Out>());
                txItem.getOuts().add(outItem);
                txItemList.add(txItem);
                return null;
            }
        });
        return txItemList;
    }

    public static Tx applyCursor(ICursor c) {
        Tx txItem = new Tx();
        int idColumn = c.getColumnIndex(AbstractDb.TxsColumns.BLOCK_NO);
        if (!c.isNull(idColumn)) {
            txItem.setBlockNo(c.getInt(idColumn));
        } else {
            txItem.setBlockNo(Tx.TX_UNCONFIRMED);
        }
        idColumn = c.getColumnIndex(AbstractDb.TxsColumns.TX_HASH);
        if (idColumn != -1) {
            try {
                txItem.setTxHash(Base58.decode(c.getString(idColumn)));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.TxsColumns.SOURCE);
        if (idColumn != -1) {
            txItem.setSource(c.getInt(idColumn));
        }
        if (txItem.getSource() >= 1) {
            txItem.setSawByPeerCnt(txItem.getSource() - 1);
            txItem.setSource(1);
        } else {
            txItem.setSawByPeerCnt(0);
            txItem.setSource(0);
        }
        idColumn = c.getColumnIndex(AbstractDb.TxsColumns.TX_TIME);
        if (idColumn != -1) {
            txItem.setTxTime(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.TxsColumns.TX_VER);
        if (idColumn != -1) {
            txItem.setTxVer(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.TxsColumns.TX_LOCKTIME);
        if (idColumn != -1) {
            txItem.setTxLockTime(c.getInt(idColumn));
        }
        return txItem;
    }

    public static In applyCursorIn(ICursor c) {
        In inItem = new In();
        int idColumn = c.getColumnIndex(AbstractDb.InsColumns.TX_HASH);
        if (idColumn != -1) {
            try {
                inItem.setTxHash(Base58.decode(c.getString(idColumn)));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.InsColumns.IN_SN);
        if (idColumn != -1) {
            inItem.setInSn(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.InsColumns.PREV_TX_HASH);
        if (idColumn != -1) {
            try {
                inItem.setPrevTxHash(Base58.decode(c.getString(idColumn)));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.InsColumns.PREV_OUT_SN);
        if (idColumn != -1) {
            inItem.setPrevOutSn(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.InsColumns.IN_SIGNATURE);
        if (idColumn != -1) {
            String inSignature = c.getString(idColumn);
            if (!Utils.isEmpty(inSignature)) {
                try {
                    inItem.setInSignature(Base58.decode(c.getString(idColumn)));
                } catch (AddressFormatException e) {
                    e.printStackTrace();
                }
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.InsColumns.IN_SEQUENCE);
        if (idColumn != -1) {
            inItem.setInSequence(c.getInt(idColumn));
        }
        return inItem;
    }

    public static Out applyCursorOut(ICursor c) {
        Out outItem = new Out();
        int idColumn = c.getColumnIndex(AbstractDb.OutsColumns.TX_HASH);
        if (idColumn != -1) {
            try {
                outItem.setTxHash(Base58.decode(c.getString(idColumn)));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_SN);
        if (idColumn != -1) {
            outItem.setOutSn(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_SCRIPT);
        if (idColumn != -1) {
            try {
                outItem.setOutScript(Base58.decode(c.getString(idColumn)));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_VALUE);
        if (idColumn != -1) {
            outItem.setOutValue(c.getLong(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_STATUS);
        if (idColumn != -1) {
            outItem.setOutStatus(Out.getOutStatus(c.getInt(idColumn)));
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_ADDRESS);
        if (idColumn != -1) {
            outItem.setOutAddress(c.getString(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.OutsColumns.HD_ACCOUNT_ID);
        if (idColumn != -1 && !c.isNull(idColumn)) {
            outItem.setHDAccountId(c.getInt(idColumn));
        }
        return outItem;
    }
}
