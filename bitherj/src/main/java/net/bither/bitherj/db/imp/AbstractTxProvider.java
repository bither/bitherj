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

package net.bither.bitherj.db.imp;

import com.google.common.base.Function;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.ITxProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IDb;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractTxProvider extends AbstractProvider implements ITxProvider {

    @Override
    public List<Tx> getTxAndDetailByAddress(String address) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();
        String sql = "select b.* from addresses_txs a, txs b" +
                " where a.tx_hash=b.tx_hash and a.address=? order by ifnull(b.block_no,4294967295) desc";
        IDb db = this.getReadDb();
        this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txItemList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                return null;
            }
        });
        addInForTxDetail(db, address, txDict);
        addOutForTxDetail(db, address, txDict);

        return txItemList;
    }

    private void addInForTxDetail(IDb db, String address, final HashMap<Sha256Hash, Tx> txDict) {
        String sql = "select b.* from addresses_txs a, ins b where a.tx_hash=b.tx_hash and a.address=? "
                + "order by b.tx_hash ,b.in_sn";
        this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                In inItem = applyCursorIn(c);
                Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                if (tx != null) {
                    tx.getIns().add(inItem);
                }
                return null;
            }
        });
    }

    private void addOutForTxDetail(IDb db, String address, final HashMap<Sha256Hash, Tx> txDict) {
        String sql = "select b.* from addresses_txs a, outs b where a.tx_hash=b.tx_hash and a.address=? "
                + "order by b.tx_hash,b.out_sn";
        this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Out out = applyCursorOut(c);
                Tx tx = txDict.get(new Sha256Hash(out.getTxHash()));
                if (tx != null) {
                    tx.getOuts().add(out);
                }
                return null;
            }
        });
    }

    @Override
    public List<Tx> getTxAndDetailByAddress(String address, int page) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();

        IDb db = this.getReadDb();

        String sql = "select b.* from addresses_txs a, txs b" +
                " where a.tx_hash=b.tx_hash and a.address=? order by ifnull(b.block_no,4294967295) desc limit ?,? ";
        final StringBuilder txsStrBuilder = new StringBuilder();
        this.execQueryLoop(db, sql, new String[]{address
                    , Integer.toString((page - 1) * BitherjSettings.TX_PAGE_SIZE)
                    , Integer.toString(BitherjSettings.TX_PAGE_SIZE)}
                , new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txItemList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                txsStrBuilder.append("'").append(Base58.encode(txItem.getTxHash())).append("'").append(",");
                return null;
            }
        });

        if (txsStrBuilder.length() > 1) {
            String txs = txsStrBuilder.substring(0, txsStrBuilder.length() - 1);
            sql = Utils.format("select b.* from ins b where b.tx_hash in (%s)" +
                    " order by b.tx_hash ,b.in_sn", txs);
            this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    In inItem = applyCursorIn(c);
                    Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                    if (tx != null) {
                        tx.getIns().add(inItem);
                    }
                    return null;
                }
            });
            sql = Utils.format("select b.* from outs b where b.tx_hash in (%s)" +
                    " order by b.tx_hash,b.out_sn", txs);
            this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    Out out = applyCursorOut(c);
                    Tx tx = txDict.get(new Sha256Hash(out.getTxHash()));
                    if (tx != null) {
                        tx.getOuts().add(out);
                    }
                    return null;
                }
            });
        }
        return txItemList;
    }

    @Override
    public List<Tx> getPublishedTxs() {
        final List<Tx> txItemList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();
        IDb db = this.getReadDb();
        String sql = "select * from txs where block_no is null";
        this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txItemList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                return null;
            }
        });

        sql = "select b.* from txs a, ins b  where a.tx_hash=b.tx_hash  and a.block_no is null "
                + "order by b.tx_hash ,b.in_sn";
        this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                In inItem = applyCursorIn(c);
                Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                tx.getIns().add(inItem);
                return null;
            }
        });
        sql = "select b.* from txs a, outs b where a.tx_hash=b.tx_hash and a.block_no is null "
                + "order by b.tx_hash,b.out_sn";
        this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Out out = applyCursorOut(c);
                Tx tx = txDict.get(new Sha256Hash(out.getTxHash()));
                tx.getOuts().add(out);
                return null;
            }
        });
        return txItemList;
    }

    public Tx getTxDetailByTxHash(byte[] txHash) {
        final Tx[] txItem = {null};
        final boolean[] txExists = {false};
        String txHashStr = Base58.encode(txHash);
        String sql = "select * from txs where tx_hash=?";
        IDb db = this.getReadDb();
        this.execQueryOneRecord(db, sql, new String[]{txHashStr}, new Function<ICursor, Void>() {
            @Nullable

            @Override
            public Void apply(@Nullable ICursor c) {
                txItem[0] = applyCursor(c);
                txExists[0] = true;
                return null;
            }
        });
        if (txExists[0]) {
            addInsAndOuts(db, txItem[0]);
        }
        return txItem[0];
    }

    @Override
    public long sentFromAddress(byte[] txHash, String address) {
        String sql = "select  sum(o.out_value) out_value from ins i,outs o where" +
                " i.tx_hash=? and o.tx_hash=i.prev_tx_hash and i.prev_out_sn=o.out_sn and o.out_address=?";
        final long[] sum = {0};
        this.execQueryOneRecord(sql, new String[]{Base58.encode(txHash), address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.OutsColumns.OUT_VALUE);
                if (idColumn != -1) {
                    sum[0] = c.getLong(idColumn);
                }
                return null;
            }
        });
        return sum[0];
    }


    public boolean isExist(byte[] txHash) {
        final boolean[] result = {false};
        String sql = "select count(0) from txs where tx_hash=?";
        this.execQueryOneRecord(sql, new String[]{Base58.encode(txHash)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                result[0] = c.getInt(0) > 0;
                return null;
            }
        });
        return result[0];
    }

    public void add(Tx txItem) {
        IDb db = this.getWriteDb();
        db.beginTransaction();
        addTxToDb(db, txItem);
        db.endTransaction();
    }

    public void addTxs(List<Tx> txItems) {
        if (txItems.size() > 0) {
            IDb db = this.getWriteDb();
            db.beginTransaction();
            for (Tx txItem : txItems) {
                addTxToDb(db, txItem);
            }
            db.endTransaction();
        }
    }

    private void addTxToDb(IDb db, Tx txItem) {
        this.insertTx(db, txItem);
        List<AddressTx> addressesTxsRels = new ArrayList<AddressTx>();
        List<AddressTx> temp = insertIn(db, txItem);
        if (temp != null && temp.size() > 0) {
            addressesTxsRels.addAll(temp);
        }
        temp = insertOut(db, txItem);
        if (temp != null && temp.size() > 0) {
            addressesTxsRels.addAll(temp);
        }
        String sql = "insert or ignore into addresses_txs(address, tx_hash) values(?,?)";
        for (AddressTx addressTx : addressesTxsRels) {
            this.execUpdate(db, sql, new String[]{addressTx.getAddress(), addressTx.getTxHash()});
        }
    }

    public void remove(byte[] txHash) {
        String txHashStr = Base58.encode(txHash);
        List<String> txHashes = new ArrayList<String>();
        List<String> needRemoveTxHashes = new ArrayList<String>();
        txHashes.add(txHashStr);
        while (txHashes.size() > 0) {
            String thisHash = txHashes.get(0);
            txHashes.remove(0);
            needRemoveTxHashes.add(thisHash);
            List<String> temp = getRelayTx(thisHash);
            txHashes.addAll(temp);
        }
        IDb db = this.getWriteDb();
        db.beginTransaction();
        for (String str : needRemoveTxHashes) {
            removeSingleTx(db, str);
        }
        db.endTransaction();
    }

    private void removeSingleTx(IDb db, String tx) {
        String deleteTx = "delete from txs where tx_hash=?";
        String deleteIn = "delete from ins where tx_hash=?";
        String deleteOut = "delete from outs where tx_hash=?";
        String deleteAddressesTx = "delete from addresses_txs where tx_hash=?";
        String inSql = "select prev_tx_hash,prev_out_sn from ins where tx_hash=?";
        String existOtherIn = "select count(0) cnt from ins where prev_tx_hash=? and prev_out_sn=?";
        String updatePrevOut = "update outs set out_status=? where tx_hash=? and out_sn=?";
        final List<Object[]> needUpdateOuts = new ArrayList<Object[]>();
        this.execQueryLoop(db, inSql, new String[]{tx}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.InsColumns.PREV_TX_HASH);
                String prevTxHash = null;
                int prevOutSn = 0;
                if (idColumn != -1) {
                    prevTxHash = c.getString(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.InsColumns.PREV_OUT_SN);
                if (idColumn != -1) {
                    prevOutSn = c.getInt(idColumn);
                }
                needUpdateOuts.add(new Object[]{prevTxHash, prevOutSn});
                return null;
            }
        });
        this.execUpdate(db, deleteAddressesTx, new String[] {tx});
        this.execUpdate(db, deleteOut, new String[] {tx});
        this.execUpdate(db, deleteIn, new String[] {tx});
        this.execUpdate(db, deleteTx, new String[] {tx});
        for (Object[] array : needUpdateOuts) {
            final boolean[] isExist = {false};
            this.execQueryLoop(db, existOtherIn, new String[]{array[0].toString(), array[1].toString()}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    if (c.getInt(0) == 0) {
                        isExist[0] = true;
                    }
                    return null;
                }
            });
            if (isExist[0]) {
                this.execUpdate(db, updatePrevOut, new String[] {"0", array[0].toString(), array[1].toString()});
            }
        }
    }

    private List<String> getRelayTx(String txHash) {
        final List<String> relayTxHashes = new ArrayList<String>();
        String relayTxSql = "select distinct tx_hash from ins where prev_tx_hash=?";
        this.execQueryLoop(relayTxSql, new String[]{txHash}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                relayTxHashes.add(c.getString(0));
                return null;
            }
        });
        return relayTxHashes;
    }

    public boolean isAddressContainsTx(String address, Tx txItem) {
        boolean result = false;
        String sql = "select count(0) from ins a, txs b where a.tx_hash=b.tx_hash and" +
                " b.block_no is not null and a.prev_tx_hash=? and a.prev_out_sn=?";
        IDb db = this.getReadDb();
        for (In inItem : txItem.getIns()) {
            final boolean[] isDoubleSpent = {false};
            this.execQueryOneRecord(db, sql, new String[]{Base58.encode(inItem.getPrevTxHash()), Integer.toString(inItem.getPrevOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    isDoubleSpent[0] = c.getInt(0) > 0;
                    return null;
                }
            });
            if (isDoubleSpent[0]) {
                return false;
            }
        }
        sql = "select count(0) from addresses_txs where tx_hash=? and address=?";
        final boolean[] isRecordInRel = {false};
        this.execQueryOneRecord(db, sql, new String[]{Base58.encode(txItem.getTxHash()), address}
                , new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                isRecordInRel[0] = c.getInt(0) > 0;
                return null;
            }
        });
        if (isRecordInRel[0]) {
            return true;
        }
        sql = "select count(0) from outs where tx_hash=? and out_sn=? and out_address=?";
        for (In inItem : txItem.getIns()) {
            final int[] cnt = {0};
            this.execQueryOneRecord(db, sql, new String[]{Base58.encode(inItem.getPrevTxHash())
                    , Integer.toString(inItem.getPrevOutSn()), address}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    cnt[0] = c.getInt(0);
                    return null;
                }
            });
            if (cnt[0] > 0) {
                return true;
            }
        }
        return result;
    }

    public boolean isTxDoubleSpendWithConfirmedTx(Tx tx) {
        String sql = "select count(0) from ins a, txs b where a.tx_hash=b.tx_hash and" +
                " b.block_no is not null and a.prev_tx_hash=? and a.prev_out_sn=?";
        IDb db = this.getReadDb();
        for (In inItem : tx.getIns()) {
            final int[] cnt = {0};
            this.execQueryOneRecord(db, sql, new String[]{Base58.encode(inItem.getPrevTxHash()), Integer.toString(inItem.getPrevOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    cnt[0] = c.getInt(0);
                    return null;
                }
            });
            if (cnt[0] > 0) {
                return true;
            }
        }
        return false;
    }

    public List<String> getInAddresses(Tx tx) {
        final List<String> result = new ArrayList<String>();
        String sql = "select out_address from outs where tx_hash=? and out_sn=?";
        IDb db = this.getReadDb();
        for (In inItem : tx.getIns()) {
            this.execQueryOneRecord(db, sql, new String[]{Base58.encode(inItem.getPrevTxHash())
                    , Integer.toString(inItem.getPrevOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    if (!c.isNull(0)) {
                        result.add(c.getString(0));
                    }
                    return null;
                }
            });
        }
        return result;
    }

    public void confirmTx(int blockNo, List<byte[]> txHashes) {
        if (blockNo == Tx.TX_UNCONFIRMED || txHashes == null) {
            return;
        }
        String updateBlockNoSql = "update txs set block_no=? where tx_hash=?";
        String existSql = "select count(0) from txs where block_no=? and tx_hash=?";
        String doubleSpendSql = "select a.tx_hash from ins a, ins b where a.prev_tx_hash=b.prev_tx_hash " +
                "and a.prev_out_sn=b.prev_out_sn and a.tx_hash<>b.tx_hash and b.tx_hash=?";
        String blockTimeSql = "select block_time from blocks where block_no=?";
        String updateTxTimeThatMoreThanBlockTime = "update txs set tx_time=? where block_no=? and tx_time>?";
        IDb db = this.getWriteDb();
        db.beginTransaction();
        for (byte[] txHash : txHashes) {
            final int[] cnt = {0};
            this.execQueryOneRecord(db, existSql, new String[]{Integer.toString(blockNo), Base58.encode(txHash)}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    cnt[0] = c.getInt(0);
                    return null;
                }
            });
            if (cnt[0] > 0) {
                continue;
            }
            this.execUpdate(db, updateBlockNoSql, new String[] {Integer.toString(blockNo), Base58.encode(txHash)});
            final List<String> txHashes1 = new ArrayList<String>();
            this.execQueryLoop(db, doubleSpendSql, new String[]{Base58.encode(txHash)}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex("tx_hash");
                    if (idColumn != -1) {
                        txHashes1.add(c.getString(idColumn));
                    }
                    return null;
                }
            });
            List<String> needRemoveTxHashes = new ArrayList<String>();
            while (txHashes1.size() > 0) {
                String thisHash = txHashes1.get(0);
                txHashes1.remove(0);
                needRemoveTxHashes.add(thisHash);
                List<String> temp = getRelayTx(thisHash);
                txHashes1.addAll(temp);
            }
            for (String each : needRemoveTxHashes) {
                removeSingleTx(db, each);
            }
        }
        final int[] blockTime = {-1};
        this.execQueryOneRecord(db, blockTimeSql, new String[]{Integer.toString(blockNo)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("block_time");
                if (idColumn != -1) {
                    blockTime[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        if (blockTime[0] > 0) {
            this.execUpdate(db, updateTxTimeThatMoreThanBlockTime, new String[]{Integer.toString(blockTime[0])
                    , Integer.toString(blockNo), Integer.toString(blockTime[0])});
        }
        db.endTransaction();
    }

    public void unConfirmTxByBlockNo(int blockNo) {
        String sql = "update txs set block_no=null where block_no>=?";
        this.execUpdate(sql, new String[] {Integer.toString(blockNo)});
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

//    public List<Out> getUnspendOutWithAddress(String address) {
//        final List<Out> outItems = new ArrayList<Out>();
//        String unspendOutSql = "select a.* from outs a,txs b where a.tx_hash=b.tx_hash " +
//                " and a.out_address=? and a.out_status=?";
//        this.execQueryLoop(unspendOutSql, new String[]{address, Integer.toString(Out.OutStatus.unspent.getValue())}, new Function<ICursor, Void>() {
//            @Nullable
//            @Override
//            public Void apply(@Nullable ICursor c) {
//                outItems.add(applyCursorOut(c));
//                return null;
//            }
//        });
//        return outItems;
//    }

    public long getConfirmedBalanceWithAddress(String address) {
        final long[] sum = {0};
        String unspendOutSql = "select ifnull(sum(a.out_value),0) sum from outs a,txs b where a.tx_hash=b.tx_hash " +
                " and a.out_address=? and a.out_status=? and b.block_no is not null";
        this.execQueryOneRecord(unspendOutSql, new String[]{address, Integer.toString(Out.OutStatus.unspent.getValue())}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("sum");
                if (idColumn != -1) {
                    sum[0] = c.getLong(idColumn);
                }
                return null;
            }
        });
        return sum[0];
    }

    public List<Tx> getUnconfirmedTxWithAddress(String address) {
        final List<Tx> txList = new ArrayList<Tx>();

        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();
        IDb db = this.getReadDb();
            String sql = "select b.* from addresses_txs a, txs b " +
                    "where a.tx_hash=b.tx_hash and a.address=? and b.block_no is null " +
                    "order by b.block_no desc";
            this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    Tx txItem = applyCursor(c);
                    txItem.setIns(new ArrayList<In>());
                    txItem.setOuts(new ArrayList<Out>());
                    txList.add(txItem);
                    txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                    return null;
                }
            });
            sql = "select b.tx_hash,b.in_sn,b.prev_tx_hash,b.prev_out_sn " +
                    "from addresses_txs a, ins b, txs c " +
                    "where a.tx_hash=b.tx_hash and b.tx_hash=c.tx_hash and c.block_no is null and a.address=? "
                    + "order by b.tx_hash ,b.in_sn";
            this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    In inItem = applyCursorIn(c);
                    Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                    if (tx != null) {
                        tx.getIns().add(inItem);
                    }
                    return null;
                }
            });

            sql = "select b.tx_hash,b.out_sn,b.out_value,b.out_address " +
                    "from addresses_txs a, outs b, txs c " +
                    "where a.tx_hash=b.tx_hash and b.tx_hash=c.tx_hash and c.block_no is null and a.address=? "
                    + "order by b.tx_hash,b.out_sn";
            this.execQueryLoop(db, sql, new String[]{address}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    Out out = applyCursorOut(c);
                    Tx tx = txDict.get(new Sha256Hash(out.getTxHash()));
                    if (tx != null) {
                        tx.getOuts().add(out);
                    }
                    return null;
                }
            });
        return txList;
    }

    public int txCount(String address) {
        final int[] result = {0};
        String sql = "select count(0) cnt from addresses_txs where address=?";
        this.execQueryOneRecord(sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    result[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return result[0];
    }

    public long totalReceive(String address) {
        final long[] result = {0};
        String sql = "select sum(aa.receive-ifnull(bb.send,0)) sum" +
                "  from (select a.tx_hash,sum(a.out_value) receive " +
                "    from outs a where a.out_address=?" +
                "    group by a.tx_hash) aa LEFT OUTER JOIN " +
                "  (select b.tx_hash,sum(a.out_value) send" +
                "    from outs a, ins b" +
                "    where a.tx_hash=b.prev_tx_hash and a.out_sn=b.prev_out_sn and a.out_address=?" +
                "    group by b.tx_hash) bb on aa.tx_hash=bb.tx_hash " +
                "  where aa.receive>ifnull(bb.send, 0)";
        this.execQueryOneRecord(sql, new String[]{address, address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                result[0] = c.getLong(0);
                return null;
            }
        });
        return result[0];
    }

    public void txSentBySelfHasSaw(byte[] txHash) {
        String sql = "update txs set source=source+1 where tx_hash=? and source>=1";
        this.execUpdate(sql, new String[]{Base58.encode(txHash)});
    }

    public List<Out> getOuts() {
        final List<Out> outItemList = new ArrayList<Out>();
        String sql = "select * from outs ";
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outItemList.add(applyCursorOut(c));
                return null;
            }
        });
        return outItemList;
    }

//    public List<In> getRelatedIn(String address) {
//        final List<In> list = new ArrayList<In>();
//        String sql = "select ins.* from ins,addresses_txs " +
//                "where ins.tx_hash=addresses_txs.tx_hash and addresses_txs.address=? ";
//        this.execQueryLoop(sql, new String[]{address}, new Function<ICursor, Void>() {
//            @Nullable
//            @Override
//            public Void apply(@Nullable ICursor c) {
//                list.add(applyCursorIn(c));
//                return null;
//            }
//        });
//        return list;
//    }

    public List<Tx> getRecentlyTxsByAddress(String address, int greateThanBlockNo, int limit) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        String sql = "select b.* from addresses_txs a, txs b where a.tx_hash=b.tx_hash and a.address='%s' " +
                "and ((b.block_no is null) or (b.block_no is not null and b.block_no>%d)) " +
                "order by ifnull(b.block_no,4294967295) desc, b.tx_time desc " +
                "limit %d ";
        sql = Utils.format(sql, address, greateThanBlockNo, limit);
        IDb db = this.getReadDb();
        this.execQueryLoop(db, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = applyCursor(c);
                txItemList.add(txItem);
                return null;
            }
        });
        for (Tx item : txItemList) {
            addInsAndOuts(db, item);
        }
        return txItemList;
    }

//    public HashMap<Sha256Hash, Tx> getTxDependencies(Tx txItem) {
//        HashMap<Sha256Hash, Tx> result = new HashMap<Sha256Hash, Tx>();
//        IDb db = this.getReadDb();
//
//        for (In inItem : txItem.getIns()) {
//            final Tx tx = new Tx();
//            final boolean[] isExists = {false};
//            String sql = "select * from txs where tx_hash=?";
//            this.execQueryOneRecord(db, sql, new String[]{Base58.encode(inItem.getTxHash())}, new Function<ICursor, Void>() {
//                @Nullable
//                @Override
//                public Void apply(@Nullable ICursor c) {
//                    applyCursor(c, tx);
//                    isExists[0] = true;
//                    return null;
//                }
//            });
//            if (!isExists[0]) {
//                continue;
//            }
//            addInsAndOuts(db, tx);
//            result.put(new Sha256Hash(tx.getTxHash()), tx);
//        }
//        return result;
//    }

    public void clearAllTx() {
//        SQLiteDatabase db = mDb.getWritableDatabase();
        IDb db = this.getWriteDb();
        db.beginTransaction();
        this.execUpdate(db, "drop table " + AbstractDb.Tables.TXS + ";", null);
        this.execUpdate(db, "drop table " + AbstractDb.Tables.OUTS + ";", null);
        this.execUpdate(db, "drop table " + AbstractDb.Tables.INS + ";", null);
        this.execUpdate(db, "drop table " + AbstractDb.Tables.ADDRESSES_TXS + ";", null);
        this.execUpdate(db, "drop table " + AbstractDb.Tables.PEERS + ";", null);
        this.execUpdate(db, AbstractDb.CREATE_TXS_SQL, null);
        this.execUpdate(db, AbstractDb.CREATE_TX_BLOCK_NO_INDEX, null);
        this.execUpdate(db, AbstractDb.CREATE_OUTS_SQL, null);
        this.execUpdate(db, AbstractDb.CREATE_OUT_OUT_ADDRESS_INDEX, null);
        this.execUpdate(db, AbstractDb.CREATE_INS_SQL, null);
        this.execUpdate(db, AbstractDb.CREATE_IN_PREV_TX_HASH_INDEX, null);
        this.execUpdate(db, AbstractDb.CREATE_ADDRESSTXS_SQL, null);
        this.execUpdate(db, AbstractDb.CREATE_PEER_SQL, null);
        db.endTransaction();
    }

    public void completeInSignature(List<In> ins) {
        IDb db = this.getWriteDb();
        db.beginTransaction();
        String sql = "update ins set in_signature=? where tx_hash=? and in_sn=? and ifnull(in_signature,'')=''";
        for (In in : ins) {
            this.execUpdate(db, sql, new String[]{Base58.encode(in.getInSignature())
                    , Base58.encode(in.getTxHash()), Integer.toString(in.getInSn())});
        }
        db.endTransaction();
    }

    public int needCompleteInSignature(String address) {
        final int[] result = {0};
        String sql = "select max(txs.block_no) from outs,ins,txs where outs.out_address=? " +
                "and ins.prev_tx_hash=outs.tx_hash and ins.prev_out_sn=outs.out_sn " +
                "and ifnull(ins.in_signature,'')='' and txs.tx_hash=ins.tx_hash";
        this.execQueryOneRecord(sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                result[0] = c.getInt(0);
                return null;
            }
        });
        return result[0];
    }

    public static Tx applyCursor(ICursor c) {
        return applyCursor(c, null);
    }

    public static Tx applyCursor(ICursor c, @Nullable Tx tx) {
        Tx txItem = null;
        if (tx == null) {
            txItem = new Tx();
        } else {
            txItem = tx;
        }
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

    public void addInsAndOuts(IDb db, final Tx txItem) {
        String txHashStr = Base58.encode(txItem.getTxHash());
        txItem.setOuts(new ArrayList<Out>());
        txItem.setIns(new ArrayList<In>());
        String sql = "select * from ins where tx_hash=? order by in_sn";
        this.execQueryLoop(db, sql, new String[]{txHashStr}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                In inItem = applyCursorIn(c);
                inItem.setTx(txItem);
                txItem.getIns().add(inItem);
                return null;
            }
        });

        sql = "select * from outs where tx_hash=? order by out_sn";
        this.execQueryLoop(db, sql, new String[]{txHashStr}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Out outItem = applyCursorOut(c);
                outItem.setTx(txItem);
                txItem.getOuts().add(outItem);
                return null;
            }
        });
    }

    public void insertTx(IDb db, Tx txItem) {
        final int[] cnt = {0};
        String existSql = "select count(0) cnt from txs where tx_hash=?";
        this.execQueryOneRecord(db, existSql, new String[]{Base58.encode(txItem.getTxHash())}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    cnt[0] = c.getInt(idColumn);
                }
                return null;
            }
        });

        if (cnt[0] == 0) {
            this.insertTxToDb(db, txItem);
        }

    }

    protected abstract void insertTxToDb(IDb db, Tx tx);


    public List<AddressTx> insertIn(IDb db, final Tx txItem) {
        final List<AddressTx> addressTxes = new ArrayList<AddressTx>();
        String existSql = "select count(0) cnt from ins where tx_hash=? and in_sn=?";
        String outAddressSql = "select out_address from outs where tx_hash=? and out_sn=?";
        String updateOutStatusSql = "update outs set out_status=? where tx_hash=? and out_sn=?";
        for (In inItem : txItem.getIns()) {
            final int[] cnt = {0};
            this.execQueryOneRecord(db, existSql, new String[]{Base58.encode(inItem.getTxHash())
                        , Integer.toString(inItem.getInSn())}
                    , new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex("cnt");
                    if (idColumn != -1) {
                        cnt[0] = c.getInt(idColumn);
                    }
                    return null;
                }
            });
            if (cnt[0] == 0) {
                this.insertInToDb(db, inItem);
            }

            this.execQueryLoop(db, outAddressSql, new String[]{Base58.encode(inItem.getPrevTxHash())
                        , Integer.toString(inItem.getPrevOutSn())}
                    , new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex("out_address");
                    if (idColumn != -1) {
                        addressTxes.add(new AddressTx(c.getString(idColumn), Base58.encode(txItem
                                .getTxHash())));
                    }
                    return null;
                }
            });

            this.execUpdate(db, updateOutStatusSql, new String[]{Integer.toString(Out.OutStatus.spent.getValue()), Base58
                    .encode(inItem.getPrevTxHash()), Integer.toString(inItem.getPrevOutSn())});
        }
        return addressTxes;
    }

    protected abstract void insertInToDb(IDb db, In in);

    public List<AddressTx> insertOut(IDb db, Tx txItem) {
        String existSql = "select count(0) cnt from outs where tx_hash=? and out_sn=?";
        String updateHDAccountIdSql = "update outs set hd_account_id=? where tx_hash=? and out_sn=?";
        String queryHDAddressSql = "select hd_account_id,path_type,address_index from hd_account_addresses where address=?";
        String updateHDAddressIssuedSql = "update hd_account_addresses set is_issued=? where path_type=? and address_index<=? and hd_account_id=?";
        String queryPrevTxHashSql = "select tx_hash from ins where prev_tx_hash=? and prev_out_sn=?";
        String updateOutStatusSql = "update outs set out_status=? where tx_hash=? and out_sn=?";
        final List<AddressTx> addressTxes = new ArrayList<AddressTx>();
        for (final Out outItem : txItem.getOuts()) {
            final int[] cnt = {0};
            this.execQueryOneRecord(db, existSql, new String[]{Base58.encode(outItem.getTxHash()), Integer
                    .toString(outItem.getOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex("cnt");
                    if (idColumn != -1) {
                        cnt[0] = c.getInt(idColumn);
                    }
                    return null;
                }
            });
            if (cnt[0] == 0) {
                this.insertOutToDb(db, outItem);
            } else {
                if (outItem.getHDAccountId() > -1) {
                    this.execUpdate(db, updateHDAccountIdSql, new String[]{
                            Integer.toString(outItem.getHDAccountId()), Base58.encode(txItem.getTxHash())
                            , Integer.toString(outItem.getOutSn())});
                }
            }
            if (outItem.getHDAccountId() > -1) {
                final int[] tmpHDAccountId = {-1};
                final int[] tmpPathType = {0};
                final int[] tmpAddressIndex = {0};
                this.execQueryOneRecord(db, queryHDAddressSql, new String[]{outItem.getOutAddress()}, new Function<ICursor, Void>() {
                    @Nullable
                    @Override
                    public Void apply(@Nullable ICursor c) {
                        tmpHDAccountId[0] = c.getInt(0);
                        tmpPathType[0] = c.getInt(1);
                        tmpAddressIndex[0] = c.getInt(2);
                        return null;
                    }
                });
                if (tmpHDAccountId[0] > 0) {
                    this.execUpdate(db, updateHDAddressIssuedSql
                            , new String[]{"1", Integer.toString(tmpPathType[0])
                            , Integer.toString(tmpAddressIndex[0])
                            , Integer.toString(tmpHDAccountId[0])});
                }
            }
            if (!Utils.isEmpty(outItem.getOutAddress())) {
                addressTxes.add(new AddressTx(outItem.getOutAddress(), Base58.encode(txItem
                        .getTxHash())));
            }
            final boolean[] isSpentByExistTx = {false};
            this.execQueryOneRecord(db, queryPrevTxHashSql, new String[]{Base58.encode(txItem.getTxHash())
                    , Integer.toString(outItem.getOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex("tx_hash");
                    if (idColumn != -1) {
                        addressTxes.add(new AddressTx(outItem.getOutAddress(), c.getString(idColumn)));
                    }
                    isSpentByExistTx[0] = true;
                    return null;
                }
            });
            if (isSpentByExistTx[0]) {
                this.execUpdate(db, updateOutStatusSql, new String[]{Integer.toString(Out.OutStatus.spent.getValue())
                        , Base58.encode(txItem.getTxHash()), Integer.toString(outItem.getOutSn())});
            }
        }
        return addressTxes;
    }

    public byte[] isIdentify(Tx tx) {
        HashSet<String> result = new HashSet<String>();

        for (In in : tx.getIns()) {
            String queryPrevTxHashSql = "select tx_hash from ins where prev_tx_hash=? and prev_out_sn=?";
            final HashSet<String> each = new HashSet<String>();
            this.execQueryOneRecord(this.getReadDb(), queryPrevTxHashSql, new String[]{Base58.encode(in.getPrevTxHash())
                    , Integer.toString(in.getPrevOutSn())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    each.add(c.getString(0));
                    return null;
                }
            });
            each.remove(Base58.encode(tx.getTxHash()));
            result.retainAll(each);
            if (result.size() == 0) {
                break;
            }
        }
        if (result.size() == 0) {
            return new byte[0];
        } else {
            try {
                return Base58.decode((String) result.toArray()[0]);
            } catch (AddressFormatException e) {
                e.printStackTrace();
                return new byte[0];
            }
        }
    }

    protected abstract void insertOutToDb(IDb db, Out out);

    public static class AddressTx {
        private String address;
        private String txHash;

        public AddressTx(String address, String txHash) {
            this.address = address;
            this.txHash = txHash;
        }

        public String getTxHash() {
            return txHash;
        }

        public void setTxHash(String txHash) {
            this.txHash = txHash;
        }

        public String getAddress() {
            return address;
        }

        public void setAddress(String address) {
            this.address = address;
        }
    }
}
