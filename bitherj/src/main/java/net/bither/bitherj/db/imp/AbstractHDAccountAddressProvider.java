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
import net.bither.bitherj.core.AbstractHD;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.In;
import net.bither.bitherj.core.Out;
import net.bither.bitherj.core.OutPoint;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IHDAccountAddressProvider;
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

import static net.bither.bitherj.db.imp.AbstractTxProvider.applyCursorOut;

public abstract class AbstractHDAccountAddressProvider extends AbstractProvider implements IHDAccountAddressProvider {

    @Override
    public void addAddress(List<HDAccount.HDAccountAddress> hdAccountAddresses) {
        String sql = "insert into hd_account_addresses(hd_account_id,path_type,address_index,is_issued,address,pub,is_synced) values(?,?,?,?,?,?,?)";
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        for (HDAccount.HDAccountAddress hdAccountAddress : hdAccountAddresses) {
            this.execUpdate(writeDb, sql, new String[] {
                    Integer.toString(hdAccountAddress.getHdAccountId())
                    , Integer.toString(hdAccountAddress.getPathType().getValue())
                    , Integer.toString(hdAccountAddress.getIndex())
                    , hdAccountAddress.isIssued() ? "1" : "0"
                    , hdAccountAddress.getAddress()
                    , Base58.encode(hdAccountAddress.getPub())
                    , hdAccountAddress.isSyncedComplete() ? "1" : "0"
            });
        }
        writeDb.endTransaction();
    }


    @Override
    public int issuedIndex(int hdAccountId, AbstractHD.PathType pathType) {
        String sql = "select ifnull(max(address_index),-1) address_index " +
                " from hd_account_addresses" +
                " where path_type=? and is_issued=? and hd_account_id=?";
        final int[] issuedIndex = {-1};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(pathType.getValue()), "1", String.valueOf(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS_INDEX);
                if (idColumn != -1) {
                    issuedIndex[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return issuedIndex[0];
    }

    @Override
    public int allGeneratedAddressCount(int hdAccountId, AbstractHD.PathType pathType) {
        String sql = "select ifnull(count(address),0) count " +
                " from hd_account_addresses " +
                " where path_type=? and hd_account_id=?";
        final int[] count = {0};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(pathType.getValue()), String.valueOf(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("count");
                if (idColumn != -1) {
                    count[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return count[0];
    }

    @Override
    public String externalAddress(int hdAccountId) {
        String sql = "select address from hd_account_addresses" +
                " where path_type=? and is_issued=? and hd_account_id=? order by address_index asc limit 1 ";
        final String[] address = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(AbstractHD.PathType.EXTERNAL_ROOT_PATH.getValue())
                , "0", Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS);
                if (idColumn != -1) {
                    address[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return address[0];
    }

    @Override
    public HashSet<String> getBelongAccountAddresses(int hdAccountId, List<String> addressList) {
        final HashSet<String> addressSet = new HashSet<String>();

        List<String> temp = new ArrayList<String>();
        if (addressList != null) {
            for (String str : addressList) {
                temp.add(Utils.format("'%s'", str));
            }
        }
        String sql = Utils.format("select address from hd_account_addresses where hd_account_id=? and address in (%s) "
                , Utils.joinString(temp, ","));
        this.execQueryLoop(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS);
                if (idColumn != -1) {
                    addressSet.add(c.getString(idColumn));
                }
                return null;
            }
        });
        return addressSet;
    }

    @Override
    public HashSet<String> getBelongAccountAddresses(List<String> addressList) {
        final HashSet<String> addressSet = new HashSet<String>();

        List<String> temp = new ArrayList<String>();
        if (addressList != null) {
            for (String str : addressList) {
                temp.add(Utils.format("'%s'", str));
            }
        }
        String sql = Utils.format("select address from hd_account_addresses where address in (%s) "
                , Utils.joinString(temp, ","));
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS);
                if (idColumn != -1) {
                    addressSet.add(c.getString(idColumn));
                }
                return null;
            }
        });
        return addressSet;
    }

    @Override
    public Tx updateOutHDAccountId(Tx tx) {
        final Tx finalTx = tx;
        List<String> addressList = tx.getOutAddressList();
        if (addressList != null && addressList.size() > 0) {
            HashSet<String> set = new HashSet<String>();
            set.addAll(addressList);
            StringBuilder strBuilder = new StringBuilder();
            for (String str : set) {
                strBuilder.append("'").append(str).append("',");
            }

            String sql = Utils.format("select address,hd_account_id from hd_account_addresses where address in (%s) "
                    , strBuilder.substring(0, strBuilder.length() - 1));
            this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    String address = c.getString(0);
                    int hdAccountId = c.getInt(1);
                    for (Out out : finalTx.getOuts()) {
                        if (Utils.compareString(out.getOutAddress(), address)) {
                            out.setHDAccountId(hdAccountId);
                        }
                    }
                    return null;
                }
            });
        }
        return tx;
    }

    @Override
    public int getRelatedAddressCnt(List<String> addresses) {
        final int[] cnt = {0};
        if (addresses != null && addresses.size() > 0) {
            HashSet<String> set = new HashSet<String>();
            set.addAll(addresses);
            StringBuilder strBuilder = new StringBuilder();
            for (String str : set) {
                strBuilder.append("'").append(str).append("',");
            }
            String sql = Utils.format("select count(0) cnt from hd_account_addresses where address in (%s) "
                    , strBuilder.substring(0, strBuilder.length() - 1));
            this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    cnt[0] = c.getInt(0);
                    return null;
                }
            });
        }
        return cnt[0];
    }

    @Override
    public List<Integer> getRelatedHDAccountIdList(List<String> addresses) {
        final List<Integer> hdAccountIdList = new ArrayList<Integer>();
        if (addresses != null && addresses.size() > 0) {
            HashSet<String> set = new HashSet<String>();
            set.addAll(addresses);
            StringBuilder strBuilder = new StringBuilder();
            for (String str : set) {
                strBuilder.append("'").append(str).append("',");
            }
            String sql = Utils.format("select distinct hd_account_id from hd_account_addresses where address in (%s) "
                    , strBuilder.substring(0, strBuilder.length() - 1));
            this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    hdAccountIdList.add(c.getInt(0));
                    return null;
                }
            });
        }
        return hdAccountIdList;
    }

    @Override
    public List<byte[]> getPubs(int hdAccountId, AbstractHD.PathType pathType) {
        String sql = "select pub from hd_account_addresses where path_type=? and hd_account_id=?";
        final List<byte[]> adressPubList = new ArrayList<byte[]>();
        this.execQueryLoop(sql, new String[]{Integer.toString(pathType.getValue()), Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.PUB);
                if (idColumn != -1) {
                    try {
                        adressPubList.add(Base58.decode(c.getString(idColumn)));
                    } catch (AddressFormatException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        return adressPubList;
    }

    public List<HDAccount.HDAccountAddress> getAllHDAddress(int hdAccountId) {
        final List<HDAccount.HDAccountAddress> adressPubList = new ArrayList<HDAccount
                .HDAccountAddress>();
        String sql = "select address,pub,path_type,address_index,is_issued,is_synced,hd_account_id " +
                "from hd_account_addresses where hd_account_id=? ";
        this.execQueryLoop(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                HDAccount.HDAccountAddress hdAccountAddress = formatAddress(c);
                if (hdAccountAddress != null) {
                    adressPubList.add(hdAccountAddress);
                }
                return null;
            }
        });
        return adressPubList;
    }


    @Override
    public List<Out> getUnspendOutByHDAccount(int hdAccountId) {
        final List<Out> outItems = new ArrayList<Out>();
        String unspendOutSql = "select a.* from outs a,txs b where a.tx_hash=b.tx_hash " +
                " and a.out_status=? and a.hd_account_id=?";
        this.execQueryLoop(unspendOutSql, new String[]{Integer.toString(Out.OutStatus.unspent.getValue()), Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outItems.add(AbstractTxProvider.applyCursorOut(c));
                return null;
            }
        });
        return outItems;
    }

    @Override
    public HDAccount.HDAccountAddress addressForPath(int hdAccountId, AbstractHD.PathType type, int index) {
        String sql = "select address,pub,path_type,address_index,is_issued," +
                "is_synced,hd_account_id from hd_account_addresses" +
                " where path_type=? and address_index=? and hd_account_id=?";
        final HDAccount.HDAccountAddress[] accountAddress = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(type.getValue()), Integer.toString(index), Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                accountAddress[0] = formatAddress(c);
                return null;
            }
        });
        return accountAddress[0];
    }

    @Override
    public void updateIssuedIndex(int hdAccountId, AbstractHD.PathType pathType, int index) {
        String sql = "update hd_account_addresses set is_issued=? where path_type=? and address_index<=? and hd_account_id=?";
        this.execUpdate(sql, new String[]{"1", Integer.toString(pathType.getValue()), Integer.toString(index), Integer.toString(hdAccountId)});
    }


    @Override
    public List<HDAccount.HDAccountAddress> belongAccount(int hdAccountId, List<String> addresses) {
        final List<HDAccount.HDAccountAddress> hdAccountAddressList = new ArrayList<HDAccount
                .HDAccountAddress>();
        List<String> temp = new ArrayList<String>();
        for (String str : addresses) {
            temp.add(Utils.format("'%s'", str));
        }
        String sql = "select address,pub,path_type,address_index,is_issued,is_synced,hd_account_id " +
                " from hd_account_addresses" +
                " where hd_account_id=? and address in (" + Utils.joinString(temp, ",") + ")";
        this.execQueryLoop(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                hdAccountAddressList.add(formatAddress(c));
                return null;
            }
        });
        return hdAccountAddressList;
    }


    @Override
    public long getHDAccountConfirmedBalance(int hdAccountId) {
        final long[] sum = {0};
        String unspendOutSql = "select ifnull(sum(a.out_value),0) sum from outs a,txs b where a" +
                ".tx_hash=b.tx_hash " +
                "  and a.out_status=? and a.hd_account_id=? and b.block_no is not null";
        this.execQueryOneRecord(unspendOutSql, new String[]{Integer.toString(Out.OutStatus.unspent.getValue()), Integer.toString
                (hdAccountId)}, new Function<ICursor, Void>() {
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


    @Override
    public List<Tx> getHDAccountUnconfirmedTx(int hdAccountId) {
        String sql = "select distinct a.* " +
                " from txs a,addresses_txs b,hd_account_addresses c" +
                " where a.tx_hash=b.tx_hash and b.address=c.address and c.hd_account_id=? and a.block_no is null" +
                " order by a.tx_hash";
        final List<Tx> txList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();

        IDb db = this.getReadDb();
        this.execQueryLoop(db, sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = AbstractTxProvider.applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                return null;
            }
        });
        sql = "select distinct a.* " +
                " from ins a, txs b,addresses_txs c,hd_account_addresses d" +
                " where a.tx_hash=b.tx_hash and b.tx_hash=c.tx_hash and c.address=d.address" +
                "   and b.block_no is null and d.hd_account_id=?" +
                " order by a.tx_hash,a.in_sn";
        this.execQueryLoop(db, sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                In inItem = AbstractTxProvider.applyCursorIn(c);
                Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                if (tx != null) {
                    tx.getIns().add(inItem);
                }
                return null;
            }
        });
        sql = "select distinct a.* " +
                " from outs a, txs b,addresses_txs c,hd_account_addresses d" +
                " where a.tx_hash=b.tx_hash and b.tx_hash=c.tx_hash and c.address=d.address" +
                "   and b.block_no is null and d.hd_account_id=?" +
                " order by a.tx_hash,a.out_sn";
        this.execQueryLoop(db, sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Out out = AbstractTxProvider.applyCursorOut(c);
                Tx tx = txDict.get(new Sha256Hash(out.getTxHash()));
                if (tx != null) {
                    tx.getOuts().add(out);
                }
                return null;
            }
        });
        return txList;
    }


    @Override
    public List<HDAccount.HDAccountAddress> getSigningAddressesForInputs(int hdAccountId, List<In> inList) {
        final List<HDAccount.HDAccountAddress> hdAccountAddressList =
                new ArrayList<HDAccount.HDAccountAddress>();
        for (In in : inList) {
            String sql = "select a.address,a.path_type,a.address_index,a.is_synced,a.hd_account_id" +
                    " from hd_account_addresses a ,outs b" +
                    " where a.address=b.out_address" +
                    " and b.tx_hash=? and b.out_sn=? and a.hd_account_id=?";
            OutPoint outPoint = in.getOutpoint();
            this.execQueryOneRecord(sql, new String[]{Base58.encode(in.getPrevTxHash()), Integer.toString
                    (outPoint.getOutSn()), Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    hdAccountAddressList.add(formatAddress(c));
                    return null;
                }
            });
        }
        return hdAccountAddressList;
    }


    @Override
    public void updateSyncdComplete(int hdAccountId, HDAccount.HDAccountAddress address) {
        String sql = "update hd_account_addresses set is_synced=? where address=? and hd_account_id=?";
        this.execUpdate(sql, new String[]{address.isSyncedComplete() ? "1" : "0", address.getAddress()
                , Integer.toString(hdAccountId)});
    }

    @Override
    public void updateSyncedForIndex(int hdAccountId, AbstractHD.PathType pathType, int index) {
        String sql = "update hd_account_addresses set is_synced=? where path_type=? and address_index>? and hd_account_id=?";
        this.execUpdate(sql, new String[]{"1", Integer.toString(pathType.getValue())
                , Integer.toString(index), Integer.toString(hdAccountId)});
    }

    @Override
    public void setSyncedNotComplete() {
        String sql = "update hd_account_addresses set is_synced=?";
        this.execUpdate(sql, new String[]{"0"});
    }

    @Override
    public int unSyncedAddressCount(int hdAccountId) {
        String sql = "select count(address) cnt from hd_account_addresses where is_synced=? and hd_account_id=? ";
        final int[] cnt = {0};
        this.execQueryOneRecord(sql, new String[]{"0", Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
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
        return cnt[0];
    }

    @Override
    public List<Tx> getRecentlyTxsByAccount(int hdAccountId, int greaterThanBlockNo, int limit) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        String sql = "select distinct a.* " +
                " from txs a, addresses_txs b, hd_account_addresses c" +
                " where a.tx_hash=b.tx_hash and b.address=c.address " +
                "   and ((a.block_no is null) or (a.block_no is not null and a.block_no>?)) " +
                "   and c.hd_account_id=?" +
                " order by ifnull(a.block_no,4294967295) desc, a.tx_time desc" +
                " limit ?";
        IDb db = this.getReadDb();
        this.execQueryLoop(db, sql, new String[]{Integer.toString(greaterThanBlockNo)
                , Integer.toString(hdAccountId), Integer.toString(limit)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = AbstractTxProvider.applyCursor(c);
                txItemList.add(txItem);
                return null;
            }
        });
        for (Tx item : txItemList) {
            this.addInsAndOuts(db, item);
        }
        return txItemList;
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
                In inItem = AbstractTxProvider.applyCursorIn(c);
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
                Out outItem = AbstractTxProvider.applyCursorOut(c);
                outItem.setTx(txItem);
                txItem.getOuts().add(outItem);
                return null;
            }
        });
    }

    @Override
    public long sentFromAccount(int hdAccountId, byte[] txHash) {
        String sql = "select  sum(o.out_value) out_value from ins i,outs o where" +
                " i.tx_hash=? and o.tx_hash=i.prev_tx_hash and i.prev_out_sn=o.out_sn and o" +
                ".hd_account_id=?";
        final long[] sum = {0};
        this.execQueryOneRecord(sql, new String[]{Base58.encode(txHash), Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
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

    @Override
    public List<Tx> getTxAndDetailByHDAccount(int hdAccountId) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();
        String sql = "select distinct a.* " +
                " from txs a,addresses_txs b,hd_account_addresses c" +
                " where a.tx_hash=b.tx_hash and b.address=c.address and c.hd_account_id=?" +
                " order by ifnull(block_no,4294967295) desc,a.tx_hash";
        IDb db = this.getReadDb();
        final StringBuilder txsStrBuilder = new StringBuilder();
        this.execQueryLoop(db, sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = AbstractTxProvider.applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txItemList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                txsStrBuilder.append("'").append(Base58.encode(txItem.getTxHash())).append("'")
                        .append(",");
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
                    In inItem = AbstractTxProvider.applyCursorIn(c);
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
                    Out out = AbstractTxProvider.applyCursorOut(c);
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
    public List<Tx> getTxAndDetailByHDAccount(int hdAccountId, int page) {
        final List<Tx> txItemList = new ArrayList<Tx>();
        final HashMap<Sha256Hash, Tx> txDict = new HashMap<Sha256Hash, Tx>();
        String sql = "select distinct a.* " +
                " from txs a,addresses_txs b,hd_account_addresses c" +
                " where a.tx_hash=b.tx_hash and b.address=c.address and c.hd_account_id=?" +
                " order by ifnull(block_no,4294967295) desc,a.tx_hash" +
                " limit ?,?";
        IDb db = this.getReadDb();
        final StringBuilder txsStrBuilder = new StringBuilder();
        this.execQueryLoop(db, sql, new String[]{
                Integer.toString(hdAccountId)
                , Integer.toString((page - 1) * BitherjSettings.TX_PAGE_SIZE)
                , Integer.toString(BitherjSettings.TX_PAGE_SIZE)
        }, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Tx txItem = AbstractTxProvider.applyCursor(c);
                txItem.setIns(new ArrayList<In>());
                txItem.setOuts(new ArrayList<Out>());
                txItemList.add(txItem);
                txDict.put(new Sha256Hash(txItem.getTxHash()), txItem);
                txsStrBuilder.append("'").append(Base58.encode(txItem.getTxHash())).append("'")
                        .append(",");
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
                    In inItem = AbstractTxProvider.applyCursorIn(c);
                    Tx tx = txDict.get(new Sha256Hash(inItem.getTxHash()));
                    if (tx != null) {
                        tx.getIns().add(inItem);
                    }
                    return null;
                }
            });
            sql = Utils.format("select b.* from outs b where b.tx_hash in (%s)" +
                    " order by b.tx_hash,b.out_sn", txs);
            this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    Out out = AbstractTxProvider.applyCursorOut(c);
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
    public int hdAccountTxCount(int hdAccountId) {
        final int[] result = {0};
        String sql = "select count( distinct a.tx_hash) cnt from addresses_txs a ," +
                "hd_account_addresses b where a.address=b.address and b.hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
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

    @Override
    public int getUnspendOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType
            pathType) {
        final int[] result = {0};
        String sql = "select count(tx_hash) cnt from outs where out_address in " +
                "(select address from hd_account_addresses where path_type =? and out_status=?) " +
                "and hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(pathType.getValue())
                , Integer.toString(Out.OutStatus.unspent.getValue())
                , Integer.toString(hdAccountId)
        }, new Function<ICursor, Void>() {
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

    @Override
    public List<Out> getUnspendOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType
            pathType) {
        String sql = "select * from outs where out_address in " +
                "(select address from hd_account_addresses where path_type =? and " +
                "out_status=?) " +
                "and hd_account_id=?";
        final List<Out> outList = new ArrayList<Out>();
        this.execQueryLoop(sql, new String[]{Integer.toString(pathType.getValue())
                , Integer.toString(Out.OutStatus.unspent.getValue())
                , Integer.toString(hdAccountId)
        }, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outList.add(AbstractTxProvider.applyCursorOut(c));
                return null;
            }
        });
        return outList;
    }

    @Override
    public int getUnconfirmedSpentOutCountByHDAccountWithPath(int hdAccountId, AbstractHD.PathType
            pathType) {
        final int[] result = {0};
        String sql = "select count(0) cnt from outs o, ins i, txs t, hd_account_addresses a " +
                "  where o.tx_hash=i.prev_tx_hash and o.out_sn=i.prev_out_sn and t.tx_hash=i.tx_hash " +
                "    and o.out_address=a.address and a.path_type=?" +
                "    and o.out_status=? and t.block_no is null and a.hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(pathType.getValue())
                , Integer.toString(Out.OutStatus.spent.getValue())
                , Integer.toString(hdAccountId)
        }, new Function<ICursor, Void>() {
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

    @Override
    public List<Out> getUnconfirmedSpentOutByHDAccountWithPath(int hdAccountId, AbstractHD.PathType
            pathType) {
        String sql = "select o.* from outs o, ins i, txs t, hd_account_addresses a " +
                "  where o.tx_hash=i.prev_tx_hash and o.out_sn=i.prev_out_sn and t.tx_hash=i.tx_hash " +
                "    and o.out_address=a.address and a.path_type=?" +
                "    and o.out_status=? and t.block_no is null and a.hd_account_id=?";
        final List<Out> outList = new ArrayList<Out>();
        this.execQueryLoop(sql, new String[]{Integer.toString(pathType.getValue())
                , Integer.toString(Out.OutStatus.spent.getValue())
                , Integer.toString(hdAccountId)
        }, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outList.add(AbstractTxProvider.applyCursorOut(c));
                return null;
            }
        });
        return outList;
    }

    @Override
    public boolean requestNewReceivingAddress(int hdAccountId) {
        int issuedIndex = this.issuedIndex(hdAccountId, AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        final boolean[] result = {false};
        if (issuedIndex >= HDAccount.MaxUnusedNewAddressCount - 2) {
            String sql = "select count(0) from hd_account_addresses a,outs b " +
                    " where a.address=b.out_address and a.hd_account_id=? and a.path_type=0 and a.address_index>? and a.is_issued=?";
            this.execQueryOneRecord(sql, new String[]{Integer.toString(hdAccountId), Integer.toString(issuedIndex - HDAccount.MaxUnusedNewAddressCount + 1), "1"}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    result[0] = c.getInt(0) > 0;
                    return null;
                }
            });
        } else {
            result[0] = true;
        }
        if (result[0]) {
            this.updateIssuedIndex(hdAccountId, AbstractHD.PathType.EXTERNAL_ROOT_PATH, issuedIndex + 1);
        }
        return result[0];
    }

    private HDAccount.HDAccountAddress formatAddress(ICursor c) {
        String address = null;
        byte[] pubs = null;
        AbstractHD.PathType ternalRootType = AbstractHD.PathType.EXTERNAL_ROOT_PATH;
        int index = 0;
        boolean isIssued = false;
        boolean isSynced = true;
        int hdAccountId = 0;
        HDAccount.HDAccountAddress hdAccountAddress = null;
        int idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS);
        if (idColumn != -1) {
            address = c.getString(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.PUB);
        if (idColumn != -1) {
            try {
                pubs = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.PATH_TYPE);
        if (idColumn != -1) {
            ternalRootType = AbstractHD.getTernalRootType(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.ADDRESS_INDEX);
        if (idColumn != -1) {
            index = c.getInt(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.IS_ISSUED);
        if (idColumn != -1) {
            isIssued = c.getInt(idColumn) == 1;
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.IS_SYNCED);
        if (idColumn != -1) {
            isSynced = c.getInt(idColumn) == 1;
        }
        idColumn = c.getColumnIndex(AbstractDb.HDAccountAddressesColumns.HD_ACCOUNT_ID);
        if (idColumn != -1) {
            hdAccountId = c.getInt(idColumn);
        }
        hdAccountAddress = new HDAccount.HDAccountAddress(address, pubs,
                ternalRootType, index, isIssued, isSynced, hdAccountId);
        return hdAccountAddress;
    }

    public List<Out> getUnspentOutputByBlockNo(long blockNo, int hdSeedId) {
        final List<Out> outItems = new ArrayList<Out>();
        String sqlPreUnspentOut = "select a.* from outs a,txs b where a.tx_hash=b.tx_hash and " +
                "a.hd_account_id=? and a.out_status=? and b.block_no is not null and " +
                "b.block_no<?";
        String sqlPostSpentOuts = "select a.* from outs a, txs out_b, ins i, txs b " +
                "where a.tx_hash=out_b.tx_hash and a.out_sn=i.prev_out_sn and " +
                "a.tx_hash=i.prev_tx_hash and a.hd_account_id=? and b.tx_hash=i.tx_hash and " +
                "a.out_status=? and out_b.block_no is not null and " +
                "out_b.block_no<? and (b.block_no>=? or b.block_no is null)";

        this.execQueryLoop(sqlPreUnspentOut, new String[] {Integer.toString(hdSeedId),Integer.toString(0),
                Long.toString(blockNo)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outItems.add(applyCursorOut(c));
                return null;
            }
        });

        this.execQueryLoop(sqlPostSpentOuts, new String[] {Integer.toString(hdSeedId),Integer.toString(1),
                Long.toString(blockNo),Long.toString(blockNo)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                outItems.add(applyCursorOut(c));
                return null;
            }
        });
        return outItems;
    }
}
