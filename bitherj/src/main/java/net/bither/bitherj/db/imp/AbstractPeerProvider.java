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

import net.bither.bitherj.core.Peer;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IPeerProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IDb;
import net.bither.bitherj.utils.Utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractPeerProvider extends AbstractProvider implements IPeerProvider {

    public List<Peer> getAllPeers() {
        final List<Peer> peers = new ArrayList<Peer>();
        String sql = "select * from peers";
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                Peer peer = applyCursor(c);
                if (peer != null) {
                    peers.add(peer);
                }
                return null;
            }
        });
        return peers;
    }

//    @Override
//    public ArrayList<InetAddress> exists(ArrayList<InetAddress> peerAddresses) {
//        ArrayList<InetAddress> exists = new ArrayList<InetAddress>();
//        List<Peer> peerItemList = getAllPeers();
//        for (Peer item : peerItemList) {
//            if (peerAddresses.contains(item.getPeerAddress())) {
//                exists.add(item.getPeerAddress());
//            }
//        }
//        return exists;
//    }

    @Override
    public void addPeers(List<Peer> items) {
        List<Peer> addItems = new ArrayList<Peer>();
        List<Peer> allItems = getAllPeers();
        for (Peer peerItem : items) {
            if (!allItems.contains(peerItem) && !addItems.contains(peerItem)) {
                addItems.add(peerItem);
            }
        }
        if (addItems.size() > 0) {
            String sql = "insert into peers(peer_address,peer_port,peer_services,peer_timestamp,peer_connected_cnt) values(?,?,?,?,?)";
            IDb writeDb = this.getWriteDb();
            writeDb.beginTransaction();
            for (Peer item : addItems) {
                this.execUpdate(writeDb, sql, new String[]{
                        Long.toString(Utils.parseLongFromAddress(item.getPeerAddress()))
                        , Integer.toString(item.getPeerPort())
                        , Long.toString(item.getPeerServices())
                        , Integer.toString(item.getPeerTimestamp())
                        , Integer.toString(item.getPeerConnectedCnt())});
            }
            writeDb.endTransaction();
        }
    }

    @Override
    public void removePeer(InetAddress address) {
        String sql = "delete from peers where peer_address=?";
        this.execUpdate(sql, new String[] {Long.toString(Utils.parseLongFromAddress(address))});
    }

    public void conncetFail(InetAddress address) {
        long addressLong = Utils.parseLongFromAddress(address);
        String sql = "select count(0) cnt from peers where peer_address=? and peer_connected_cnt=0";
        final int[] cnt = {0};
        this.execQueryOneRecord(sql, new String[]{Long.toString(addressLong)}, new Function<ICursor, Void>() {
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
            sql = "update peers set peer_connected_cnt=peer_connected_cnt+1 where peer_address=?";
            this.execUpdate(sql, new String[] {Long.toString(addressLong)});
        } else {
            sql = "update peers set peer_connected_cnt=2 where peer_address=?";
            this.execUpdate(sql, new String[]{Long.toString(addressLong)});
        }
    }

    public void connectSucceed(InetAddress address) {
        String sql = "update peers set peer_connected_cnt=?,peer_timestamp=? where peer_address=?";
        long addressLong = Utils.parseLongFromAddress(address);
        this.execUpdate(sql, new String[] {"1", Long.toString(new Date().getTime()), Long.toString(addressLong)});
    }

    public List<Peer> getPeersWithLimit(int limit) {
        String sql = "select * from peers order by peer_address limit ?";
        final List<Peer> peerItemList = new ArrayList<Peer>();
        this.execQueryLoop(sql, new String[]{Integer.toString(limit)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Peer peer = applyCursor(c);
                if (peer != null) {
                    peerItemList.add(peer);
                }
                return null;
            }
        });
        return peerItemList;
    }

    public void clearIPV6() {
        String sql = "delete from peers where peer_address>? or peer_address<? or peer_address=0";
        this.execUpdate(sql, new String[]{Integer.toString(Integer.MAX_VALUE), Integer.toString(Integer.MIN_VALUE)});
    }

    public void cleanPeers() {
        int maxPeerSaveCnt = 12;
        String disconnectingPeerCntSql = "select count(0) cnt from peers where peer_connected_cnt<>1";
        final int[] disconnectingPeerCnt = {0};
        this.execQueryOneRecord(disconnectingPeerCntSql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    disconnectingPeerCnt[0] = c.getInt(idColumn);
                }
                return null;
            }
        });

        if (disconnectingPeerCnt[0] > maxPeerSaveCnt) {
            String sql = "select peer_timestamp from peers where peer_connected_cnt<>1 " +
                    " limit 1 offset ?";
            final long[] timestamp = {0};
            this.execQueryOneRecord(sql, new String[]{Integer.toString(maxPeerSaveCnt)}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    int idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_TIMESTAMP);
                    if (idColumn != -1) {
                        timestamp[0] = c.getLong(idColumn);
                    }
                    return null;
                }
            });
            if (timestamp[0] > 0) {
                sql = "delete from peers where peer_connected_cnt<>1 and peer_timestamp<=?";
                this.execUpdate(sql, new String[]{Long.toString(timestamp[0])});
            }
        }
    }

    private void deleteUnknowHost(long address) {
        String sql = "delete from peers where peer_address=?";
        this.execUpdate(sql, new String[]{Long.toString(address)});
    }

    private Peer applyCursor(ICursor c) {
        InetAddress address = null;
        int idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_ADDRESS);
        if (idColumn != -1) {
            long addressLong = c.getLong(idColumn);
            try {
                if (addressLong >= Integer.MIN_VALUE && addressLong <= Integer.MAX_VALUE) {
                    address = Utils.parseAddressFromLong(c.getLong(idColumn));
                } else {
                    clearIPV6();
                }
            } catch (UnknownHostException e) {
                deleteUnknowHost(addressLong);
                e.printStackTrace();
                return null;
            }
        }
        Peer peerItem = new Peer(address);
        idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_CONNECTED_CNT);
        if (idColumn != -1) {
            peerItem.setPeerConnectedCnt(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_PORT);
        if (idColumn != -1) {
            peerItem.setPeerPort(c.getInt(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_SERVICES);
        if (idColumn != -1) {
            peerItem.setPeerServices(c.getLong(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.PeersColumns.PEER_TIMESTAMP);
        if (idColumn != -1) {
            peerItem.setPeerTimestamp(c.getInt(idColumn));
        }
        return peerItem;
    }

    public void recreate() {
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        this.execUpdate(writeDb, "drop table peers", null);
        this.execUpdate(writeDb, AbstractDb.CREATE_PEER_SQL, null);
        writeDb.endTransaction();
    }
}
