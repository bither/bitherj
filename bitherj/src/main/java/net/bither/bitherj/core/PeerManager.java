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

package net.bither.bitherj.core;

import net.bither.bitherj.BitherjApplication;
import net.bither.bitherj.db.PeerProvider;
import net.bither.bitherj.db.TxProvider;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.DnsDiscovery;
import net.bither.bitherj.utils.NotificationUtil;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class PeerManager {
    public static final String ConnectedChangeBroadcast = PeerManager.class.getPackage()
            .getName() + ".peer_manager_connected_change";
    private static final Logger log = LoggerFactory.getLogger(PeerManager.class);
    private static final int MAX_CONNECT_FAILURE_COUNT = 12;

    private static final int MaxPeerCount = 100;
    private static final int MaxConnectFailure = 20;

    private static PeerManager instance = new PeerManager();

    private PeerManagerExecutorService executor;
    private boolean running;
    private boolean connected;

    private long tweak, syncStartHeight, filterUpdateHeight;
    private long lastRelayTime;
//    public long earliestKeyTime;

    private BloomFilter bloomFilter;
    private int bloomFilterElementCount;
    private double filterFpRate;

    private int connectFailure;
    private final HashSet<Peer> connectedPeers;
    private final HashSet<Peer> abandonPeers;
    private final HashMap<Sha256Hash, HashSet<Peer>> txRelays;
    private final HashMap<Sha256Hash, Tx> publishedTx;

    private boolean synchronizing;
    private Peer downloadingPeer;

    private Timer syncTimeOutTimer;

    public static final PeerManager instance() {
        return instance;
    }

    private PeerManager() {
        running = false;
        connected = false;
        connectedPeers = new HashSet<Peer>();
        abandonPeers = new HashSet<Peer>();
        txRelays = new HashMap<Sha256Hash, HashSet<Peer>>();
        publishedTx = new HashMap<Sha256Hash, Tx>();
        tweak = new Random().nextLong();
//        earliestKeyTime = new Date().getTime() / 1000;//TODO how to set this field
        executor = new PeerManagerExecutorService();
        initPublishedTx();
    }

    private void initPublishedTx() {
        for (Tx tx : TxProvider.getInstance().getPublishedTxs()) {
            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED) {
                publishedTx.put(new Sha256Hash(tx.getTxHash()), tx);
            }
        }

    }

    public boolean isConnected() {
        return connected;
    }

    public boolean isRunning() {
        return running;
    }

    public void start() {
        if (!running) {
            log.info("peer manager start");
            running = true;
            bloomFilter = null;
            if (this.connectFailure >= MAX_CONNECT_FAILURE_COUNT)
                this.connectFailure = 0;
            reconnect();
        } else {
            log.info("peer manager call start, but it is connected already");
        }
    }

    public void stop() {
        if (running) {
            log.info("peer manager stop");
            running = false;
            if (connected) {
                NotificationUtil.removeBroadcastPeerState();
                bloomFilter = null;
                connected = false;
                sendConnectedChangeBroadcast();
                executor.getQueue().clear();
                executor.submit(new Runnable() {
                    @Override
                    public void run() {
                        for (Peer peer : connectedPeers) {
                            peer.disconnect();
                        }
                    }
                });
            }
        } else {
            log.info("peer manager call stop, but it does not running");
        }
    }

    public long getLastBlockHeight() {
        Block lastBlock = BlockChain.getInstance().lastBlock;
        return lastBlock == null ? 0 : lastBlock.getBlockNo();
    }

    private void reconnect() {
        if (!running) {
            return;
        }
        executor.submit(new Runnable() {
            @Override
            public void run() {
                Iterator<Peer> iterator = connectedPeers.iterator();
                while (iterator.hasNext()) {
                    if (iterator.next().state == Peer.State.Disconnected) {
                        iterator.remove();
                    }
                }
                if (connectedPeers.size() >= BitherjSettings.MaxPeerConnections) {
                    return;
                }
                HashSet<Peer> peers = bestPeers();
                for (Peer p : peers) {
                    if (connectedPeers.size() >= BitherjSettings.MaxPeerConnections) {
                        break;
                    }
                    if (!connectedPeers.contains(p)) {
                        connectedPeers.add(p);
                        p.connect();
                    }
                }
                sendPeerCountChangeNotification();
                if (connectedPeers.size() == 0) {
                    stop();
                }
            }
        });
    }

    public List<Peer> getConnectedPeers() {
        List<Peer> peerList = new ArrayList<Peer>();
        for (Peer peer : connectedPeers) {
            peerList.add(peer);

        }
        return peerList;
    }

    private HashSet<Peer> bestPeers() {
        HashSet<Peer> peers = new HashSet<Peer>();
        peers.addAll(PeerProvider.getInstance().getPeersWithLimit(BitherjSettings
                .MaxPeerConnections));
        if (peers.size() < BitherjSettings.MaxPeerConnections) {
            if (getPeersFromDns().size() > 0) {
                peers.clear();
                peers.addAll(PeerProvider.getInstance().getPeersWithLimit(BitherjSettings
                        .MaxPeerConnections));
            }
        }
        log.info("peer manager got " + peers.size() + " best " +
                "peers");
        return peers;
    }

    private HashSet<Peer> getPeersFromDns() {
        HashSet<Peer> peers = new HashSet<Peer>();
        Peer[] ps = DnsDiscovery.instance().getPeers(5, TimeUnit.SECONDS);
        Collections.addAll(peers, ps);
        PeerProvider.getInstance().addPeers(new ArrayList<Peer>(peers));
        return peers;
    }

    @Override
    protected void finalize() throws Throwable {
        executor.shutdownNow();
        super.finalize();
    }

    private void abandonPeer(final Peer peer) {
        peer.connectError();
        peer.disconnect();
        connectedPeers.remove(peer);
        abandonPeers.add(peer);
        reconnect();
    }

    private void addRelayedPeers(final List<Peer> peers) {
        executor.submit(new Runnable() {
            @Override
            public void run() {
                ArrayList<Peer> result = new ArrayList<Peer>();
                for (Peer peer : peers) {
                    if (!abandonPeers.contains(peer)) {
                        result.add(peer);
                    }
                }
                PeerProvider.getInstance().addPeers(result);
                PeerProvider.getInstance().cleanPeers();
            }
        });
    }

    private void setBlockHeightForTxs(final int height, final List<byte[]> txHashes) {
        if (txHashes == null || txHashes.size() == 0) {
            return;
        }
        if (height != BitherjSettings.TX_UNCONFIRMED) {
            // update all tx in db
            log.info("update {} txs confirmation", txHashes.size());
            TxProvider.getInstance().confirmTx(height, txHashes);
            // update all address 's tx and balance
            for (Address address : AddressManager.getInstance().getAllAddresses()) {
                address.setBlockHeight(txHashes, height);
            }

            // remove confirmed tx from publish list and relay counts
            for (byte[] hash : txHashes) {
                publishedTx.remove(new Sha256Hash(hash));
                txRelays.remove(new Sha256Hash(hash));
            }
        }
    }

    public void peerConnected(final Peer peer) {
        if (running) {
            if (peer.getVersionLastBlockHeight() + 10 < getLastBlockHeight()) {
                log.warn("Peer height low abandon : " + peer
                        .getPeerAddress().getHostAddress());
                executor.submit(new Runnable() {
                    @Override
                    public void run() {
                        abandonPeer(peer);
                    }
                });
                return;
            }
            if (!connected) {
                connected = true;
                sendConnectedChangeBroadcast();
            }
            log.info("Peer {} connected", peer.getPeerAddress().getHostAddress());
            connectFailure = 0;
            bloomFilter = null;
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    peer.connectSucceed();
                    if (connected && ((downloadingPeer != null && downloadingPeer
                            .getVersionLastBlockHeight() >= peer.getVersionLastBlockHeight()) ||
                            getLastBlockHeight() >= peer.getVersionLastBlockHeight())) {
                        if (downloadingPeer != null && getLastBlockHeight() < downloadingPeer
                                .getVersionLastBlockHeight()) {
                            return; // don't load bloom filter yet if we're syncing
                        }
                        peer.sendFilterLoadMessage(bloomFilterForPeer(peer));
                        for (Tx tx : publishedTx.values()) {
                            if (tx.getSource() > 0 && tx.getSource() <= MaxPeerCount) {
                                peer.sendInvMessageWithTxHash(new Sha256Hash(tx.getTxHash()));
                            }
                        }
                        peer.sendMemPoolMessage();
                        return; // we're already connected to a download peer
                    }
                    Peer dp = peer;
                    for (Peer p : connectedPeers) {
                        if ((p.pingTime < dp.pingTime && p.getVersionLastBlockHeight() >= dp
                                .getVersionLastBlockHeight()) || p.getVersionLastBlockHeight() > dp
                                .getVersionLastBlockHeight()) {
                            dp = p;
                        }
                    }
                    if (downloadingPeer != null) {
                        downloadingPeer.disconnect();
                    }
                    downloadingPeer = dp;
                    connected = true;

                    // every time a new wallet address is added, the bloom filter has to be
                    // rebuilt, and each address is only used for
                    // one transaction, so here we generate some spare addresses to avoid
                    // rebuilding the filter each time a wallet
                    // transaction is encountered during the blockchain download (generates twice
                    // the external gap limit for both
                    // address chains)

                    bloomFilter = null; // make sure the bloom filter is updated with any newly
                    // generated addresses
                    dp.sendFilterLoadMessage(bloomFilterForPeer(dp));

                    if (getLastBlockHeight() < dp.getVersionLastBlockHeight()) {

                        lastRelayTime = 0;
                        synchronizing = true;

                        scheduleTimeoutTimer(BitherjSettings.PROTOCOL_TIMEOUT);
                        if (doneSyncFromSPV()) {
                            dp.sendGetBlocksMessage(BlockChain.getInstance().getBlockLocatorArray
                                    (), null);
                        } else {
                            dp.sendGetHeadersMessage(BlockChain.getInstance()
                                    .getBlockLocatorArray(), null);
                        }
                    } else { // we're already synced
                        syncStopped();
                        dp.sendGetAddrMessage();
                        syncStartHeight = 0;
                        NotificationUtil.sendBroadcastSyncSPVFinished(true);
                    }
                }
            });
        } else {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    peer.disconnect();
                }
            });
        }
    }

    private void syncStopped() {
        synchronizing = false;

        for (Peer p : connectedPeers) { // after syncing, load filters and get mempools from the
            // other peers
            if (p != downloadingPeer) {
                p.sendFilterLoadMessage(bloomFilterForPeer(p));
            }
            for (Tx tx : publishedTx.values()) {
                if (tx.getSource() > 0 && tx.getSource() <= MaxPeerCount) {
                    p.sendInvMessageWithTxHash(new Sha256Hash(tx.getTxHash()));
                }
            }
            p.sendMemPoolMessage();
        }
        cancelTimeoutTimer();
    }

    public void peerDisconnected(final Peer peer, final Peer.DisconnectReason reason) {
        executor.submit(new Runnable() {
            @Override
            public void run() {
                if (reason == null || reason == Peer.DisconnectReason.Normal) {
                    peer.connectFail();
                } else if (reason == Peer.DisconnectReason.Timeout) {
                    if (peer.getPeerConnectedCnt() > MAX_CONNECT_FAILURE_COUNT) {
                        // Failed too many times, we don't want to play with it any more.
                        abandonPeer(peer);
                    } else {
                        peer.connectFail();
                    }
                } else {
                    peer.connectError();
                    connectFailure++;
                }
                int previousConnectedCount = connectedPeers.size();
                connectedPeers.remove(peer);
                log.info("Peer disconnected {} , remaining {} peers , reason: " + reason,
                        peer.getPeerAddress().getHostAddress(), connectedPeers.size());
                if (previousConnectedCount > 0 && connectedPeers.size() == 0) {
                    connected = false;
                    sendConnectedChangeBroadcast();
                }

                sendPeerCountChangeNotification();

                for (Sha256Hash txHash : txRelays.keySet()) {
                    txRelays.get(txHash).remove(peer);
                }

                if (downloadingPeer != null && downloadingPeer.equals(peer)) {
                    connected = false;
                    downloadingPeer = null;
                    syncStopped();
                    if (connectFailure > MaxConnectFailure) {
                        connectFailure = MaxConnectFailure;
                    }
                }

                if (!connected && connectFailure == MaxConnectFailure) {
                    syncStartHeight = 0;
                    //TODO notify sync fail
                    log.info("connect failed {} times, we give up", connectFailure);
                } else if (connectFailure < MaxConnectFailure) {
                    reconnect();
                }
            }
        });
    }


    public void relayedPeers(Peer fromPeer, List<Peer> peers) {
        if (!isRunning()) {
            return;
        }
        if (fromPeer == this.downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        }
        if (peers.size() > MaxPeerCount) {
            peers = peers.subList(0, MaxPeerCount);
        }
        addRelayedPeers(peers);
    }

    public void relayedTransaction(final Peer fromPeer, final Tx tx) {
        if (!isRunning()) {
            return;
        }
        if (fromPeer == downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        }
        executor.submit(new Runnable() {
            @Override
            public void run() {

                boolean isAlreadyInDb = TxProvider.getInstance().isExist(tx.getTxHash());
                boolean isRel = AddressManager.getInstance().registerTx(tx,
                        Tx.TxNotificationType.txReceive);
                if (isRel) {
                    if (publishedTx.get(new Sha256Hash(tx.getTxHash())) == null) {
                        publishedTx.put(new Sha256Hash(tx.getTxHash()), tx);
                    }

                    // keep track of how many peers relay a tx, this indicates how likely it is
                    // to be
                    // confirmed in future blocks
                    if (txRelays.get(new Sha256Hash(tx.getTxHash())) == null) {
                        txRelays.put(new Sha256Hash(tx.getTxHash()), new HashSet<Peer>());
                    }

                    long count = txRelays.get(new Sha256Hash(tx.getTxHash())).size();
                    txRelays.get(new Sha256Hash(tx.getTxHash())).add(fromPeer);
                    if (txRelays.get(new Sha256Hash(tx.getTxHash())).size() > count) {
                        tx.sawByPeer();
                    }

                    if (!isAlreadyInDb) {
                        bloomFilter = null; // reset the filter so a new one will be created with
                        // the new
                        // wallet addresses

                        for (Peer p : connectedPeers) {
                            p.sendFilterLoadMessage(bloomFilterForPeer(p));
                        }
                    }

                    // after adding addresses to the filter, re-request upcoming blocks that were
                    // requested using the old one
                    if (downloadingPeer != null && BlockChain.getInstance().lastBlock != null) {
                        downloadingPeer.refetchBlocksFrom(new Sha256Hash(BlockChain.getInstance()
                                .lastBlock.getBlockHash()));
                    }
                }
            }
        });
    }

    public void relayedBlockHeadersForMainChain(final Peer fromPeer, final List<Block> blocks) {
        if (!isRunning()) {
            return;
        }
        if (blocks == null || blocks.size() == 0) {
            return;
        }
        if (fromPeer == downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        }
        executor.submit(new Runnable() {
            @Override
            public void run() {
                Block oldLastBlock = BlockChain.getInstance().getLastBlock();
                // do not need earliest time
//                ArrayList<Block> blocksToRelay = new ArrayList<Block>();
//                for (Block block : blocks) {
//                    if ((block.getTxHashes() == null || block.getTxHashes().size() == 0) && block
//                            .getBlockTime() - new Date().getTime() / 1000 + 60 * 60 * 24 * 7 >
//                            earliestKeyTime) {
//                        continue;
//                    } else {
//                        if (!blocksToRelay.contains(block)) {
//                            blocksToRelay.add(block);
//                        }
//                    }
//                }
                try {
                    int relayedCount = BlockChain.getInstance().relayedBlockHeadersForMainChain(blocks);
                    if (relayedCount == blocks.size()) {
                        log.info("Peer {} relay {} block headers OK, last block No.{}, total block: {}", fromPeer.getPeerAddress().getHostAddress(), relayedCount, BlockChain.getInstance().getLastBlock().getBlockNo(), BlockChain.getInstance().getBlockCount());
                    } else {
                        abandonPeer(fromPeer);
                        log.info("Peer {} relay {}/{} block headers. drop this peer", fromPeer.getPeerAddress().getHostAddress(), relayedCount, blocks.size());
                    }
                } catch (Exception e) {
                    abandonPeer(fromPeer);
                    log.warn("Peer {} relay block Error. Drop it", fromPeer.getPeerAddress().getHostAddress());
                }
                if (getLastBlockHeight() == fromPeer.getVersionLastBlockHeight()) {
                    syncStopped();
                    fromPeer.sendGetAddrMessage(); // request a list of other bitcoin peers
                    syncStartHeight = 0;
                    if (!doneSyncFromSPV()) {
                        log.info("Done sync from spv");
                        NotificationUtil.sendBroadcastSyncSPVFinished(true);
                    }
                }
                if (oldLastBlock != null && BlockChain.getInstance().getLastBlock() != null &&
                        oldLastBlock.getBlockNo() != BlockChain.getInstance().getLastBlock()
                                .getBlockNo()) {
                    NotificationUtil.sendLastBlockChange();
                }
            }
        });
    }

    public void relayedBlock(final Peer fromPeer, final Block block) {
        if (!isRunning()) {
            return;
        }
        if (block == null) {
            return;
        }
        if (fromPeer == downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        }
        // do not need earliest time
//        if ((block.getTxHashes() == null || block.getTxHashes().size() == 0) && block
//                .getBlockTime() - new Date().getTime() / 1000 + 60 * 60 * 24 * 7 >
//                earliestKeyTime) {
//            return;
//        }

        // track the observed bloom filter false positive rate using a low pass filter to smooth
        // out variance
        if (fromPeer == downloadingPeer && block.getTxHashes() != null && block.getTxHashes()
                .size() > 0) {
            // 1% low pass filter, also weights each block by total transactions,
            // using 400 tx per block as typical
            filterFpRate = filterFpRate * (1.0 - 0.01 * block.getTxHashes().size() / 400) + 0.01
                    * block.getTxHashes().size() / 400;

            // todo: do not check bloom filter now. may be it's useful
        }

        executor.submit(new Runnable() {
            @Override
            public void run() {
                Block oldLastBlock = BlockChain.getInstance().lastBlock;
                try {
                    if (BlockChain.getInstance().relayedBlock(block)) {
                        if (block.getTxHashes() != null) {
                            setBlockHeightForTxs(block.getBlockNo(), block.getTxHashes());
                        }
                    } else {
                        abandonPeer(fromPeer);
                        log.warn("Peer {} relay block {} failed, drop this peer", fromPeer.getPeerAddress().getHostAddress(), Utils.hashToString(block.getBlockHash()));
                    }
                } catch (ProtocolException e) {
                    abandonPeer(fromPeer);
                    log.warn("Peer {} relay block {} error, drop this peer", fromPeer.getPeerAddress().getHostAddress(), Utils.hashToString(block.getBlockHash()));
                }

                if (block.getBlockNo() == fromPeer.getVersionLastBlockHeight() && block.getBlockNo() ==
                        getLastBlockHeight()) {
                    syncStopped();
                    fromPeer.sendGetAddrMessage(); // request a list of other bitcoin peers
                    syncStartHeight = 0;
                    if (!doneSyncFromSPV()) {
                        NotificationUtil.sendBroadcastSyncSPVFinished(true);
                    }
                }

                if (block == BlockChain.getInstance().lastBlock && BlockChain.getInstance()
                        .singleBlocks.get(block.getBlockHash()) != null) {
                    Block b = BlockChain.getInstance().singleBlocks.get(block.getBlockHash());
                    BlockChain.getInstance().singleBlocks.remove(block.getBlockHash());
                    relayedBlock(fromPeer, b);
                }

                if (oldLastBlock != null && BlockChain.getInstance().getLastBlock() != null &&
                        oldLastBlock.getBlockNo() != BlockChain.getInstance().getLastBlock()
                                .getBlockNo()) {
                    Block lastBlock = BlockChain.getInstance().getLastBlock();
                    log.info("Peer {} relay new best block No.{}, hash: {}, txs: {}", fromPeer.getPeerAddress().getHostAddress(), lastBlock.getBlockNo(), Utils.hashToString(lastBlock.getBlockHash()), lastBlock.getTxHashes() == null ? 0 : lastBlock.getTxHashes().size());
                    NotificationUtil.sendLastBlockChange();
                }
            }
        });
    }

    public Tx requestedTransaction(final Peer byPeer, final byte[] txHash) {
        if (!isRunning()) {
            return null;
        }
        final Tx tx = publishedTx.get(new Sha256Hash(txHash));
        if (tx != null) {
            bloomFilter = null;
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    if (txRelays.get(new Sha256Hash(txHash)) == null) {
                        txRelays.put(new Sha256Hash(txHash), new HashSet<Peer>());
                    }
                    long count = txRelays.get(new Sha256Hash(txHash)).size();
                    txRelays.get(new Sha256Hash(txHash)).add(byPeer);
                    if (txRelays.get(new Sha256Hash(txHash)).size() > count) {
                        tx.sawByPeer();
                    }
                }
            });
        }
        return tx;
    }

    public BloomFilter bloomFilterForPeer(Peer peer) {
        if (!isRunning()) {
            return null;
        }
        BloomFilter filter = getBloomFilter();
        filterFpRate = filter.getFalsePositiveRate(bloomFilterElementCount);
        filterUpdateHeight = getLastBlockHeight();
        return filter;
    }

    public void publishTransaction(final Tx tx) throws PublishUnsignedTxException {
        if (!tx.isSigned()) {
            throw new PublishUnsignedTxException();
        }

        AddressManager.getInstance().registerTx(tx, Tx.TxNotificationType.txSend);

        publishedTx.put(new Sha256Hash(tx.getTxHash()), tx);

        executor.submit(new Runnable() {
            @Override
            public void run() {
                bloomFilter = null;
                for (Peer p : connectedPeers) {
                    p.sendFilterLoadMessage(getBloomFilter());
                }
                if (connectedPeers.size() > 0) {
                    Iterator<Peer> iterator = connectedPeers.iterator();
                    Sha256Hash hash = new Sha256Hash(tx.getTxHash());
                    if (iterator.hasNext()) {
                        iterator.next();
                    }
                    while (iterator.hasNext()) {
                        iterator.next().sendInvMessageWithTxHash(hash);
                    }
                }
            }
        });
    }

    private BloomFilter getBloomFilter() {
        if (bloomFilter == null) {

            filterUpdateHeight = getLastBlockHeight();
            filterFpRate = BloomFilter.DEFAULT_BLOOM_FILTER_FP_RATE;

            if (downloadingPeer != null && filterUpdateHeight + BitherjSettings
                    .BLOCK_DIFFICULTY_INTERVAL < downloadingPeer.getVersionLastBlockHeight()) {
                filterFpRate = BloomFilter.BLOOM_REDUCED_FALSEPOSITIVE_RATE; // lower false
                // positive rate during chain sync
            } else if (downloadingPeer != null && filterUpdateHeight < downloadingPeer
                    .getVersionLastBlockHeight()) { // partially
                // lower fp rate if we're nearly synced
                filterFpRate -= (BloomFilter.DEFAULT_BLOOM_FILTER_FP_RATE - BloomFilter
                        .BLOOM_REDUCED_FALSEPOSITIVE_RATE) * (downloadingPeer.getVersionLastBlockHeight() - filterUpdateHeight) / BitherjSettings.BLOCK_DIFFICULTY_INTERVAL;
            }
            List<Out> outs = TxProvider.getInstance().getOuts();
            List<Address> addresses = AddressManager.getInstance().getAllAddresses();
            bloomFilterElementCount = addresses.size() * 2 + outs.size() + 100;

            BloomFilter filter = new BloomFilter(bloomFilterElementCount, filterFpRate, tweak,
                    BloomFilter.BloomUpdate.UPDATE_ALL);


            for (Address address : addresses) { // add addresses to watch for any tx receiveing
                // money to the wallet
                byte[] pub = address.getPubKey();
                if (pub != null && !filter.contains(pub)) {
                    filter.insert(pub);
                }
                if (pub != null) {
                    byte[] hash = Utils.sha256hash160(pub);
                    if (hash != null && !filter.contains(hash)) {
                        filter.insert(hash);
                    }
                }
            }
            for (Out out : outs) {
                byte[] outpoint = out.getOutpointData();
                if (!filter.contains(outpoint)) {
                    filter.insert(outpoint);
                }
            }
            bloomFilter = filter;
        }
        return bloomFilter;
    }

    public boolean doneSyncFromSPV() {
        return BitherjApplication.getInitialize().getBitherjDoneSyncFromSpv();
    }

    private void sendConnectedChangeBroadcast() {
        BitherjApplication.sendConnectedChangeBroadcast(ConnectedChangeBroadcast, isConnected());
        log.info("peer manager connected changed to " + isConnected());
    }

    private void sendPeerCountChangeNotification() {
        NotificationUtil.sendBroadcastPeerState(connectedPeers.size());
    }

    public Peer getDownloadingPeer() {
        return downloadingPeer;
    }

    static class PeerManagerExecutorService extends ThreadPoolExecutor {
        private static final int TaskCapacity = 5000;
        private static final int TaskCapacityWaitForRoom = 2000;
        private ReentrantLock executeLock = new ReentrantLock();
        private Condition fullCondition = executeLock.newCondition();
        private boolean isWaiting = false;

        public PeerManagerExecutorService() {
            super(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>());
        }

        private final static Marker marker = MarkerFactory.getMarker("PeerManagerExecutor");

        @Override
        public void execute(Runnable command) {
            int waiting = getQueue().size();
            if (getQueue().size() >= TaskCapacity) {
                isWaiting = true;
                try {
                    log.info(marker, "PeerManager full capacity with " + waiting
                            + " waiting");
                    executeLock.lockInterruptibly();
                    fullCondition.await();
                    log.info(marker, "PeerManager execute again with " + getQueue
                            ().size() + " waiting");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    executeLock.unlock();
                }
            }
            super.execute(command);
        }

        protected void afterExecute(Runnable r, Throwable t) {
            super.afterExecute(r, t);
            long completed = getCompletedTaskCount();
            int waiting = getQueue().size();
            //LogUtil.d("PeerManagerExecutor", "PeerManager finished " + completed + " tasks,
            // " + waiting + " tasks remaining");
            if (t == null && r instanceof Future<?>) {
                try {
                    Future<?> future = (Future<?>) r;
                    if (future.isDone()) {
                        future.get();
                    }
                } catch (CancellationException ce) {
                    t = ce;
                } catch (ExecutionException ee) {
                    t = ee.getCause();
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt(); // ignore/reset
                }
            }
            if (t != null) {
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                t.printStackTrace(new PrintStream(bout));
                log.error("exception in PeerManager: " + new String(bout.toByteArray()));
            }
            if (isWaiting && waiting < TaskCapacity - TaskCapacityWaitForRoom) {
                try {
                    executeLock.lock();
                    fullCondition.signal();
                } finally {
                    executeLock.unlock();
                }
                isWaiting = false;
            }
        }

        @Override
        protected void finalize() {
            super.shutdown();
        }
    }

    public static final class PublishUnsignedTxException extends Exception {

    }

    private void syncTimeout(){
        long now = System.currentTimeMillis();
        if (now - lastRelayTime < BitherjSettings.PROTOCOL_TIMEOUT) { // the download peer relayed something in time, so restart timer
            scheduleTimeoutTimer(BitherjSettings.PROTOCOL_TIMEOUT - (now - lastRelayTime));
        } else {
            if(downloadingPeer != null){
                log.warn("{} chain sync time out", downloadingPeer.getPeerAddress().getHostAddress());
                synchronizing = false;
                downloadingPeer.disconnect();
            }
        }
    }

    private void cancelTimeoutTimer(){
        if(syncTimeOutTimer != null) {
            syncTimeOutTimer.cancel();
            syncTimeOutTimer = null;
        }
    }

    private void scheduleTimeoutTimer(long delay){
        cancelTimeoutTimer();
        syncTimeOutTimer = new Timer();
        syncTimeOutTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                syncTimeout();
            }
        }, delay);
    }
}
