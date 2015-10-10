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

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.net.NioClientManager;
import net.bither.bitherj.utils.DnsDiscovery;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class PeerManager {

    public static final String ConnectedChangeBroadcast = PeerManager.class.getPackage().getName
            () + ".peer_manager_connected_change";
    private static final Logger log = LoggerFactory.getLogger(PeerManager.class);
    private static final int MAX_CONNECT_FAILURE_COUNT = 6;

    private static final int MaxPeerCount = 100;
    private static final int MaxConnectFailure = 20;

    private static Object newInstanceLock = new Object();

    private static PeerManager instance;

    private PeerManagerExecutorService executor;

    private AtomicBoolean running;
    private AtomicBoolean connected;

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
    private HashMap<Sha256Hash, Timer> publishTxTimeoutTimers;

    private boolean onlyBroadcasting = false;

    public static final PeerManager instance() {
        if (instance == null) {
            synchronized (newInstanceLock) {
                if (instance == null) {
                    instance = new PeerManager();
                }
            }
        }
        return instance;
    }

    private PeerManager() {
        running = new AtomicBoolean(false);
        connected = new AtomicBoolean(false);
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
        for (Tx tx : AbstractDb.txProvider.getPublishedTxs()) {
            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED) {
                publishedTx.put(new Sha256Hash(tx.getTxHash()), tx);
            }
        }

    }

    public boolean isConnected() {
        return connected.get();
    }

    public boolean isRunning() {
        return running.get();
    }

    public void start() {
        if (!running.getAndSet(true)) {
            log.info("peer manager start");
            bloomFilter = null;
            if (this.connectFailure >= MAX_CONNECT_FAILURE_COUNT) {
                this.connectFailure = 0;
            }
            if (connectedPeers.size() > 0) {
                for (Peer peer : connectedPeers) {
                    peer.connectError();
                    peer.disconnect();
                    abandonPeers.add(peer);
                }
                connectedPeers.clear();
            }
            reconnect();
        } else {
            log.info("peer manager call start, but it is connected already");
        }
    }

    public void stop() {
        if (running.getAndSet(false)) {
            log.info("peer manager stop");
            if (connected.getAndSet(false)) {
                AbstractApp.notificationService.removeBroadcastPeerState();
                bloomFilter = null;
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

    public void notifyMaxConnectedPeerCountChange() {
        if (running.get()) {
            reconnect();
        }
    }

    public void clearPeerAndRestart() {
        this.stop();
        AbstractDb.peerProvider.recreate();
        this.start();
    }

    public long getLastBlockHeight() {
        Block lastBlock = BlockChain.getInstance().lastBlock;
        return lastBlock == null ? 0 : lastBlock.getBlockNo();
    }

    private void reconnect() {
        if (!running.get()) {
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
                log.info("reconnect {},{}", connectedPeers.size(), getMaxPeerConnect());
                if (connectedPeers.size() >= getMaxPeerConnect()) {
                    return;
                }
                HashSet<Peer> peers = bestPeers();
                for (Peer p : peers) {
                    if (connectedPeers.size() >= getMaxPeerConnect()) {
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
        return new ArrayList<Peer>(connectedPeers);
    }

    private HashSet<Peer> bestPeers() {
        HashSet<Peer> peers = new HashSet<Peer>();
        peers.addAll(AbstractDb.peerProvider.getPeersWithLimit(getMaxPeerConnect()));
        log.info("{} dbpeers", peers.size());
        if (peers.size() < getMaxPeerConnect()) {
            AbstractDb.peerProvider.recreate();
            AbstractDb.peerProvider.addPeers(new ArrayList<Peer>(peers));
            if (getPeersFromDns().size() > 0) {
                peers.clear();
                peers.addAll(AbstractDb.peerProvider.getPeersWithLimit(getMaxPeerConnect()));
            }
        }
        log.info("{} totalpeers", peers.size());
        return peers;
    }

    private HashSet<Peer> getPeersFromDns() {
        HashSet<Peer> peers = new HashSet<Peer>();
        Peer[] ps = DnsDiscovery.instance().getPeers(5, TimeUnit.SECONDS);
        Collections.addAll(peers, ps);
        AbstractDb.peerProvider.addPeers(new ArrayList<Peer>(peers));
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
                AbstractDb.peerProvider.addPeers(result);
                AbstractDb.peerProvider.cleanPeers();
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
            AbstractDb.txProvider.confirmTx(height, txHashes);
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
        if (running.get()) {
            if (peer.getVersionLastBlockHeight() + 10 < getLastBlockHeight()) {
                log.warn("Peer height low abandon : " + peer.getPeerAddress().getHostAddress());
                executor.submit(new Runnable() {
                    @Override
                    public void run() {
                        abandonPeer(peer);
                    }
                });
                return;
            }
            if (!connected.getAndSet(true)) {
                sendConnectedChangeBroadcast();
            }
            log.info("Peer {} connected", peer.getPeerAddress().getHostAddress());
            connectFailure = 0;
            bloomFilter = null;
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    peer.connectSucceed();
                    if (isOnlyBroadcasting()) {
                        for (Tx tx : publishedTx.values()) {
                            if (tx.getSource() > 0 && tx.getSource() <= MaxPeerCount) {
                                peer.sendInvMessageWithTxHash(new Sha256Hash(tx.getTxHash()));
                            }
                        }
                        return;
                    }
                    if (!doneSyncFromSPV() && getLastBlockHeight() >= peer.getVersionLastBlockHeight()) {
                        AbstractApp.notificationService.sendBroadcastSyncSPVFinished(true);
                    }
                    if (connected.get() && ((downloadingPeer != null && downloadingPeer
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
                                .getVersionLastBlockHeight()) || p.getVersionLastBlockHeight() >
                                dp.getVersionLastBlockHeight()) {
                            dp = p;
                        }
                    }
                    if (downloadingPeer != null) {
                        downloadingPeer.disconnect();
                    }
                    downloadingPeer = dp;
                    connected.set(true);

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

                        lastRelayTime = System.currentTimeMillis();
                        synchronizing = true;

                        scheduleTimeoutTimer(BitherjSettings.PROTOCOL_TIMEOUT);
                        if (doneSyncFromSPV()) {
                            dp.sendGetBlocksMessage(BlockChain.getInstance().getBlockLocatorArray
                                    (), null);
                        } else {
                            dp.sendGetHeadersMessage(BlockChain.getInstance()
                                    .getBlockLocatorArray(), null);
                        }
                        downloadingPeer.setSynchronising(true);
                        syncStartHeight = getLastBlockHeight();
                        sendSyncProgress();
                    } else { // we're already synced
                        downloadingPeer.setSynchronising(false);
                        syncStopped();
                        dp.sendGetAddrMessage();
                        AbstractApp.notificationService.sendBroadcastSyncSPVFinished(true);
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
        syncStartHeight = 0;

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
        sendSyncProgress();
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
                log.info("Peer disconnected {} , remaining {} peers , reason: " + reason, peer
                        .getPeerAddress().getHostAddress(), connectedPeers.size());
                if (previousConnectedCount > 0 && connectedPeers.size() == 0) {
                    connected.set(false);
                    sendConnectedChangeBroadcast();
                }

                sendPeerCountChangeNotification();

                for (Sha256Hash txHash : txRelays.keySet()) {
                    txRelays.get(txHash).remove(peer);
                }

                if (downloadingPeer != null && downloadingPeer.equals(peer)) {
                    connected.set(false);
                    downloadingPeer.setSynchronising(false);
                    downloadingPeer = null;
                    syncStopped();
                    if (connectFailure > MaxConnectFailure) {
                        connectFailure = MaxConnectFailure;
                    }
                }

                if (!connected.get() && connectFailure == MaxConnectFailure) {
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

    public void relayedTransaction(final Peer fromPeer, final Tx tx, final boolean isConfirmed) {
        if (!isRunning()) {
            return;
        }
        if (fromPeer == downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        }
        executor.submit(new Runnable() {
            @Override
            public void run() {
                boolean isRel = AddressManager.getInstance().registerTx(tx, Tx.TxNotificationType
                        .txReceive, isConfirmed);
                if (isRel) {
                    boolean isAlreadyInDb = AbstractDb.txProvider.isExist(tx.getTxHash());

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
                    int relayedCount = BlockChain.getInstance().relayedBlockHeadersForMainChain
                            (blocks);
                    if (relayedCount == blocks.size()) {
                        log.info("Peer {} relay {} block headers OK, last block No.{}, " +
                                "" + "total block: {}", fromPeer.getPeerAddress().getHostAddress
                                (), relayedCount, BlockChain.getInstance().getLastBlock()
                                .getBlockNo(), BlockChain.getInstance().getBlockCount());
                    } else {
                        abandonPeer(fromPeer);
                        log.info("Peer {} relay {}/{} block headers. drop this peer",
                                fromPeer.getPeerAddress().getHostAddress(), relayedCount,
                                blocks.size());
                    }
                } catch (Exception e) {
                    abandonPeer(fromPeer);
                    log.warn("Peer {} relay block Error. Drop it",
                            fromPeer.getPeerAddress().getHostAddress());
                }
                sendSyncProgress();
                if (getLastBlockHeight() == fromPeer.getVersionLastBlockHeight()) {
                    downloadingPeer.setSynchronising(false);
                    syncStopped();
                    fromPeer.sendGetAddrMessage(); // request a list of other bitcoin peers
                    if (!doneSyncFromSPV()) {
                        log.info("Done sync from spv");
                        AbstractApp.notificationService.sendBroadcastSyncSPVFinished(true);
                    }
                }
                if (oldLastBlock != null && BlockChain.getInstance().getLastBlock() != null &&
                        oldLastBlock.getBlockNo() != BlockChain.getInstance().getLastBlock()
                                .getBlockNo()) {
                    AbstractApp.notificationService.sendLastBlockChange();
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
                        log.warn("Peer {} relay block {} failed, drop this peer",
                                fromPeer.getPeerAddress().getHostAddress(),
                                Utils.hashToString(block.getBlockHash()));
                    }
                } catch (ProtocolException e) {
                    abandonPeer(fromPeer);
                    log.warn("Peer {} relay block {} error, drop this peer",
                            fromPeer.getPeerAddress().getHostAddress(),
                            Utils.hashToString(block.getBlockHash()));
                }
                sendSyncProgress();
                if (block.getBlockNo() == fromPeer.getVersionLastBlockHeight() && block
                        .getBlockNo() == getLastBlockHeight()) {
                    downloadingPeer.setSynchronising(false);
                    syncStopped();
                    fromPeer.sendGetAddrMessage(); // request a list of other bitcoin peers
                    if (!doneSyncFromSPV()) {
                        AbstractApp.notificationService.sendBroadcastSyncSPVFinished(true);
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
                    log.info("Peer {} relay new best block No.{}, hash: {}, txs: {}",
                            fromPeer.getPeerAddress().getHostAddress(), lastBlock.getBlockNo(),
                            Utils.hashToString(lastBlock.getBlockHash()),
                            lastBlock.getTxHashes() == null ? 0 : lastBlock.getTxHashes().size());
                    AbstractApp.notificationService.sendLastBlockChange();
                }
            }
        });
    }

    public void relayedBlocks(final Peer fromPeer, final List<Block> blocks) {
        if (!isRunning()) {
            return;
        }
        if (blocks == null || blocks.size() == 0) {
            return;
        }
        final List<Block> blockList = new ArrayList<Block>();
        blockList.addAll(blocks);

        if (fromPeer == downloadingPeer) {
            lastRelayTime = System.currentTimeMillis();
        } else {
            return;
        }
        executor.submit(new Runnable() {
            @Override
            public void run() {
                // todo:
                // track the observed bloom filter false positive rate using a low pass filter to
                // smooth out variance

                try {
                    int relayedCnt = BlockChain.getInstance().relayedBlocks(blockList);
                    if (relayedCnt > 0) {
                        log.info("Peer {} relay {} block OK, last block No.{}, total block: {}",
                                fromPeer.getPeerAddress().getHostAddress(), relayedCnt,
                                BlockChain.getInstance().getLastBlock().getBlockNo(),
                                BlockChain.getInstance().getBlockCount());
                        sendSyncProgress();
                        if (BlockChain.getInstance().getLastBlock().getBlockNo() >= fromPeer
                                .getVersionLastBlockHeight()) {
                            fromPeer.setSynchronising(false);
                            syncStopped();
                            fromPeer.sendGetAddrMessage(); // request a list of other bitcoin peers
                        }

                        if (BlockChain.getInstance().singleBlocks.get(BlockChain.getInstance()
                                .getLastBlock().getBlockHash()) != null) {
                            Block b = BlockChain.getInstance().singleBlocks.get(BlockChain
                                    .getInstance().getLastBlock().getBlockHash());
                            BlockChain.getInstance().singleBlocks.remove(BlockChain.getInstance()
                                    .getLastBlock().getBlockHash());
                            relayedBlock(fromPeer, b);
                        }

                        log.info("Peer {} relay new best block No.{}, hash: {}, txs: {}",
                                fromPeer.getPeerAddress().getHostAddress(),
                                BlockChain.getInstance().getLastBlock().getBlockNo(),
                                Utils.hashToString(BlockChain.getInstance().getLastBlock()
                                        .getBlockHash()), BlockChain.getInstance().getLastBlock()
                                        .getTxHashes() == null ? 0 : BlockChain.getInstance()
                                        .getLastBlock().getTxHashes().size());
                        AbstractApp.notificationService.sendLastBlockChange();
                    } else {
                        abandonPeer(fromPeer);
                        log.info("Peer {} relay {}/{} block. drop this peer",
                                fromPeer.getPeerAddress().getHostAddress(), relayedCnt,
                                blocks.size());
                    }
                } catch (Exception e) {
                    abandonPeer(fromPeer);
                    log.warn("Peer {} relay block Error. Drop it",
                            fromPeer.getPeerAddress().getHostAddress());
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

        AddressManager.getInstance().registerTx(tx, Tx.TxNotificationType.txSend, false);

        publishedTx.put(new Sha256Hash(tx.getTxHash()), tx);

        executor.submit(new Runnable() {
            @Override
            public void run() {
//                bloomFilter = null;
//                for (Peer p : connectedPeers) {
//                    p.sendFilterLoadMessage(getBloomFilter());
//                }
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
                schedulePublishTxTimeoutTimer(BitherjSettings.PROTOCOL_TIMEOUT, tx.getTxHash());
            }
        });
    }

    public void requestBloomFilterRecalculate() {
        bloomFilter = null;
    }

    private BloomFilter getBloomFilter() {
        if (bloomFilter == null) {

            filterUpdateHeight = getLastBlockHeight();
            filterFpRate = BloomFilter.DEFAULT_BLOOM_FILTER_FP_RATE;

            if (downloadingPeer != null && filterUpdateHeight + 500 < downloadingPeer.getVersionLastBlockHeight()) {
                filterFpRate = BloomFilter.BLOOM_REDUCED_FALSEPOSITIVE_RATE; // lower false
                // positive rate during chain sync
            } else if (downloadingPeer != null && filterUpdateHeight < downloadingPeer
                    .getVersionLastBlockHeight()) { // partially
                // lower fp rate if we're nearly synced
                filterFpRate -= (BloomFilter.DEFAULT_BLOOM_FILTER_FP_RATE - BloomFilter
                        .BLOOM_REDUCED_FALSEPOSITIVE_RATE) * (downloadingPeer
                        .getVersionLastBlockHeight() - filterUpdateHeight) / BitherjSettings
                        .BLOCK_DIFFICULTY_INTERVAL;
            }

            List<Out> outs = new ArrayList<Out>();
            for (Out out : AbstractDb.txProvider.getOuts()) {
                if (AddressManager.getInstance().getAddressHashSet().contains(out.getOutAddress()
                )) {
                    outs.add(out);
                }
            }
            List<Address> addresses = AddressManager.getInstance().getAllAddresses();
            int desktopHDMElementCount = 0;
            if (AddressManager.getInstance().hasDesktopHDMKeychain()) {
                DesktopHDMKeychain desktopHDMKeychain =
                        AddressManager.getInstance().getDesktopHDMKeychains().get(0);
                desktopHDMElementCount = desktopHDMKeychain.elementCountForBloomFilter();

            }
            bloomFilterElementCount = addresses.size() * 2 + outs.size() + (AddressManager
                    .getInstance().hasHDAccountHot() ? AddressManager.getInstance().getHDAccountHot()
                    .elementCountForBloomFilter() : 0) + (AddressManager.getInstance()
                    .hasHDAccountMonitored() ? AddressManager.getInstance().getHDAccountMonitored
                    ().elementCountForBloomFilter() : 0) + desktopHDMElementCount + 100;

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

            if (AddressManager.getInstance().hasHDAccountHot()) {
                AddressManager.getInstance().getHDAccountHot().addElementsForBloomFilter(filter);
            }

            if (AddressManager.getInstance().hasHDAccountMonitored()) {
                AddressManager.getInstance().getHDAccountMonitored().addElementsForBloomFilter(filter);
            }

            if (AddressManager.getInstance().hasDesktopHDMKeychain()) {
                DesktopHDMKeychain desktopHDMKeychain = AddressManager.getInstance().getDesktopHDMKeychains().get(0);
                desktopHDMKeychain.addElementsForBloomFilter(filter);
            }
            bloomFilter = filter;
        }
        return bloomFilter;
    }

    public boolean doneSyncFromSPV() {
        return AbstractApp.bitherjSetting.getBitherjDoneSyncFromSpv();
    }

    private void sendConnectedChangeBroadcast() {
        AbstractApp.notificationService.sendConnectedChangeBroadcast(ConnectedChangeBroadcast,
                isConnected());
        log.info("peer manager connected changed to " + isConnected());
    }

    private void sendPeerCountChangeNotification() {
        AbstractApp.notificationService.sendBroadcastPeerState(connectedPeers.size());
    }

    public Peer getDownloadingPeer() {
        return downloadingPeer;
    }

    public int waitingTaskCount() {
        if (executor == null || executor.getQueue() == null) {
            return 0;
        }
        return executor.getQueue().size();
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

        @Override
        public void execute(Runnable command) {
            int waiting = getQueue().size();
            if (getQueue().size() >= TaskCapacity) {
                isWaiting = true;
                try {
                    log.info("PeerManagerExecutor full capacity with " + waiting + " waiting");
                    executeLock.lockInterruptibly();
                    fullCondition.await();
                    log.info("PeerManagerExecutor execute again with " + getQueue().size() + " " +
                            "waiting");
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
//            log.info("PeerManagerExecutor finished " + completed + " " +
//                    "tasks, " + waiting + " tasks remaining");
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
            if (t != null && t.getMessage() != null && t.getMessage().length() > 0) {
                log.error("exception in PeerManager: " + t.getMessage());
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

    private void syncTimeout() {
        long now = System.currentTimeMillis();
        if (now - lastRelayTime < BitherjSettings.PROTOCOL_TIMEOUT) { // the download peer
            // relayed something in time, so restart timer
            scheduleTimeoutTimer(BitherjSettings.PROTOCOL_TIMEOUT - (now - lastRelayTime));
        } else {
            if (downloadingPeer != null) {
                log.warn("{} chain sync time out", downloadingPeer.getPeerAddress()
                        .getHostAddress());
                downloadingPeer.disconnect();
            }
        }
        sendSyncProgress();
    }

    private void cancelTimeoutTimer() {
        if (syncTimeOutTimer != null) {
            syncTimeOutTimer.cancel();
            syncTimeOutTimer = null;
        }
    }

    private void scheduleTimeoutTimer(long delay) {
        cancelTimeoutTimer();
        syncTimeOutTimer = new Timer();
        syncTimeOutTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                syncTimeout();
            }
        }, delay);
    }


    private void publishTxTimeout(final byte[] txHash) {
        executor.execute(new Runnable() {
            @Override
            public void run() {
                cancelPublishTxTimeoutTimer(txHash);
                for (Peer peer : connectedPeers) {
                    peer.disconnect();
                }
            }
        });
    }

    private void cancelPublishTxTimeoutTimer(byte[] txHash) {
        Sha256Hash hash = new Sha256Hash(txHash);
        if (publishTxTimeoutTimers != null && publishTxTimeoutTimers.containsKey(hash)) {
            Timer publishTxTimeoutTimer = publishTxTimeoutTimers.get(hash);
            publishTxTimeoutTimers.remove(hash);
            publishTxTimeoutTimer.cancel();
            publishTxTimeoutTimer = null;
        }
    }

    private void schedulePublishTxTimeoutTimer(long delay, final byte[] txHash) {
        cancelPublishTxTimeoutTimer(txHash);
        if (publishTxTimeoutTimers == null) {
            publishTxTimeoutTimers = new HashMap<Sha256Hash, Timer>();
        }

        Timer publishTxTimeoutTimer = new Timer();
        publishTxTimeoutTimers.put(new Sha256Hash(txHash), publishTxTimeoutTimer);
        publishTxTimeoutTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                publishTxTimeout(txHash);
            }
        }, delay);
    }

    private void sendSyncProgress() {
        long lastBlockHeight = getLastBlockHeight();
        if (synchronizing && syncStartHeight > 0 && downloadingPeer != null && lastBlockHeight >=
                syncStartHeight && lastBlockHeight <= downloadingPeer.getVersionLastBlockHeight()) {
            double progress = (double) (lastBlockHeight - syncStartHeight) / (double) (downloadingPeer.getVersionLastBlockHeight() -
                    syncStartHeight);
            AbstractApp.notificationService.sendBroadcastProgressState(progress);
        } else {
            AbstractApp.notificationService.sendBroadcastProgressState(-1);
        }
    }

    private int getMaxPeerConnect() {
        if (AbstractApp.bitherjSetting.isApplicationRunInForeground()) {
            return BitherjSettings.MaxPeerConnections;
        } else {
            return BitherjSettings.MaxPeerBackgroundConnections;
        }
    }

    public boolean isSynchronizing() {
        return synchronizing;
    }

    public boolean isOnlyBroadcasting() {
        return this.onlyBroadcasting;
    }

    public void setOnlyBroadcasting(boolean onlyBroadcasting) {
        this.onlyBroadcasting = onlyBroadcasting;
    }

    public void onDestroy() {
        instance = null;
        NioClientManager.instance().onDestroy();
    }
}
