/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.core;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by songchenwen on 15/6/19.
 */
public class HDAccountMonitored extends Address {
    public static final String HDAccountMonitoredPlaceHolder = "HDAccountMonitored";

    private static final double GenerationPreStartProgress = 0.01;

    private static final int LOOK_AHEAD_SIZE = 100;

    private long balance = 0;

    protected int hdSeedId = -1;
    protected boolean isFromXRandom;

    private static final Logger log = LoggerFactory.getLogger(HDAccountMonitored.class);

    public HDAccountMonitored(byte[] accountExtentedPub) throws MnemonicException
            .MnemonicLengthException {
        this(accountExtentedPub, false);
    }

    public HDAccountMonitored(byte[] accountExtentedPub, boolean isFromXRandom) throws
            MnemonicException.MnemonicLengthException {
        this(accountExtentedPub, isFromXRandom, true, null);
    }


    public HDAccountMonitored(byte[] accountExtentedPub, boolean isFromXRandom, boolean
            isSyncedComplete, HDAccount.HDAccountGenerationDelegate generationDelegate) throws
            MnemonicException.MnemonicLengthException {
        super();
        this.isFromXRandom = isFromXRandom;
        DeterministicKey account = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (accountExtentedPub);
        initHDAccount(account, isFromXRandom, isSyncedComplete, generationDelegate);
    }

    private void initHDAccount(DeterministicKey accountKey, boolean isFromXRandom, boolean
            isSyncedComplete, HDAccount.HDAccountGenerationDelegate generationDelegate) {
        double progress = 0;
        if (generationDelegate != null) {
            generationDelegate.onHDAccountGenerationProgress(progress);
        }
        DeterministicKey internalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
        DeterministicKey externalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        accountKey.wipe();

        progress += GenerationPreStartProgress;
        if (generationDelegate != null) {
            generationDelegate.onHDAccountGenerationProgress(progress);
        }

        double itemProgress = (1.0 - GenerationPreStartProgress) / (LOOK_AHEAD_SIZE * 2);

        List<HDAccount.HDAccountAddress> externalAddresses = new ArrayList<HDAccount
                .HDAccountAddress>();
        List<HDAccount.HDAccountAddress> internalAddresses = new ArrayList<HDAccount
                .HDAccountAddress>();
        for (int i = 0;
             i < LOOK_AHEAD_SIZE;
             i++) {
            byte[] subExternalPub = externalKey.deriveSoftened(i).getPubKey();
            HDAccount.HDAccountAddress externalAddress = new HDAccount.HDAccountAddress
                    (subExternalPub, AbstractHD.PathType.EXTERNAL_ROOT_PATH, i, isSyncedComplete,
                            hdSeedId);
            externalAddresses.add(externalAddress);
            progress += itemProgress;
            if (generationDelegate != null) {
                generationDelegate.onHDAccountGenerationProgress(progress);
            }

            byte[] subInternalPub = internalKey.deriveSoftened(i).getPubKey();
            HDAccount.HDAccountAddress internalAddress = new HDAccount.HDAccountAddress
                    (subInternalPub, AbstractHD.PathType.INTERNAL_ROOT_PATH, i, isSyncedComplete,
                            hdSeedId);
            internalAddresses.add(internalAddress);
            progress += itemProgress;
            if (generationDelegate != null) {
                generationDelegate.onHDAccountGenerationProgress(progress);
            }
        }
        AbstractDb.hdAccountProvider.addAddress(externalAddresses);
        AbstractDb.hdAccountProvider.addAddress(internalAddresses);

        hdSeedId = AbstractDb.hdAccountProvider.addMonitoredHDAccount(isFromXRandom,
                internalKey.getPubKeyExtended(), externalKey.getPubKeyExtended());
        internalKey.wipe();
        externalKey.wipe();
    }

    public HDAccountMonitored(int seedId) {
        this.hdSeedId = seedId;
        this.isFromXRandom = AbstractDb.hdAccountProvider.hdAccountIsXRandom(seedId);
        updateBalance();
    }


    public int getHdSeedId() {
        return hdSeedId;
    }

    public String getFullEncryptPrivKey() {
        return null;
    }

    public byte[] getInternalPub() {
        return AbstractDb.hdAccountProvider.getInternalPub(hdSeedId);
    }

    public byte[] getExternalPub() {
        return AbstractDb.hdAccountProvider.getExternalPub(hdSeedId);
    }

    public void supplyEnoughKeys(boolean isSyncedComplete) {
        int lackOfExternal = issuedExternalIndex() + 1 + LOOK_AHEAD_SIZE -
                allGeneratedExternalAddressCount();
        if (lackOfExternal > 0) {
            supplyNewExternalKey(lackOfExternal, isSyncedComplete);
        }

        int lackOfInternal = issuedInternalIndex() + 1 + LOOK_AHEAD_SIZE -
                allGeneratedInternalAddressCount();
        if (lackOfInternal > 0) {
            supplyNewInternalKey(lackOfInternal, isSyncedComplete);
        }
    }

    private void supplyNewInternalKey(int count, boolean isSyncedComplete) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getInternalPub());
        int firstIndex = allGeneratedInternalAddressCount();
        ArrayList<HDAccount.HDAccountAddress> as = new ArrayList<HDAccount.HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccount.HDAccountAddress(root.deriveSoftened(i).getPubKey(), AbstractHD
                    .PathType.INTERNAL_ROOT_PATH, i, isSyncedComplete, hdSeedId));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
        log.info("HD monitored supplied {} internal addresses", as.size());
    }

    private void supplyNewExternalKey(int count, boolean isSyncedComplete) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getExternalPub());
        int firstIndex = allGeneratedExternalAddressCount();
        ArrayList<HDAccount.HDAccountAddress> as = new ArrayList<HDAccount.HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccount.HDAccountAddress(root.deriveSoftened(i).getPubKey(), AbstractHD
                    .PathType.EXTERNAL_ROOT_PATH, i, isSyncedComplete, hdSeedId));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
        log.info("HD monitored supplied {} external addresses", as.size());
    }

    public String getAddress() {
        return AbstractDb.hdAccountProvider.externalAddress(this.hdSeedId);
    }

    public String getShortAddress() {
        return Utils.shortenAddress(getAddress());
    }

    public int issuedInternalIndex() {
        return AbstractDb.hdAccountProvider.issuedIndex(this.hdSeedId, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
    }

    public int issuedExternalIndex() {
        return AbstractDb.hdAccountProvider.issuedIndex(this.hdSeedId, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);

    }

    private int allGeneratedInternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(this.hdSeedId, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
    }

    private int allGeneratedExternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(this.hdSeedId, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
    }

    private HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index) {
        assert index < (type == AbstractHD.PathType.EXTERNAL_ROOT_PATH ?
                allGeneratedExternalAddressCount() : allGeneratedInternalAddressCount());
        return AbstractDb.hdAccountProvider.addressForPath(this.hdSeedId, type, index);
    }

    public void onNewTx(Tx tx, List<HDAccount.HDAccountAddress> relatedAddresses, Tx
            .TxNotificationType txNotificationType) {
        if (relatedAddresses == null || relatedAddresses.size() == 0) {
            return;
        }

        int maxInternal = -1, maxExternal = -1;
        for (HDAccount.HDAccountAddress a : relatedAddresses) {
            if (a.getPathType() == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                if (a.getIndex() > maxExternal) {
                    maxExternal = a.getIndex();
                }
            } else {
                if (a.getIndex() > maxInternal) {
                    maxInternal = a.getIndex();
                }
            }
        }

        log.info("HD on new tx issued ex {}, issued in {}", maxExternal, maxInternal);
        if (maxExternal >= 0 && maxExternal > issuedExternalIndex()) {
            updateIssuedExternalIndex(maxExternal);
        }
        if (maxInternal >= 0 && maxInternal > issuedInternalIndex()) {
            updateIssuedInternalIndex(maxInternal);
        }

        supplyEnoughKeys(true);

        long deltaBalance = getDeltaBalance();
        AbstractApp.notificationService.notificatTx(HDAccountMonitoredPlaceHolder, tx,
                txNotificationType, deltaBalance);
    }


    public boolean isTxRelated(Tx tx, List<String> inAddresses) {
        return getRelatedAddressesForTx(tx, inAddresses).size() > 0;
    }

    public boolean initTxs(List<Tx> txs) {
        AbstractDb.txProvider.addTxs(txs);
        notificatTx(null, Tx.TxNotificationType.txFromApi);
        return true;
    }

    public void notificatTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        long deltaBalance = getDeltaBalance();
        AbstractApp.notificationService.notificatTx(HDAccount.HDAccountPlaceHolder, tx,
                txNotificationType, deltaBalance);
    }

    private long getDeltaBalance() {
        long oldBalance = this.balance;
        this.updateBalance();
        return this.balance - oldBalance;
    }

    public List<Tx> getTxs(int page) {
        return AbstractDb.hdAccountProvider.getTxAndDetailByHDAccount(page);
    }

    @Override
    public List<Tx> getTxs() {
        return AbstractDb.hdAccountProvider.getTxAndDetailByHDAccount(this.hdSeedId);
    }

    public int txCount() {
        return AbstractDb.hdAccountProvider.hdAccountTxCount(this.hdSeedId);
    }

    public void updateBalance() {
        this.balance = AbstractDb.hdAccountProvider.getHDAccountConfirmedBanlance
                (hdSeedId) + calculateUnconfirmedBalance();
    }

    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.hdAccountProvider.getHDAccountUnconfirmedTx(this.hdSeedId);
        Collections.sort(txs);

        Set<byte[]> invalidTx = new HashSet<byte[]>();
        Set<OutPoint> spentOut = new HashSet<OutPoint>();
        Set<OutPoint> unspendOut = new HashSet<OutPoint>();

        for (int i = txs.size() - 1;
             i >= 0;
             i--) {
            Set<OutPoint> spent = new HashSet<OutPoint>();
            Tx tx = txs.get(i);

            Set<byte[]> inHashes = new HashSet<byte[]>();
            for (In in : tx.getIns()) {
                spent.add(new OutPoint(in.getPrevTxHash(), in.getPrevOutSn()));
                inHashes.add(in.getPrevTxHash());
            }

            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED && (Utils.isIntersects(spent, spentOut) ||
                    Utils.isIntersects(inHashes, invalidTx))) {
                invalidTx.add(tx.getTxHash());
                continue;
            }

            spentOut.addAll(spent);
            HashSet<String> addressSet = getBelongAccountAddresses(tx.getOutAddressList());
            for (Out out : tx.getOuts()) {
                if (addressSet.contains(out.getOutAddress())) {
                    unspendOut.add(new OutPoint(tx.getTxHash(), out.getOutSn()));
                    balance += out.getOutValue();
                }
            }
            spent.clear();
            spent.addAll(unspendOut);
            spent.retainAll(spentOut);
            for (OutPoint o : spent) {
                Tx tx1 = AbstractDb.txProvider.getTxDetailByTxHash(o.getTxHash());
                unspendOut.remove(o);
                for (Out out : tx1.getOuts()) {
                    if (out.getOutSn() == o.getOutSn()) {
                        balance -= out.getOutValue();
                    }
                }
            }
        }
        return balance;
    }

    public List<HDAccount.HDAccountAddress> getRelatedAddressesForTx(Tx tx, List<String>
            inAddresses) {
        List<String> outAddressList = new ArrayList<String>();
        List<HDAccount.HDAccountAddress> hdAccountAddressList = new ArrayList<HDAccount
                .HDAccountAddress>();
        for (Out out : tx.getOuts()) {
            String outAddress = out.getOutAddress();
            outAddressList.add(outAddress);
        }
        List<HDAccount.HDAccountAddress> belongAccountOfOutList = AbstractDb
                .hdAccountProvider.belongAccount(this.hdSeedId, outAddressList);
        if (belongAccountOfOutList != null && belongAccountOfOutList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfOutList);
        }

        List<HDAccount.HDAccountAddress> belongAccountOfInList = getAddressFromIn(inAddresses);
        if (belongAccountOfInList != null && belongAccountOfInList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfInList);
        }

        return hdAccountAddressList;
    }

    public HashSet<String> getBelongAccountAddresses(List<String> addressList) {
        return AbstractDb.hdAccountProvider.getBelongAccountAddresses(this.hdSeedId, addressList);
    }

    public Tx newTx(String toAddress, Long amount) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        return newTx(new String[]{toAddress}, new Long[]{amount});
    }


    public Tx newTx(String[] toAddresses, Long[] amounts) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        List<Out> outs = AbstractDb.hdAccountProvider.getUnspendOutByHDAccount
                (hdSeedId);
        Tx tx = TxBuilder.getInstance().buildTxFromAllAddress(outs, getNewChangeAddress(), Arrays
                .asList(amounts), Arrays.asList(toAddresses));
        return tx;
    }

    public List<HDAccount.HDAccountAddress> getSigningAddressesForInputs(List<In> inputs) {
        return AbstractDb.hdAccountProvider.getSigningAddressesForInputs(this.hdSeedId, inputs);
    }


    public boolean isSendFromMe(List<String> addresses) {
        List<HDAccount.HDAccountAddress> hdAccountAddressList = getAddressFromIn(addresses);
        return hdAccountAddressList.size() > 0;
    }

    private List<HDAccount.HDAccountAddress> getAddressFromIn(List<String> addresses) {

        List<HDAccount.HDAccountAddress> hdAccountAddressList = AbstractDb
                .hdAccountProvider.belongAccount(this.hdSeedId, addresses);
        return hdAccountAddressList;
    }

    public void updateIssuedInternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(this.hdSeedId, AbstractHD.PathType
                        .INTERNAL_ROOT_PATH,
                index);
    }

    public void updateIssuedExternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(this.hdSeedId, AbstractHD.PathType
                        .EXTERNAL_ROOT_PATH,
                index);
    }

    private String getNewChangeAddress() {
        return addressForPath(AbstractHD.PathType.INTERNAL_ROOT_PATH,
                issuedInternalIndex() + 1)
                .getAddress();
    }


    public void updateSyncComplete(HDAccount.HDAccountAddress accountAddress) {
        AbstractDb.hdAccountProvider.updateSyncdComplete(this.hdSeedId, accountAddress);
    }

    public int elementCountForBloomFilter() {
        return allGeneratedExternalAddressCount() * 2 + AbstractDb.hdAccountProvider
                .getUnspendOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType
                        .INTERNAL_ROOT_PATH);
    }

    public void addElementsForBloomFilter(BloomFilter filter) {
        List<byte[]> pubs = AbstractDb.hdAccountProvider.getPubs(this.hdSeedId, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        for (byte[] pub : pubs) {
            filter.insert(pub);
            filter.insert(Utils.sha256hash160(pub));
        }
        List<Out> outs = AbstractDb.hdAccountProvider
                .getUnspendOutByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType
                        .INTERNAL_ROOT_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
    }

    public long getBalance() {
        return balance;
    }

    public boolean isSyncComplete() {
        int unsyncedAddressCount = AbstractDb.hdAccountProvider.unSyncedAddressCount(this.hdSeedId);
        return unsyncedAddressCount == 0;
    }

    public List<Tx> getRecentlyTxsWithConfirmationCntLessThan(int confirmationCnt, int limit) {
        List<Tx> txList = new ArrayList<Tx>();
        int blockNo = BlockChain.getInstance().getLastBlock().getBlockNo() - confirmationCnt + 1;
        for (Tx tx : AbstractDb.hdAccountProvider.getRecentlyTxsByAccount(this.hdSeedId, blockNo, limit)) {
            txList.add(tx);
        }
        return txList;
    }

    public Tx buildTx(String changeAddress, List<Long> amounts, List<String> addresses) {
        throw new RuntimeException("use newTx() for hdAccount");
    }

    public boolean hasPrivKey() {
        return false;
    }

    public long getSortTime() {
        return 0;
    }

    public String getEncryptPrivKeyOfDb() {
        return null;
    }

    public String getFullEncryptPrivKeyOfDb() {
        return null;
    }

    protected DeterministicKey getChainRootKey(DeterministicKey accountKey, AbstractHD.PathType
            pathType) {
        return accountKey.deriveSoftened(pathType.getValue());
    }

    public boolean checkWithPassword(CharSequence password) {
        return true;
    }

    public boolean isFromXRandom() {
        return isFromXRandom;
    }

}
