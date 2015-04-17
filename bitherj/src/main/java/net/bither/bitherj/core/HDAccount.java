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

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HDAccount extends AbstractHD {

    public static final String HDAccountPlaceHolder = "HDAccount";

    private static final int LOOK_AHEAD_SIZE = 100;

    private long balance = 0;

    public HDAccount(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
        hdSeed = seedFromMnemonic(mnemonicSeed);
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);

        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);
        initHDAccount(master, encryptedMnemonicSeed, encryptedHDSeed);
    }

    // Create With Random
    public HDAccount(SecureRandom random, CharSequence password) {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        mnemonicSeed = new byte[16];
        String firstAddress = null;
        EncryptedData encryptedMnemonicSeed = null;
        EncryptedData encryptedHDSeed = null;
        DeterministicKey master = null;
        while (firstAddress == null) {
            try {
                random.nextBytes(mnemonicSeed);
                hdSeed = seedFromMnemonic(mnemonicSeed);
                encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
                encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);
                master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
                firstAddress = getFirstAddressFromSeed(password);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        initHDAccount(master, encryptedMnemonicSeed, encryptedHDSeed);
    }

    private void initHDAccount(DeterministicKey master, EncryptedData encryptedMnemonicSeed,
                               EncryptedData encryptedHDSeed) {
        String firstAddress;
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey internalKey = getChainRootKey(accountKey, PathType.INTERNAL_ROOT_PATH);
        DeterministicKey externalKey = getChainRootKey(accountKey, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey key = externalKey.deriveSoftened(0);
        firstAddress = key.toAddress();
        accountKey.wipe();
        master.wipe();
        List<HDAccountAddress> externalAddresses = new ArrayList<HDAccountAddress>();
        List<HDAccountAddress> internalAddresses = new ArrayList<HDAccountAddress>();
        for (int i = 0;
             i < LOOK_AHEAD_SIZE;
             i++) {
            byte[] subExternalPub = externalKey.deriveSoftened(i).getPubKey();
            byte[] subInternalPub = internalKey.deriveSoftened(i).getPubKey();
            HDAccountAddress externalAddress = new HDAccountAddress(subExternalPub
                    , PathType.EXTERNAL_ROOT_PATH, i);
            HDAccountAddress internalAddress = new HDAccountAddress(subInternalPub
                    , PathType.INTERNAL_ROOT_PATH, i);
            externalAddresses.add(externalAddress);
            internalAddresses.add(internalAddress);
        }
        wipeHDSeed();
        wipeMnemonicSeed();
        AbstractDb.hdAccountProvider.addAddress(externalAddresses);
        AbstractDb.hdAccountProvider.addAddress(internalAddresses);
        hdSeedId = AbstractDb.addressProvider.addHDAccount(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                        .getPubKeyExtended());
        internalKey.wipe();
        externalKey.wipe();
    }

    public HDAccount(int seedId) {
        this.hdSeedId = seedId;
        updateBalance();
    }

    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public String getQRCodeFullEncryptPrivKey() {
        return QRCodeUtil.HD_QR_CODE_FLAG + getFullEncryptPrivKey();
    }

    public byte[] getInternalPub() {
        return AbstractDb.addressProvider.getInternalPub(hdSeedId);
    }

    public byte[] getExternalPub() {
        return AbstractDb.addressProvider.getExternalPub(hdSeedId);
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.addressProvider.getHDFristAddress(hdSeedId);
    }

    private void supplyEnoughKeys() {
        int lackOfExternal = LOOK_AHEAD_SIZE - (allGeneratedExternalAddressCount() -
                issuedExternalIndex());
        if (lackOfExternal > 0) {
            supplyNewExternalKey(lackOfExternal);
        }

        int lackOfInternal = LOOK_AHEAD_SIZE - (allGeneratedInternalAddressCount() -
                issuedInternalIndex());
        if (lackOfInternal > 0) {
            supplyNewInternalKey(lackOfInternal);
        }
    }

    private void supplyNewInternalKey(int count) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getInternalPub());
        int firstIndex = allGeneratedInternalAddressCount();
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .INTERNAL_ROOT_PATH, i));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
    }

    private void supplyNewExternalKey(int count) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getExternalPub());
        int firstIndex = allGeneratedExternalAddressCount();
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .EXTERNAL_ROOT_PATH, i));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return AbstractDb.addressProvider.getHDAccountEncryptMnmonicSeed(hdSeedId);
    }


    @Override
    protected String getEncryptedHDSeed() {
        return AbstractDb.addressProvider.getHDAccountEncryptSeed(hdSeedId);
    }

    public String getReceivingAddress() {
        return AbstractDb.hdAccountProvider.externalAddress();
    }

    public String getShortReceivingAddress() {
        return Utils.shortenAddress(getReceivingAddress());
    }

    public int issuedInternalIndex() {

        return AbstractDb.hdAccountProvider.issuedIndex(PathType.INTERNAL_ROOT_PATH);
    }

    public int issuedExternalIndex() {
        return AbstractDb.hdAccountProvider.issuedIndex(PathType.EXTERNAL_ROOT_PATH);

    }

    private int allGeneratedInternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(PathType.INTERNAL_ROOT_PATH);
    }

    private int allGeneratedExternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(PathType.EXTERNAL_ROOT_PATH);
    }

    private HDAccountAddress addressForPath(PathType type, int index) {
        assert index < (type == PathType.EXTERNAL_ROOT_PATH ? allGeneratedExternalAddressCount()
                : allGeneratedInternalAddressCount());
        return AbstractDb.hdAccountProvider.addressForPath(type, index);
    }

    public boolean onNewTx(Tx tx) {
        List<HDAccountAddress> relatedAddresses = getRelatedAddressesForTx(tx);
        if (relatedAddresses.size() > 0) {
            AbstractDb.hdAccountProvider.addTx(tx);
            int maxInternal = -1, maxExternal = -1;
            for (HDAccountAddress a : relatedAddresses) {
                if (a.pathType == PathType.EXTERNAL_ROOT_PATH) {
                    if (a.index > maxExternal) {
                        maxExternal = a.index;
                    }
                } else {
                    if (a.index > maxInternal) {
                        maxInternal = a.index;
                    }
                }
            }

            if (maxExternal > issuedExternalIndex()) {
                updateIssuedExternalIndex(maxExternal);
            }
            if (maxInternal > issuedInternalIndex()) {
                updateIssuedInternalIndex(maxInternal);
            }

            supplyEnoughKeys();
            return true;
        }
        return false;
    }

    public boolean isTxRelated(Tx tx) {
        return getRelatedAddressesForTx(tx).size() > 0;
    }

    public int txCount() {
        return AbstractDb.hdAccountProvider.txCount();
    }

    public void updateBalance() {
        this.balance = AbstractDb.hdAccountProvider.getConfirmedBanlance()
                + calculateUnconfirmedBalance();
    }


    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.hdAccountProvider.getUnconfirmedTx();
        Collections.sort(txs);

        Set<byte[]> invalidTx = new HashSet<byte[]>();
        Set<OutPoint> spentOut = new HashSet<OutPoint>();
        Set<OutPoint> unspendOut = new HashSet<OutPoint>();

        for (int i = txs.size() - 1; i >= 0; i--) {
            Set<OutPoint> spent = new HashSet<OutPoint>();
            Tx tx = txs.get(i);

            Set<byte[]> inHashes = new HashSet<byte[]>();
            for (In in : tx.getIns()) {
                spent.add(new OutPoint(in.getPrevTxHash(), in.getPrevOutSn()));
                inHashes.add(in.getPrevTxHash());
            }

            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED
                    && (Utils.isIntersects(spent, spentOut) || Utils.isIntersects(inHashes, invalidTx))) {
                invalidTx.add(tx.getTxHash());
                continue;
            }

            spentOut.addAll(spent);
            HashSet<String> addressSet = getAllAddress();
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
                Tx tx1 = AbstractDb.hdAccountProvider.getTxDetailByTxHash(o.getTxHash());
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

    public List<HDAccountAddress> getRelatedAddressesForTx(Tx tx) {
        List<String> outAddressList = new ArrayList<String>();
        List<HDAccountAddress> hdAccountAddressList = new ArrayList<HDAccountAddress>();
        for (Out out : tx.getOuts()) {
            String outAddress = out.getOutAddress();
            outAddressList.add(outAddress);
        }
        List<HDAccountAddress> belongAccountOfOutList = AbstractDb.hdAccountProvider.belongAccount(outAddressList);
        if (belongAccountOfOutList != null
                && belongAccountOfOutList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfOutList);
        }

        List<HDAccountAddress> belongAccountOfInList = getAddressFromIn(tx);
        if (belongAccountOfInList != null && belongAccountOfInList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfInList);
        }

        return hdAccountAddressList;
    }

    public HashSet<String> getAllAddress() {
        return AbstractDb.hdAccountProvider.getAllAddress();
    }

    public Tx newTx(String toAddress, Long amount, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        return newTx(new String[]{toAddress}, new Long[]{amount}, password);
    }


    public Tx newTx(String[] toAddresses, Long[] amounts, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        List<Out> outs = AbstractDb.hdAccountProvider.getUnspendOut();

        Tx tx = TxBuilder.getInstance().buildTxFromAllAddress(outs, getNewChangeAddress(), Arrays
                .asList(amounts), Arrays.asList(toAddresses));
        List<HDAccountAddress> signingAddresses = getSigningAddressesForInputs(tx.getIns());
        assert signingAddresses.size() == tx.getIns().size();

        DeterministicKey master = masterKey(password);
        if (master == null) {
            return null;
        }
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey external = getChainRootKey(accountKey, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(accountKey, PathType.INTERNAL_ROOT_PATH);
        master.wipe();
        List<byte[]> unsignedHashes = tx.getUnsignedInHashes();
        assert unsignedHashes.size() == signingAddresses.size();
        ArrayList<byte[]> signatures = new ArrayList<byte[]>();
        HashMap<String, DeterministicKey> addressToKeyMap = new HashMap<String, DeterministicKey>
                (signingAddresses.size());

        for (int i = 0;
             i < signingAddresses.size();
             i++) {
            HDAccountAddress a = signingAddresses.get(i);
            byte[] unsigned = unsignedHashes.get(i);

            if (!addressToKeyMap.containsKey(a.getAddress())) {
                if (a.getPathType() == PathType.EXTERNAL_ROOT_PATH) {
                    addressToKeyMap.put(a.getAddress(), external.deriveSoftened(a.index));
                } else {
                    addressToKeyMap.put(a.getAddress(), internal.deriveSoftened(a.index));
                }
            }

            DeterministicKey key = addressToKeyMap.get(a.getAddress());
            assert key != null;

            TransactionSignature signature = new TransactionSignature(key.sign(unsigned, null),
                    TransactionSignature.SigHash.ALL, false);
            signatures.add(ScriptBuilder.createInputScript(signature, key).getProgram());
        }

        tx.signWithSignatures(signatures);
        assert tx.verifySignatures();

        external.wipe();
        internal.wipe();
        for (DeterministicKey key : addressToKeyMap.values()) {
            key.wipe();
        }

        return tx;
    }

    private List<HDAccountAddress> getSigningAddressesForInputs(List<In> inputs) {
        return AbstractDb.hdAccountProvider.getSigningAddressesForInputs(inputs);
    }


    public boolean isSendFromMe(Tx tx) {
        List<HDAccountAddress> hdAccountAddressList = getAddressFromIn(tx);
        return hdAccountAddressList.size() > 0;
    }

    private List<HDAccountAddress> getAddressFromIn(Tx tx) {
        boolean canParseFromScript = true;
        List<String> fromAddress = new ArrayList<String>();
        for (In in : tx.getIns()) {
            String address = in.getFromAddress();
            if (address != null) {
                fromAddress.add(address);
            } else {
                canParseFromScript = false;
                break;
            }
        }
        List<String> addresses;
        if (canParseFromScript) {
            addresses = fromAddress;
        } else {
            addresses = AbstractDb.hdAccountProvider.getInAddresses(tx);
        }
        List<HDAccountAddress> hdAccountAddressList = AbstractDb.hdAccountProvider.belongAccount(addresses);
        return hdAccountAddressList;
    }

    private void updateIssuedInternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(PathType.INTERNAL_ROOT_PATH, index);
    }

    private void updateIssuedExternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(PathType.EXTERNAL_ROOT_PATH, index);
    }

    private String getNewChangeAddress() {
        return addressForPath(PathType.INTERNAL_ROOT_PATH, issuedInternalIndex() + 1).getAddress();
    }

    public int elementCountForBloomFilter() {
        return allGeneratedInternalAddressCount() * 2 + allGeneratedExternalAddressCount() * 2;
    }

    public void addElementsForBloomFilter(BloomFilter filter) {
        List<byte[]> pubs = AbstractDb.hdAccountProvider.getPubs(PathType.EXTERNAL_ROOT_PATH);
        for (byte[] pub : pubs) {
            filter.insert(pub);
            filter.insert(Utils.sha256hash160(pub));
        }
        pubs = AbstractDb.hdAccountProvider.getPubs(PathType.INTERNAL_ROOT_PATH);
        for (byte[] pub : pubs) {
            filter.insert(pub);
            filter.insert(Utils.sha256hash160(pub));
        }

    }

    public long getBalance() {
        return balance;
    }

    public boolean isSyncComplete() {
        int unsyncedAddressCount = AbstractDb.hdAccountProvider.unSyncedAddressCount();
        return unsyncedAddressCount == 0;
    }

    public List<Tx> getRecentlyTxsWithConfirmationCntLessThan(int confirmationCnt, int limit) {
        List<Tx> txList = new ArrayList<Tx>();
        int blockNo = BlockChain.getInstance().getLastBlock().getBlockNo() - confirmationCnt + 1;
        for (Tx tx : AbstractDb.hdAccountProvider.getRecentlyTxsByAddress(blockNo, limit)) {
            txList.add(tx);
        }
        return txList;
    }

    public List<Tx> getPublishedTxs() {
        return AbstractDb.hdAccountProvider.getPublishedTxs();
    }

    public static class HDAccountAddress {
        private String address;
        private byte[] pub;
        private int index;
        private PathType pathType;
        private boolean isSynced;
        private boolean isIssued;

        public HDAccountAddress(byte[] pub, PathType pathType, int index) {
            this(Utils.toAddress(Utils.sha256hash160(pub)), pub, pathType, index, false, true);
        }

        public HDAccountAddress(String address, byte[] pub, PathType pathType, int index, boolean isIssued, boolean isSynced) {
            this.pub = pub;
            this.address = address;
            this.pathType = pathType;
            this.index = index;
            this.isIssued = isIssued;
            this.isSynced = isSynced;
        }

        public String getAddress() {
            return address;
        }

        public byte[] getPub() {
            return pub;
        }

        public int getIndex() {
            return index;
        }

        public PathType getPathType() {
            return pathType;
        }

        public boolean isIssued() {
            return isIssued;
        }

        public boolean isSynced() {
            return isSynced;
        }
    }
}
