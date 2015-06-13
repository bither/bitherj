/*
 *
 *  Copyright 2014 http://Bither.net
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */

package net.bither.bitherj.core;


import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import net.bither.bitherj.api.CreateHDMAddressApi;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.SecureRandom;
import java.util.*;

public class DesktopHDMKeychain extends AbstractHD {


    private long balance = 0;
    private static final int LOOK_AHEAD_SIZE = 100;

    protected int hdSeedId = -1;

    private static final Logger log = LoggerFactory.getLogger(DesktopHDMKeychain.class);


    protected ArrayList<DesktopHDMAddress> allCompletedAddresses;
    private Collection<DesktopHDMAddress> addressesInUse;
    private Collection<DesktopHDMAddress> addressesTrashed;


    public DesktopHDMKeychain(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
        String firstAddress = null;
        EncryptedData encryptedMnemonicSeed = null;
        EncryptedData encryptedHDSeed = null;
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();

        hdSeed = seedFromMnemonic(mnemonicSeed);
        encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);
        firstAddress = getFirstAddressFromSeed(password);
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = AbstractDb.enDesktopAddressProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address, null, null);
        allCompletedAddresses = new ArrayList<DesktopHDMAddress>();

    }

    // Create With Random
    public DesktopHDMKeychain(SecureRandom random, CharSequence password) {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        mnemonicSeed = new byte[32];
        String firstAddress = null;
        EncryptedData encryptedMnemonicSeed = null;
        EncryptedData encryptedHDSeed = null;
        while (firstAddress == null) {
            try {
                random.nextBytes(mnemonicSeed);
                hdSeed = seedFromMnemonic(mnemonicSeed);
                encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
                encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);
                firstAddress = getFirstAddressFromSeed(password);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = AbstractDb.enDesktopAddressProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address, null, null);
        allCompletedAddresses = new ArrayList<DesktopHDMAddress>();
    }

    // From DB
    public DesktopHDMKeychain(int seedId) {
        this.hdSeedId = seedId;
        allCompletedAddresses = new ArrayList<DesktopHDMAddress>();
        initFromDb();
    }

    // Import
    public DesktopHDMKeychain(EncryptedData encryptedMnemonicSeed, CharSequence password) throws
            HDMBitherIdNotMatchException, MnemonicException.MnemonicLengthException {
        mnemonicSeed = encryptedMnemonicSeed.decrypt(password);
        hdSeed = seedFromMnemonic(mnemonicSeed);
        isFromXRandom = encryptedMnemonicSeed.isXRandom();
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        allCompletedAddresses = new ArrayList<DesktopHDMAddress>();
        ArrayList<DesktopHDMAddress> as = new ArrayList<DesktopHDMAddress>();
        ArrayList<HDMAddress.Pubs> uncompPubs = new ArrayList<HDMAddress.Pubs>();

        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        String firstAddress = getFirstAddressFromSeed(password);
        wipeMnemonicSeed();
        wipeHDSeed();

        this.hdSeedId = AbstractDb.enDesktopAddressProvider.addHDKey(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, null, null);
        if (as.size() > 0) {
            //   EnDesktopAddressProvider.getInstance().completeHDMAddresses(getHdSeedId(), as);
            allCompletedAddresses.addAll(as);
            if (uncompPubs.size() > 0) {
                //  EnDesktopAddressProvider.getInstance().prepareHDMAddresses(getHdSeedId(), uncompPubs);
                for (HDMAddress.Pubs p : uncompPubs) {
                    AbstractDb.addressProvider.setHDMPubsRemote(getHdSeedId(), p.index, p.remote);
                }
            }
        }
    }


    public List<DesktopHDMAddress> getAddresses() {
        synchronized (allCompletedAddresses) {
            if (addressesInUse == null) {
                addressesInUse = Collections2.filter(allCompletedAddresses,
                        new Predicate<DesktopHDMAddress>() {
                            @Override
                            public boolean apply(@Nullable DesktopHDMAddress input) {
                                return !input.isTrashed();
                            }
                        });
            }
            return new ArrayList<DesktopHDMAddress>(addressesInUse);
        }
    }

    public List<DesktopHDMAddress> getTrashedAddresses() {
        synchronized (allCompletedAddresses) {
            if (addressesTrashed == null) {
                addressesTrashed = Collections2.filter(allCompletedAddresses,
                        new Predicate<DesktopHDMAddress>() {
                            @Override
                            public boolean apply(@Nullable DesktopHDMAddress input) {
                                return input.isTrashed();
                            }
                        });
            }
            return new ArrayList<DesktopHDMAddress>(addressesTrashed);
        }
    }

    private DeterministicKey externalChainRoot(CharSequence password) throws MnemonicException.MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey externalKey = getChainRootKey(accountKey, PathType.EXTERNAL_ROOT_PATH);
        master.wipe();
        accountKey.wipe();
        return externalKey;
    }

    public byte[] getExternalChainRootPubExtended(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey ex = externalChainRoot(password);
        byte[] pub = ex.getPubKeyExtended();
        ex.wipe();
        return pub;
    }

    public String getExternalChainRootPubExtendedAsHex(CharSequence password) throws
            MnemonicException.MnemonicLengthException {
        return Utils.bytesToHexString(getExternalChainRootPubExtended(password)).toUpperCase();
    }


    public int getCurrentMaxAddressIndex() {
        synchronized (allCompletedAddresses) {
            int max = Integer.MIN_VALUE;
            for (DesktopHDMAddress address : allCompletedAddresses) {
                if (address.getIndex() > max) {
                    max = address.getIndex();
                }
            }
            return max;
        }
    }

    public List<DesktopHDMAddress> getAllCompletedAddresses() {
        synchronized (allCompletedAddresses) {
            return allCompletedAddresses;
        }
    }

    private void initFromDb() {
        isFromXRandom = AbstractDb.enDesktopAddressProvider.isHDSeedFromXRandom(getHdSeedId());
        initAddressesFromDb();
    }

    private void initAddressesFromDb() {
        synchronized (allCompletedAddresses) {
//            List<EnDesktopHDMAddress> addrs = EnDesktopTxProvider.getInstance().getHDMAddressInUse(this);
//            if (addrs != null) {
//                allCompletedAddresses.addAll(addrs);
//            }
        }
    }


    public boolean isFromXRandom() {
        return isFromXRandom;
    }


    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public String getQRCodeFullEncryptPrivKey() {
        return QRCodeUtil.HDM_QR_CODE_FLAG
                + getFullEncryptPrivKey();
    }

    @Override
    protected String getEncryptedHDSeed() {

        String encrypted = AbstractDb.enDesktopAddressProvider.getEncryptHDSeed(hdSeedId);
        if (encrypted == null) {
            return null;
        }
        return encrypted.toUpperCase();
    }

    @Override
    public String getEncryptedMnemonicSeed() {

        return AbstractDb.enDesktopAddressProvider.getEncryptMnemonicSeed(hdSeedId).toUpperCase();
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.enDesktopAddressProvider.getHDMFristAddress(hdSeedId);
    }

    public boolean checkWithPassword(CharSequence password) {

        try {
            decryptHDSeed(password);
            decryptMnemonicSeed(password);
            byte[] hdCopy = Arrays.copyOf(hdSeed, hdSeed.length);
            boolean hdSeedSafe = Utils.compareString(getFirstAddressFromDb(),
                    getFirstAddressFromSeed(null));
            boolean mnemonicSeedSafe = Arrays.equals(seedFromMnemonic(mnemonicSeed), hdCopy);
            Utils.wipeBytes(hdCopy);
            wipeHDSeed();
            wipeMnemonicSeed();
            return hdSeedSafe && mnemonicSeedSafe;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    public static void getRemotePublicKeys(HDMBId hdmBId, CharSequence password,
                                           List<HDMAddress.Pubs> partialPubs) throws Exception {
        byte[] decryptedPassword = hdmBId.decryptHDMBIdPassword(password);
        CreateHDMAddressApi createHDMAddressApi = new CreateHDMAddressApi(hdmBId.getAddress(),
                partialPubs, decryptedPassword);
        createHDMAddressApi.handleHttpPost();
        List<byte[]> remotePubs = createHDMAddressApi.getResult();
        for (int i = 0;
             i < partialPubs.size();
             i++) {
            HDMAddress.Pubs pubs = partialPubs.get(i);
            pubs.remote = remotePubs.get(i);
        }
    }

    public static final class HDMColdPubNotSameException extends RuntimeException {

    }

    public static final class HDMBitherIdNotMatchException extends RuntimeException {
        public static final String msg = "HDM Bid Not Match";

        public HDMBitherIdNotMatchException() {
            super(msg);
        }
    }

    public static boolean checkPassword(String keysString, CharSequence password) throws
            MnemonicException.MnemonicLengthException {
        String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keysString);
        String address = Base58.hexToBase58WithAddress(passwordSeeds[0]);
        String encreyptString = Utils.joinString(new String[]{passwordSeeds[1], passwordSeeds[2],
                passwordSeeds[3]}, QRCodeUtil.QR_CODE_SPLIT);
        byte[] seed = new EncryptedData(encreyptString).decrypt(password);
        MnemonicCode mnemonic = MnemonicCode.instance();

        byte[] s = mnemonic.toSeed(mnemonic.toMnemonic(seed), "");

        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(s);

        DeterministicKey purpose = master.deriveHardened(44);

        DeterministicKey coinType = purpose.deriveHardened(0);

        DeterministicKey account = coinType.deriveHardened(0);

        DeterministicKey external = account.deriveSoftened(0);

        external.clearPrivateKey();

        DeterministicKey key = external.deriveSoftened(0);
        boolean result = Utils.compareString(address, Utils.toAddress(key.getPubKeyHash()));
        key.wipe();

        return result;
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
            as.add(new HDAccount.HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .INTERNAL_ROOT_PATH, i, isSyncedComplete));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
        log.info("HD supplied {} internal addresses", as.size());
    }

    private void supplyNewExternalKey(int count, boolean isSyncedComplete) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getExternalPub());
        int firstIndex = allGeneratedExternalAddressCount();
        ArrayList<HDAccount.HDAccountAddress> as = new ArrayList<HDAccount.HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccount.HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .EXTERNAL_ROOT_PATH, i, isSyncedComplete));
        }
        AbstractDb.hdAccountProvider.addAddress(as);
        log.info("HD supplied {} external addresses", as.size());
    }

    public void onNewTx(Tx tx, List<HDAccount.HDAccountAddress> relatedAddresses, Tx.TxNotificationType txNotificationType) {
        if (relatedAddresses == null || relatedAddresses.size() == 0) {
            return;
        }

        int maxInternal = -1, maxExternal = -1;
//        for (HDAccount.HDAccountAddress a : relatedAddresses) {
//            if (a.pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
//                if (a.index > maxExternal) {
//                    maxExternal = a.index;
//                }
//            } else {
//                if (a.index > maxInternal) {
//                    maxInternal = a.index;
//                }
//            }
//        }

        log.info("HD on new tx issued ex {}, issued in {}", maxExternal, maxInternal);
        if (maxExternal >= 0 && maxExternal > issuedExternalIndex()) {
            updateIssuedExternalIndex(maxExternal);
        }
        if (maxInternal >= 0 && maxInternal > issuedInternalIndex()) {
            updateIssuedInternalIndex(maxInternal);
        }

        supplyEnoughKeys(true);

        long deltaBalance = getDeltaBalance();
//        AbstractApp.notificationService.notificatTx(HDAccountPlaceHolder, tx, txNotificationType,
//                deltaBalance);
    }

    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.hdAccountProvider.getHDAccountUnconfirmedTx();
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

    private long getDeltaBalance() {
        long oldBalance = this.balance;
        this.updateBalance();
        return this.balance - oldBalance;
    }

    public void updateBalance() {
        this.balance = AbstractDb.hdAccountProvider.getHDAccountConfirmedBanlance(hdSeedId)
                + calculateUnconfirmedBalance();
    }

    public HashSet<String> getBelongAccountAddresses(List<String> addressList) {
        return AbstractDb.hdAccountProvider.getBelongAccountAddresses(addressList);
    }

    public void updateIssuedInternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(PathType.INTERNAL_ROOT_PATH, index);
    }

    public void updateIssuedExternalIndex(int index) {
        AbstractDb.hdAccountProvider.updateIssuedIndex(PathType.EXTERNAL_ROOT_PATH, index);
    }

    public byte[] getInternalPub() {
        //   return AbstractDb.addressProvider.getInternalPub(hdSeedId);
        return new byte[]{};
    }

    public byte[] getExternalPub() {

        //return AbstractDb.addressProvider.getExternalPub(hdSeedId);
        return new byte[]{};
    }

    public int issuedInternalIndex() {

        return AbstractDb.hdAccountProvider.issuedIndex(PathType.INTERNAL_ROOT_PATH);
    }

    public int issuedExternalIndex() {
        return AbstractDb.hdAccountProvider.issuedIndex(PathType.EXTERNAL_ROOT_PATH);

    }

    private int allGeneratedInternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(PathType
                .INTERNAL_ROOT_PATH);
    }

    private int allGeneratedExternalAddressCount() {
        return AbstractDb.hdAccountProvider.allGeneratedAddressCount(PathType
                .EXTERNAL_ROOT_PATH);
    }


}
