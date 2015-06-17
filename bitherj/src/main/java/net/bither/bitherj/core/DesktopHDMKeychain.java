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


import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.api.CreateHDMAddressApi;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class DesktopHDMKeychain extends AbstractHD {

    public static final String DesktopHDMKeychainPlaceHolder = "DesktopHDMKeychain";
    private long balance = 0;
    private static final int LOOK_AHEAD_SIZE = 100;


    private static final Logger log = LoggerFactory.getLogger(DesktopHDMKeychain.class);


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
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        initHDAccount(master, encryptedMnemonicSeed, encryptedHDSeed, true);

    }


    // Create With Random
    public DesktopHDMKeychain(SecureRandom random, CharSequence password) {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        mnemonicSeed = new byte[32];

        EncryptedData encryptedMnemonicSeed = null;
        EncryptedData encryptedHDSeed = null;

        try {
            random.nextBytes(mnemonicSeed);
            hdSeed = seedFromMnemonic(mnemonicSeed);
            encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
            encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);

        } catch (Exception e) {
            e.printStackTrace();
        }

        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        initHDAccount(master, encryptedMnemonicSeed, encryptedHDSeed, true);
    }


    // From DB
    public DesktopHDMKeychain(int seedId) {
        this.hdSeedId = seedId;
        isFromXRandom = AbstractDb.desktopAddressProvider.isHDSeedFromXRandom(getHdSeedId());
        updateBalance();
    }

    // Import
    public DesktopHDMKeychain(EncryptedData encryptedMnemonicSeed, CharSequence password) throws
            HDMBitherIdNotMatchException, MnemonicException.MnemonicLengthException {
        mnemonicSeed = encryptedMnemonicSeed.decrypt(password);
        hdSeed = seedFromMnemonic(mnemonicSeed);
        isFromXRandom = encryptedMnemonicSeed.isXRandom();
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        ArrayList<DesktopHDMAddress> as = new ArrayList<DesktopHDMAddress>();
        ArrayList<HDMAddress.Pubs> uncompPubs = new ArrayList<HDMAddress.Pubs>();

        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        String firstAddress = getFirstAddressFromSeed(password);
        wipeMnemonicSeed();
        wipeHDSeed();

        this.hdSeedId = AbstractDb.desktopAddressProvider.addHDKey(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, null, null);
        if (as.size() > 0) {
            //   EnDesktopAddressProvider.getInstance().completeHDMAddresses(getHdSeedId(), as);

            if (uncompPubs.size() > 0) {
                //  EnDesktopAddressProvider.getInstance().prepareHDMAddresses(getHdSeedId(), uncompPubs);
                for (HDMAddress.Pubs p : uncompPubs) {
                    AbstractDb.addressProvider.setHDMPubsRemote(getHdSeedId(), p.index, p.remote);
                }
            }
        }
    }


    private void initHDAccount(DeterministicKey master, EncryptedData encryptedMnemonicSeed,
                               EncryptedData encryptedHDSeed, boolean isSyncedComplete) {
        String firstAddress;
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey internalKey = getChainRootKey(accountKey, AbstractHD.PathType.INTERNAL_ROOT_PATH);
        DeterministicKey externalKey = getChainRootKey(accountKey, AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey key = externalKey.deriveSoftened(0);
        firstAddress = key.toAddress();
        accountKey.wipe();
        master.wipe();

        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = AbstractDb.desktopAddressProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                        .getPubKeyExtended());
        internalKey.wipe();
        externalKey.wipe();


    }

    public void addAccountKey(byte[] firstByte, byte[] secondByte) {
        if (new BigInteger(1, firstByte).compareTo(new BigInteger(1, secondByte)) > 0) {
            byte[] temp = firstByte;
            firstByte = secondByte;
            secondByte = temp;
        }

        DeterministicKey firstAccountKey = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (firstByte);
        DeterministicKey secondAccountKey = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (secondByte);

        DeterministicKey firestInternalKey = getChainRootKey(firstAccountKey, AbstractHD.PathType.INTERNAL_ROOT_PATH);
        DeterministicKey firestExternalKey = getChainRootKey(firstAccountKey, AbstractHD.PathType.EXTERNAL_ROOT_PATH);

        DeterministicKey secondInternalKey = getChainRootKey(secondAccountKey, AbstractHD.PathType.INTERNAL_ROOT_PATH);
        DeterministicKey secondExternalKey = getChainRootKey(secondAccountKey, AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        List<byte[]> externalPubs = new ArrayList<byte[]>();
        List<byte[]> internalPubs = new ArrayList<byte[]>();
        externalPubs.add(firestExternalKey.getPubKeyExtended());
        externalPubs.add(secondExternalKey.getPubKeyExtended());
        internalPubs.add(firestInternalKey.getPubKeyExtended());
        internalPubs.add(secondInternalKey.getPubKeyExtended());
        AbstractDb.desktopAddressProvider.addHDMPub(externalPubs, internalPubs);
        addDesktopAddress(PathType.EXTERNAL_ROOT_PATH, LOOK_AHEAD_SIZE);
        addDesktopAddress(PathType.INTERNAL_ROOT_PATH, LOOK_AHEAD_SIZE);
    }

    private void addDesktopAddress(PathType pathType, int count) {
        if (pathType == PathType.EXTERNAL_ROOT_PATH) {
            List<DesktopHDMAddress> desktopHDMAddresses = new ArrayList<DesktopHDMAddress>();
            List<byte[]> externalPubs = AbstractDb.desktopAddressProvider.getExternalPubs();
            DeterministicKey externalKey1 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (externalPubs.get(0));
            DeterministicKey externalKey2 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (externalPubs.get(1));
            DeterministicKey externalKey3 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (externalPubs.get(2));
            for (int i = 0;
                 i < count;
                 i++) {
                byte[] subExternalPub1 = externalKey1.deriveSoftened(i).getPubKey();
                byte[] subExternalPub2 = externalKey2.deriveSoftened(i).getPubKey();
                byte[] subExternalPub3 = externalKey3.deriveSoftened(i).getPubKey();
                HDMAddress.Pubs pubs = new HDMAddress.Pubs();
                pubs.hot = subExternalPub1;
                pubs.cold = subExternalPub2;
                pubs.remote = subExternalPub3;
                pubs.index = i;
                DesktopHDMAddress desktopHDMAddress = new DesktopHDMAddress(pubs, pathType, DesktopHDMKeychain.this, false);
                desktopHDMAddresses.add(desktopHDMAddress);

            }
            AbstractDb.desktopTxProvider.addAddress(desktopHDMAddresses);
        } else {
            List<DesktopHDMAddress> desktopHDMAddresses = new ArrayList<DesktopHDMAddress>();
            List<byte[]> internalPubs = AbstractDb.desktopAddressProvider.getInternalPubs();
            DeterministicKey internalKey1 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (internalPubs.get(0));
            DeterministicKey internalKey2 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (internalPubs.get(1));
            DeterministicKey internalKey3 = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (internalPubs.get(2));
            for (int i = 0;
                 i < count;
                 i++) {
                byte[] subInternalPub1 = internalKey1.deriveSoftened(i).getPubKey();
                byte[] subInternalPub2 = internalKey2.deriveSoftened(i).getPubKey();
                byte[] subInternalPub3 = internalKey3.deriveSoftened(i).getPubKey();
                HDMAddress.Pubs pubs = new HDMAddress.Pubs();
                pubs.hot = subInternalPub1;
                pubs.cold = subInternalPub2;
                pubs.remote = subInternalPub3;
                pubs.index = i;
                DesktopHDMAddress desktopHDMAddress = new DesktopHDMAddress(pubs, pathType, DesktopHDMKeychain.this, false);
                desktopHDMAddresses.add(desktopHDMAddress);

            }
            AbstractDb.desktopTxProvider.addAddress(desktopHDMAddresses);
        }


    }

    public boolean hasDesktopHDMAddress() {
        return AbstractDb.desktopTxProvider.hasAddress();
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

    public boolean isTxRelated(Tx tx, List<String> inAddresses) {
        return getRelatedAddressesForTx(tx, inAddresses).size() > 0;
    }

    public Tx newTx(String toAddress, Long amount, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        return newTx(new String[]{toAddress}, new Long[]{amount}, password);
    }


    public Tx newTx(String[] toAddresses, Long[] amounts, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        List<Out> outs = AbstractDb.hdAccountProvider.getUnspendOutByHDAccount(hdSeedId);

        Tx tx = TxBuilder.getInstance().buildTxFromAllAddress(outs, getNewChangeAddress(), Arrays
                .asList(amounts), Arrays.asList(toAddresses));
        List<DesktopHDMAddress> signingAddresses = getSigningAddressesForInputs(tx.getIns());
        assert signingAddresses.size() == tx.getIns().size();

        DeterministicKey master = masterKey(password);
        if (master == null) {
            return null;
        }
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey external = getChainRootKey(accountKey, AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(accountKey, AbstractHD.PathType.INTERNAL_ROOT_PATH);
        accountKey.wipe();
        master.wipe();
        List<byte[]> unsignedHashes = tx.getUnsignedInHashes();
        assert unsignedHashes.size() == signingAddresses.size();
        ArrayList<byte[]> signatures = new ArrayList<byte[]>();
        HashMap<String, DeterministicKey> addressToKeyMap = new HashMap<String, DeterministicKey>
                (signingAddresses.size());

        for (int i = 0;
             i < signingAddresses.size();
             i++) {
            DesktopHDMAddress a = signingAddresses.get(i);
            byte[] unsigned = unsignedHashes.get(i);

            if (!addressToKeyMap.containsKey(a.getAddress())) {
                if (a.getPathType() == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                    addressToKeyMap.put(a.getAddress(), external.deriveSoftened(a.getIndex()));
                } else {
                    addressToKeyMap.put(a.getAddress(), internal.deriveSoftened(a.getIndex()));
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


    public List<DesktopHDMAddress> getRelatedAddressesForTx(Tx tx, List<String> inAddresses) {
        List<String> outAddressList = new ArrayList<String>();
        List<DesktopHDMAddress> hdAccountAddressList = new ArrayList<DesktopHDMAddress>();
        for (Out out : tx.getOuts()) {
            String outAddress = out.getOutAddress();
            outAddressList.add(outAddress);
        }
        List<DesktopHDMAddress> belongAccountOfOutList = AbstractDb.desktopTxProvider.belongAccount(DesktopHDMKeychain.this, outAddressList);
        if (belongAccountOfOutList != null
                && belongAccountOfOutList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfOutList);
        }

        List<DesktopHDMAddress> belongAccountOfInList = getAddressFromIn(inAddresses);
        if (belongAccountOfInList != null && belongAccountOfInList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfInList);
        }

        return hdAccountAddressList;
    }

    private List<DesktopHDMAddress> getAddressFromIn(List<String> addresses) {

        List<DesktopHDMAddress> hdAccountAddressList = AbstractDb.desktopTxProvider.belongAccount(DesktopHDMKeychain.this, addresses);
        return hdAccountAddressList;
    }


    private String getNewChangeAddress() {
        return addressForPath(AbstractHD.PathType.INTERNAL_ROOT_PATH, issuedInternalIndex() + 1).getAddress();
    }

    private DesktopHDMAddress addressForPath(AbstractHD.PathType type, int index) {
        assert index < (type == AbstractHD.PathType.EXTERNAL_ROOT_PATH ? allGeneratedExternalAddressCount()
                : allGeneratedInternalAddressCount());
        return AbstractDb.desktopTxProvider.addressForPath(DesktopHDMKeychain.this, type, index);
    }

    public boolean isFromXRandom() {
        return isFromXRandom;
    }


    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    private List<DesktopHDMAddress> getSigningAddressesForInputs(List<In> inputs) {
        return AbstractDb.desktopTxProvider.getSigningAddressesForInputs(DesktopHDMKeychain.this, inputs);
    }

    public String getQRCodeFullEncryptPrivKey() {
        return QRCodeUtil.HDM_QR_CODE_FLAG
                + getFullEncryptPrivKey();
    }

    @Override
    protected String getEncryptedHDSeed() {

        String encrypted = AbstractDb.desktopAddressProvider.getEncryptHDSeed(hdSeedId);
        if (encrypted == null) {
            return null;
        }
        return encrypted.toUpperCase();
    }

    @Override
    public String getEncryptedMnemonicSeed() {

        return AbstractDb.desktopAddressProvider.getEncryptMnemonicSeed(hdSeedId).toUpperCase();
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.desktopAddressProvider.getHDMFristAddress(hdSeedId);
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

    public void onNewTx(Tx tx, List<DesktopHDMAddress> relatedAddresses, Tx.TxNotificationType txNotificationType) {
        if (relatedAddresses == null || relatedAddresses.size() == 0) {
            return;
        }

        int maxInternal = -1, maxExternal = -1;
        for (DesktopHDMAddress a : relatedAddresses) {
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
        AbstractApp.notificationService.notificatTx(DesktopHDMKeychainPlaceHolder, tx, txNotificationType,
                deltaBalance);
    }


    public int elementCountForBloomFilter() {
        return allGeneratedExternalAddressCount() * 2 + AbstractDb.desktopTxProvider
                .getUnspendOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType
                        .INTERNAL_ROOT_PATH);
    }

    public void addElementsForBloomFilter(BloomFilter filter) {
        List<HDMAddress.Pubs> pubses = AbstractDb.desktopTxProvider.getPubs(AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        for (HDMAddress.Pubs pub : pubses) {
            byte[] pubByte = pub.getMultiSigScript().getProgram();
            filter.insert(pubByte);
            filter.insert(Utils.sha256hash160(pubByte));
        }
        List<Out> outs = AbstractDb.desktopTxProvider.getUnspendOutByHDAccountWithPath
                (getHdSeedId(), AbstractHD.PathType.INTERNAL_ROOT_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
    }

    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.desktopTxProvider.getHDAccountUnconfirmedTx();
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
        this.balance = AbstractDb.desktopTxProvider.getHDAccountConfirmedBanlance(hdSeedId)
                + calculateUnconfirmedBalance();
    }

    public long getBalance() {
        return this.balance;
    }

    public HashSet<String> getBelongAccountAddresses(List<String> addressList) {
        return AbstractDb.desktopTxProvider.getBelongAccountAddresses(addressList);
    }

    public void updateIssuedInternalIndex(int index) {
        AbstractDb.desktopTxProvider.updateIssuedIndex(PathType.INTERNAL_ROOT_PATH, index);
    }

    public void updateIssuedExternalIndex(int index) {
        AbstractDb.desktopTxProvider.updateIssuedIndex(PathType.EXTERNAL_ROOT_PATH, index);
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

        return AbstractDb.desktopTxProvider.issuedIndex(PathType.INTERNAL_ROOT_PATH);
    }

    public int issuedExternalIndex() {
        return AbstractDb.desktopTxProvider.issuedIndex(PathType.EXTERNAL_ROOT_PATH);

    }

    private int allGeneratedInternalAddressCount() {
        return AbstractDb.desktopTxProvider.allGeneratedAddressCount(PathType
                .INTERNAL_ROOT_PATH);
    }

    private int allGeneratedExternalAddressCount() {
        return AbstractDb.desktopTxProvider.allGeneratedAddressCount(PathType
                .EXTERNAL_ROOT_PATH);
    }

    public String getMasterPubKeyExtendedStr(CharSequence password) {
        byte[] bytes = getMasterPubKeyExtended(password);
        return Utils.bytesToHexString(bytes).toUpperCase(Locale.US);
    }

    public String externalAddress() {
        return AbstractDb.desktopTxProvider.externalAddress();
    }


}
