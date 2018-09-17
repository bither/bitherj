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
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IHDAccountProvider;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static net.bither.bitherj.core.AbstractHD.getPurposePathLevel;
import static net.bither.bitherj.utils.HDAccountUtils.getRedeemScript;
import static net.bither.bitherj.utils.HDAccountUtils.getSign;
import static net.bither.bitherj.utils.HDAccountUtils.getWitness;

public class HDAccount extends Address {
    public static final String HDAccountPlaceHolder = "HDAccount";
    public static final String HDAccountMonitoredPlaceHolder = "HDAccountMonitored";
    public static final int MaxUnusedNewAddressCount = 20;

    public interface HDAccountGenerationDelegate {
        void onHDAccountGenerationProgress(double progress);
    }

    private static final double GenerationPreStartProgress = 0.01;

    private static final int LOOK_AHEAD_SIZE = 100;

    private long balance = 0;

    protected transient byte[] mnemonicSeed;
    protected transient byte[] hdSeed;
    protected int hdSeedId = -1;
    protected boolean isFromXRandom;
    private boolean hasSeed;
    private MnemonicCode mnemonicCode = MnemonicCode.instance();
    private boolean isSegwit = false;

    private static final Logger log = LoggerFactory.getLogger(HDAccount.class);

    public HDAccount(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(mnemonicCode, mnemonicSeed, password, true);
    }

    public HDAccount(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password,
                     boolean isSyncedComplete) throws
            MnemonicException
            .MnemonicLengthException {
        super();
        this.mnemonicCode = mnemonicCode;
        this.mnemonicSeed = mnemonicSeed;
        hdSeed = seedFromMnemonic(mnemonicCode, mnemonicSeed);
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password,
                isFromXRandom);
        DeterministicKey account = getAccount(master, AbstractHD.PurposePathLevel.Normal);
        DeterministicKey purpose49Account = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
        account.clearPrivateKey();
        purpose49Account.clearPrivateKey();
        initHDAccount(account, purpose49Account, encryptedMnemonicSeed, encryptedHDSeed, isFromXRandom,
                isSyncedComplete, null);
    }

    // Create With Random
    public HDAccount(SecureRandom random, CharSequence password, HDAccountGenerationDelegate generationDelegate) throws MnemonicException.MnemonicLengthException {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        mnemonicSeed = new byte[16];
        random.nextBytes(mnemonicSeed);
        hdSeed = seedFromMnemonic(mnemonicCode, mnemonicSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password,
                isFromXRandom);
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        DeterministicKey account = getAccount(master, AbstractHD.PurposePathLevel.Normal);
        DeterministicKey purpose49Account = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
        account.clearPrivateKey();
        purpose49Account.clearPrivateKey();
        initHDAccount(account, purpose49Account, encryptedMnemonicSeed, encryptedHDSeed, isFromXRandom, true,
                generationDelegate);
    }

    //use in import
    public HDAccount(MnemonicCode mnemonicCode, EncryptedData encryptedMnemonicSeed, CharSequence password, boolean
            isSyncedComplete)
            throws MnemonicException.MnemonicLengthException {
        this.mnemonicCode = mnemonicCode;
        mnemonicSeed = encryptedMnemonicSeed.decrypt(password);
        hdSeed = seedFromMnemonic(mnemonicCode, mnemonicSeed);
        isFromXRandom = encryptedMnemonicSeed.isXRandom();
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        DeterministicKey account = getAccount(master, AbstractHD.PurposePathLevel.Normal);
        DeterministicKey purpose49Account = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
        account.clearPrivateKey();
        purpose49Account.clearPrivateKey();
        initHDAccount(account, purpose49Account, encryptedMnemonicSeed, encryptedHDSeed, isFromXRandom,
                isSyncedComplete, null);
    }

    public HDAccount(byte[] accountExtentedPub, byte[] p2shp2wpkhAccountExtentedPub) throws MnemonicException.MnemonicLengthException {
        this(accountExtentedPub, p2shp2wpkhAccountExtentedPub, false);
    }

    public HDAccount(byte[] accountExtentedPub, byte[] p2shp2wpkhAccountExtentedPub, boolean isFromXRandom) throws MnemonicException
            .MnemonicLengthException {
        this(accountExtentedPub, p2shp2wpkhAccountExtentedPub, isFromXRandom, true, null);
    }


    public HDAccount(byte[] accountExtentedPub, byte[] p2shp2wpkhAccountExtentedPub, boolean isFromXRandom, boolean isSyncedComplete,
                     HDAccount.HDAccountGenerationDelegate generationDelegate ) throws
            MnemonicException.MnemonicLengthException {
        super();
        this.isFromXRandom = isFromXRandom;
        DeterministicKey account = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (accountExtentedPub);
        DeterministicKey accountPurpose49Key = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (p2shp2wpkhAccountExtentedPub);
        initHDAccount(account, accountPurpose49Key, null, null, isFromXRandom, isSyncedComplete, generationDelegate);
    }

    private void initHDAccount(DeterministicKey accountKey, DeterministicKey accountPurpose49Key, EncryptedData encryptedMnemonicSeed,
                               EncryptedData encryptedHDSeed, boolean isFromXRandom, boolean
                                       isSyncedComplete, HDAccount.HDAccountGenerationDelegate
                                       generationDelegate) {
        this.isFromXRandom = isFromXRandom;
        double progress = 0;
        if (generationDelegate != null) {
            generationDelegate.onHDAccountGenerationProgress(progress);
        }
        String address = null;
        if (encryptedMnemonicSeed != null && mnemonicSeed != null) {
            ECKey k = new ECKey(mnemonicSeed, null);
            address = k.toAddress();
            k.clearPrivateKey();
        }

        DeterministicKey internalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
        DeterministicKey externalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        DeterministicKey internalBIP49Key = null;
        DeterministicKey externalBIP49Key = null;
        if (accountPurpose49Key != null) {
            internalBIP49Key = getChainRootKey(accountPurpose49Key,
                    AbstractHD.PathType.INTERNAL_ROOT_PATH);
            externalBIP49Key = getChainRootKey(accountPurpose49Key,
                    AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        }

        if (checkDuplicated(externalKey.getPubKeyExtended(), internalKey.getPubKeyExtended())) {
            throw new DuplicatedHDAccountException();
        }
        DeterministicKey key = externalKey.deriveSoftened(0);
        String firstAddress = key.toAddress();
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
        List<HDAccount.HDAccountAddress> externalBIP49Addresses = new ArrayList<HDAccountAddress>();
        List<HDAccount.HDAccountAddress> internalBIP49Addresses = new ArrayList<HDAccountAddress>();
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

            if (externalBIP49Key != null) {
                byte[] subExternalBIP49Pub = externalBIP49Key.deriveSoftened(i).getPubKey();
                HDAccount.HDAccountAddress externalBIP49Address = new HDAccount.HDAccountAddress
                        (subExternalBIP49Pub, AbstractHD.PathType.EXTERNAL_BIP49_PATH, i, isSyncedComplete,
                                hdSeedId);
                externalBIP49Addresses.add(externalBIP49Address);
                progress += itemProgress;
                if (generationDelegate != null) {
                    generationDelegate.onHDAccountGenerationProgress(progress);
                }
            }

            if (internalBIP49Key != null) {
                byte[] subInternalBIP49Pub = internalBIP49Key.deriveSoftened(i).getPubKey();
                HDAccount.HDAccountAddress internalBIP49Address = new HDAccount.HDAccountAddress
                        (subInternalBIP49Pub, AbstractHD.PathType.INTERNAL_BIP49_PATH, i, isSyncedComplete,
                                hdSeedId);
                internalBIP49Addresses.add(internalBIP49Address);
                progress += itemProgress;
                if (generationDelegate != null) {
                    generationDelegate.onHDAccountGenerationProgress(progress);
                }
            }
        }
        if (encryptedMnemonicSeed == null) {
            hdSeedId = AbstractDb.hdAccountProvider.addMonitoredHDAccount(firstAddress,
                    isFromXRandom, externalKey.getPubKeyExtended(), internalKey.getPubKeyExtended
                            ());
            hasSeed = false;
        } else {
            hdSeedId = AbstractDb.hdAccountProvider.addHDAccount(encryptedMnemonicSeed
                    .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                    isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                            .getPubKeyExtended());
            hasSeed = true;
        }
        if (externalBIP49Key != null && externalBIP49Key != null) {
            AbstractDb.hdAccountProvider.addHDAccountSegwitPub(hdSeedId, externalBIP49Key.getPubKeyExtended(), internalBIP49Key.getPubKeyExtended());
        }
        for (HDAccount.HDAccountAddress addr : externalAddresses) {
            addr.setHdAccountId(hdSeedId);
        }
        for (HDAccount.HDAccountAddress addr : internalAddresses) {
            addr.setHdAccountId(hdSeedId);
        }
        AbstractDb.hdAccountAddressProvider.addAddress(externalAddresses);
        AbstractDb.hdAccountAddressProvider.addAddress(internalAddresses);
        if (externalBIP49Addresses.size() > 0) {
            for (HDAccount.HDAccountAddress addr : externalBIP49Addresses) {
                addr.setHdAccountId(hdSeedId);
            }
            AbstractDb.hdAccountAddressProvider.addAddress(externalBIP49Addresses);
        }
        if (internalBIP49Addresses.size() > 0) {
            for (HDAccount.HDAccountAddress addr : internalBIP49Addresses) {
                addr.setHdAccountId(hdSeedId);
            }
            AbstractDb.hdAccountAddressProvider.addAddress(internalBIP49Addresses);
        }
        internalKey.wipe();
        externalKey.wipe();
        if (internalBIP49Key != null) {
            internalBIP49Key.wipe();
        }
        if (externalBIP49Key != null) {
            externalBIP49Key.wipe();
        }
    }

    public HDAccount(int seedId) {
        this.hdSeedId = seedId;
        this.isFromXRandom = AbstractDb.hdAccountProvider.hdAccountIsXRandom(seedId);
        hasSeed = AbstractDb.hdAccountProvider.hasMnemonicSeed(this.hdSeedId);
        updateBalance();
    }

    public String getFullEncryptPrivKey() {
        if (!hasPrivKey()) {
            return null;
        }
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public String getQRCodeFullEncryptPrivKey() {
        if (!hasPrivKey()) {
            return null;
        }
        return MnemonicCode.instance().getMnemonicWordList().getHdQrCodeFlag() + getFullEncryptPrivKey();
    }

    public byte[] getInternalPub(AbstractHD.PathType pathType) {
        IHDAccountProvider provider = AbstractDb.hdAccountProvider;
        if (pathType == AbstractHD.PathType.INTERNAL_BIP49_PATH) {
            return provider.getSegwitInternalPub(hdSeedId);
        } else {
            return provider.getInternalPub(hdSeedId);
        }
    }

    public byte[] getExternalPub(AbstractHD.PathType pathType) {
        IHDAccountProvider provider = AbstractDb.hdAccountProvider;
        if (pathType == AbstractHD.PathType.EXTERNAL_BIP49_PATH) {
            return provider.getSegwitExternalPub(hdSeedId);
        } else {
            return provider.getExternalPub(hdSeedId);
        }
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.hdAccountProvider.getHDFirstAddress(hdSeedId);
    }

    public void supplyEnoughKeys(boolean isSyncedComplete) {
        AbstractHD.PathType externalPath = AbstractHD.PathType.EXTERNAL_ROOT_PATH;
        int lackOfExternal = issuedExternalIndex(externalPath) + 1 + LOOK_AHEAD_SIZE -
                allGeneratedExternalAddressCount(externalPath);
        if (lackOfExternal > 0) {
            supplyNewExternalKey(lackOfExternal, isSyncedComplete, externalPath);
        }

        AbstractHD.PathType externalSegwitPath = AbstractHD.PathType.EXTERNAL_BIP49_PATH;
        int lackOfSegwitExternal = issuedExternalIndex(externalSegwitPath) + 1 + LOOK_AHEAD_SIZE -
                allGeneratedExternalAddressCount(externalSegwitPath);
        if (lackOfSegwitExternal > 0) {
            supplyNewExternalKey(lackOfSegwitExternal, isSyncedComplete, externalSegwitPath);
        }

        AbstractHD.PathType internalPath = AbstractHD.PathType.INTERNAL_ROOT_PATH;
        int lackOfInternal = issuedInternalIndex(internalPath) + 1 + LOOK_AHEAD_SIZE -
                allGeneratedInternalAddressCount(internalPath);
        if (lackOfInternal > 0) {
            supplyNewInternalKey(lackOfInternal, isSyncedComplete, internalPath);
        }

        AbstractHD.PathType internalSegwitPath = AbstractHD.PathType.INTERNAL_BIP49_PATH;
        int lackOfSegwitInternal = issuedInternalIndex(internalSegwitPath) + 1 + LOOK_AHEAD_SIZE -
                allGeneratedInternalAddressCount(internalSegwitPath);
        if (lackOfSegwitInternal > 0) {
            supplyNewInternalKey(lackOfSegwitInternal, isSyncedComplete, internalSegwitPath);
        }
    }

    public void addSegwitPub(CharSequence password) {
        if (AbstractDb.hdAccountProvider.getHDAccountEncryptSeed(hdSeedId) == null) {
            return;
        }
        if (AbstractDb.hdAccountProvider.getSegwitExternalPub(hdSeedId) != null && AbstractDb.hdAccountProvider.getSegwitInternalPub(hdSeedId) != null) {
            return;
        }
        try {
            DeterministicKey master = masterKey(password);
            if (master == null) {
                return ;
            }
            DeterministicKey accountPurpose49Key = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
            DeterministicKey externalBIP49Key = getChainRootKey(accountPurpose49Key, AbstractHD.PathType
                    .EXTERNAL_ROOT_PATH);
            DeterministicKey internalBIP49Key = getChainRootKey(accountPurpose49Key, AbstractHD.PathType
                    .INTERNAL_ROOT_PATH);
            AbstractDb.hdAccountProvider.addHDAccountSegwitPub(hdSeedId, externalBIP49Key.getPubKeyExtended(), internalBIP49Key.getPubKeyExtended());
            List<HDAccount.HDAccountAddress> externalBIP49Addresses = new ArrayList<HDAccountAddress>();
            List<HDAccount.HDAccountAddress> internalBIP49Addresses = new ArrayList<HDAccountAddress>();
            for (int i = 0;
                 i < LOOK_AHEAD_SIZE;
                 i++) {
                byte[] subExternalBIP49Pub = externalBIP49Key.deriveSoftened(i).getPubKey();
                HDAccount.HDAccountAddress externalBIP49Address = new HDAccount.HDAccountAddress
                        (subExternalBIP49Pub, AbstractHD.PathType.EXTERNAL_BIP49_PATH, i, isSyncComplete(),
                                hdSeedId);
                externalBIP49Addresses.add(externalBIP49Address);


                byte[] subInternalBIP49Pub = internalBIP49Key.deriveSoftened(i).getPubKey();
                HDAccount.HDAccountAddress internalBIP49Address = new HDAccount.HDAccountAddress
                        (subInternalBIP49Pub, AbstractHD.PathType.INTERNAL_BIP49_PATH, i, isSyncComplete(),
                                hdSeedId);
                internalBIP49Addresses.add(internalBIP49Address);
            }
            for (HDAccount.HDAccountAddress addr : externalBIP49Addresses) {
                addr.setHdAccountId(hdSeedId);
            }
            for (HDAccount.HDAccountAddress addr : internalBIP49Addresses) {
                addr.setHdAccountId(hdSeedId);
            }
            AbstractDb.hdAccountAddressProvider.addAddress(externalBIP49Addresses);
            AbstractDb.hdAccountAddressProvider.addAddress(internalBIP49Addresses);
            externalBIP49Key.wipe();
            internalBIP49Key.wipe();
            accountPurpose49Key.clearPrivateKey();
        } catch (MnemonicException e) {
            e.printStackTrace();
        }
    }

    private void supplyNewInternalKey(int count, boolean isSyncedComplete, AbstractHD.PathType pathType) {
        byte[] internalPub = getInternalPub(pathType);
        if (internalPub == null) {
            return;
        }
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes(internalPub);
        int firstIndex = allGeneratedInternalAddressCount(pathType);
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), pathType, i,
                    isSyncedComplete, hdSeedId));
        }
        AbstractDb.hdAccountAddressProvider.addAddress(as);
        log.info("HD supplied {} internal addresses", as.size());
    }

    private void supplyNewExternalKey(int count, boolean isSyncedComplete, AbstractHD.PathType pathType) {
        byte[] externalPub = getExternalPub(pathType);
        if (externalPub == null) {
            return;
        }
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes(externalPub);
        int firstIndex = allGeneratedExternalAddressCount(pathType);
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), pathType, i, isSyncedComplete, hdSeedId));
        }
        AbstractDb.hdAccountAddressProvider.addAddress(as);
        log.info("HD supplied {} external addresses", as.size());
    }

    protected String getEncryptedMnemonicSeed() {
        if (!hasPrivKey()) {
            return null;
        }
        return AbstractDb.hdAccountProvider.getHDAccountEncryptMnemonicSeed(hdSeedId);
    }

    protected String getEncryptedHDSeed() {
        if (!hasPrivKey()) {
            return null;
        }
        return AbstractDb.hdAccountProvider.getHDAccountEncryptSeed(hdSeedId);
    }

    public String getAddress(boolean... isSegwits) {
        boolean isSegwit = isSegwits == null || isSegwits.length == 0 ? false : isSegwits[0];
        AbstractHD.PathType pathType = isSegwit ? AbstractHD.PathType.EXTERNAL_BIP49_PATH : AbstractHD.PathType.EXTERNAL_ROOT_PATH;
        String address = AbstractDb.hdAccountAddressProvider.externalAddress(this.hdSeedId, pathType);
        if (address == null && isSegwit) {
            address = AbstractDb.hdAccountAddressProvider.externalAddress(this.hdSeedId, AbstractHD.PathType.EXTERNAL_ROOT_PATH);
        }
        return address;
    }

    public String getShortAddress(boolean isSegwit) {
        return Utils.shortenAddress(getAddress(isSegwit));
    }

    public int issuedInternalIndex(AbstractHD.PathType pathType) {
        return AbstractDb.hdAccountAddressProvider.issuedIndex(this.hdSeedId, pathType);
    }

    public int issuedExternalIndex(AbstractHD.PathType pathType) {
        return AbstractDb.hdAccountAddressProvider.issuedIndex(this.hdSeedId, pathType);
    }

    private int allGeneratedInternalAddressCount(AbstractHD.PathType pathType) {
        return AbstractDb.hdAccountAddressProvider.allGeneratedAddressCount(this.hdSeedId,
                pathType);
    }

    private int allGeneratedExternalAddressCount(AbstractHD.PathType pathType) {
        return AbstractDb.hdAccountAddressProvider.allGeneratedAddressCount(this.hdSeedId,
                pathType);
    }

    public HDAccountAddress addressForPath(AbstractHD.PathType type, int index) {

        assert index < ((type == AbstractHD.PathType.EXTERNAL_ROOT_PATH ||
                type == AbstractHD.PathType.EXTERNAL_BIP49_PATH ) ?
                allGeneratedExternalAddressCount(type)
                : allGeneratedInternalAddressCount(type));
        return AbstractDb.hdAccountAddressProvider.addressForPath(this.hdSeedId, type, index);
    }

    public boolean requestNewReceivingAddress(AbstractHD.PathType... pathTypes) {
        boolean result = AbstractDb.hdAccountAddressProvider.requestNewReceivingAddress(this.hdSeedId, pathTypes);
        if (result) {
            supplyEnoughKeys(true);
        }
        return result;
    }

    public void onNewTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        supplyEnoughKeys(true);
        long deltaBalance = getDeltaBalance();
        AbstractApp.notificationService.notificatTx(hasPrivKey() ? HDAccountPlaceHolder :
                        HDAccountMonitoredPlaceHolder, tx, txNotificationType,
                deltaBalance);
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
        AbstractApp.notificationService.notificatTx(hasPrivKey() ? HDAccountPlaceHolder :
                HDAccountMonitoredPlaceHolder, tx, txNotificationType, deltaBalance);
    }

    private long getDeltaBalance() {
        long oldBalance = this.balance;
        this.updateBalance();
        return this.balance - oldBalance;
    }

    public List<Tx> getTxs(int page) {
        return AbstractDb.hdAccountAddressProvider.getTxAndDetailByHDAccount(this.hdSeedId, page);
    }

    @Override
    public List<Tx> getTxs() {
        return AbstractDb.hdAccountAddressProvider.getTxAndDetailByHDAccount(this.hdSeedId);
    }

    public int txCount() {
        return AbstractDb.hdAccountAddressProvider.hdAccountTxCount(this.hdSeedId);
    }

    public void updateBalance() {
        this.balance = AbstractDb.hdAccountAddressProvider.getHDAccountConfirmedBalance(hdSeedId)
                + calculateUnconfirmedBalance();
    }

    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.hdAccountAddressProvider.getHDAccountUnconfirmedTx(this.hdSeedId);
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

            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED
                    && (Utils.isIntersects(spent, spentOut) || Utils.isIntersects(inHashes,
                    invalidTx))) {
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

    public List<HDAccountAddress> getRelatedAddressesForTx(Tx tx, List<String> inAddresses) {
        List<String> outAddressList = new ArrayList<String>();
        List<HDAccountAddress> hdAccountAddressList = new ArrayList<HDAccountAddress>();
        for (Out out : tx.getOuts()) {
            String outAddress = out.getOutAddress();
            outAddressList.add(outAddress);
        }
        List<HDAccountAddress> belongAccountOfOutList = AbstractDb.hdAccountAddressProvider
                .belongAccount(this.hdSeedId, outAddressList);
        if (belongAccountOfOutList != null
                && belongAccountOfOutList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfOutList);
        }

        List<HDAccountAddress> belongAccountOfInList = getAddressFromIn(inAddresses);
        if (belongAccountOfInList != null && belongAccountOfInList.size() > 0) {
            hdAccountAddressList.addAll(belongAccountOfInList);
        }

        return hdAccountAddressList;
    }

    public HashSet<String> getBelongAccountAddresses(List<String> addressList) {
        return AbstractDb.hdAccountAddressProvider.getBelongAccountAddresses(this.hdSeedId, addressList);
    }

    public Tx newTx(String toAddress, Long amount, boolean isSegwitChangeAddress, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        return newTx(new String[]{toAddress}, new Long[]{amount}, isSegwitChangeAddress, password);
    }

    public Tx newTx(String[] toAddresses, Long[] amounts, boolean isSegwitChangeAddress, CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        if (password != null && !hasPrivKey()) {
            throw new RuntimeException("Can not sign without private key");
        }
        Tx tx = newTx(toAddresses, amounts, isSegwitChangeAddress);

        List<HDAccountAddress> signingAddresses = getSigningAddressesForInputs(tx.getIns());
        assert signingAddresses.size() == tx.getIns().size();

        DeterministicKey master = masterKey(password);
        if (master == null) {
            return null;
        }
        DeterministicKey accountKey = getAccount(master, AbstractHD.PurposePathLevel.Normal);
        DeterministicKey segwitAccountKey = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
        DeterministicKey external = getChainRootKey(accountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(accountKey, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
        DeterministicKey segwitExternal = getChainRootKey(segwitAccountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        DeterministicKey segwitInternal = getChainRootKey(segwitAccountKey, AbstractHD.PathType
                .INTERNAL_ROOT_PATH);
        accountKey.wipe();
        segwitAccountKey.wipe();
        master.wipe();
        ArrayList<byte[]> signatures = new ArrayList<byte[]>();
        HashMap<String, DeterministicKey> addressToKeyMap = new HashMap<String, DeterministicKey>
                (signingAddresses.size());
        List<byte[]> witnesses = new ArrayList<byte[]>();

        for (int i = 0; i < signingAddresses.size(); i++) {
            HDAccountAddress a = signingAddresses.get(i);

            if (!addressToKeyMap.containsKey(a.getAddress())) {
                if (a.getPathType() == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                    addressToKeyMap.put(a.getAddress(), external.deriveSoftened(a.index));
                } else if (a.getPathType() == AbstractHD.PathType.INTERNAL_ROOT_PATH) {
                    addressToKeyMap.put(a.getAddress(), internal.deriveSoftened(a.index));
                } else if (a.getPathType() == AbstractHD.PathType.EXTERNAL_BIP49_PATH) {
                    addressToKeyMap.put(a.getAddress(), segwitExternal.deriveSoftened(a.index));
                    if (!tx.isSegwitAddress()) {
                        tx.setIsSegwitAddress(true);
                    }
                } else {
                    addressToKeyMap.put(a.getAddress(), segwitInternal.deriveSoftened(a.index));
                    if (!tx.isSegwitAddress()) {
                        tx.setIsSegwitAddress(true);
                    }
                }
            }

            DeterministicKey key = addressToKeyMap.get(a.getAddress());
            assert key != null;
            In in = tx.getIns().get(i);
            if (a.getPathType().isSegwit()) {
                signatures.add(getRedeemScript(key.getPubKey()));
                byte[] unsignedHash = tx.getSegwitUnsignedInHashes(key.getRedeemScript(), in);
                witnesses.add(getWitness(key.getPubKey(), getSign(key, unsignedHash)));
            } else {
                byte[] unsignedHash = tx.getUnsignedInHashes(in);
                TransactionSignature signature = new TransactionSignature(key.sign(unsignedHash, null), TransactionSignature.SigHash.ALL, false);
                signatures.add(ScriptBuilder.createInputScript(signature, key).getProgram());
                byte[] witness = {0x00};
                witnesses.add(witness);
            }
        }
        tx.setWitnesses(witnesses);
        tx.signWithSignatures(signatures);
        assert tx.verifySignatures();
        tx.setIsSigned(true);

        external.wipe();
        internal.wipe();
        for (DeterministicKey key : addressToKeyMap.values()) {
            key.wipe();
        }

        return tx;
    }

    public List<Tx> newForkTx(String toAddresses, Long amounts, CharSequence password, SplitCoin splitCoin, String...blockHash) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        if (password != null && !hasPrivKey()) {
            throw new RuntimeException("Can not sign without private key");
        }
        List<Tx> txs = newForkTx(toAddresses, amounts, splitCoin);
        for (Tx tx: txs) {
            if(blockHash != null && blockHash.length > 0) {
                tx.setBlockHash(Utils.hexStringToByteArray(blockHash[0]));
            }
            List<HDAccountAddress> signingAddresses = getSigningAddressesForInputs(tx.getIns());
            assert signingAddresses.size() == tx.getIns().size();
            DeterministicKey master = masterKey(password);
            if (master == null) {
                return null;
            }
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey external = getChainRootKey(accountKey, AbstractHD.PathType
                    .EXTERNAL_ROOT_PATH);
            DeterministicKey internal = getChainRootKey(accountKey, AbstractHD.PathType
                    .INTERNAL_ROOT_PATH);
            accountKey.wipe();
            master.wipe();
            List<byte[]> unsignedHashes = tx.getSplitCoinForkUnsignedInHashes(splitCoin);
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
                    if (a.getPathType() == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                        addressToKeyMap.put(a.getAddress(), external.deriveSoftened(a.index));
                    } else {
                        addressToKeyMap.put(a.getAddress(), internal.deriveSoftened(a.index));
                    }
                }
                DeterministicKey key = addressToKeyMap.get(a.getAddress());
                assert key != null;
                TransactionSignature signature = new TransactionSignature(key.sign(unsigned, null),
                        splitCoin.getSigHash(), false);
                signatures.add(ScriptBuilder.createInputScript(signature, key).getProgram());
            }

            tx.signWithSignatures(signatures);
            assert tx.verifySignatures();
            external.wipe();
            internal.wipe();
            for (DeterministicKey key : addressToKeyMap.values()) {
                key.wipe();
            }
        }
        return txs;
    }

    public List<Tx> extractBcc(String toAddresses, Long amounts, List<Out> outs, AbstractHD.PathType path, int index,CharSequence password) throws
            TxBuilderException, MnemonicException.MnemonicLengthException {
        if (password != null && !hasPrivKey()) {
            throw new RuntimeException("Can not sign without private key");
        }
        List<Tx> txs = newForkTx(toAddresses, amounts, outs, SplitCoin.BCC);
        for (Tx tx: txs) {
            DeterministicKey master = masterKey(password);
            if (master == null) {
                return null;
            }
            long [] preOutValue = new long[outs.size()];
            for (int idx = 0; idx < outs.size();idx++) {
                preOutValue[idx] = outs.get(idx).getOutValue();
            }
            List<byte[]> unsignedHashes = tx.getUnsignedHashesForBcc(preOutValue);
            assert unsignedHashes.size() == tx.getIns().size();
            ArrayList<byte[]> signatures = new ArrayList<byte[]>();

            for (int i = 0;
                 i < tx.getIns().size();
                 i++) {
                byte[] unsigned = unsignedHashes.get(i);
                DeterministicKey xPrivate  = getAccount(master);
                DeterministicKey pathPrivate = xPrivate.deriveSoftened(path.getValue());
                DeterministicKey key = pathPrivate.deriveSoftened(index);
                pathPrivate.wipe();
                assert key != null;
                TransactionSignature signature = new TransactionSignature(key.sign(unsigned, null),
                        TransactionSignature.SigHash.BCCFORK, false);
                signatures.add(ScriptBuilder.createInputScript(signature, key).getProgram());
                master.wipe();
                key.wipe();
            }
            tx.signWithSignatures(signatures);
            assert tx.verifySignatures();
        }
        return txs;
    }

    public List<Tx> newForkTx(String toAddress, Long amount, List<Out> outs, SplitCoin splitCoin) throws TxBuilderException,
            MnemonicException.MnemonicLengthException {
        List<Tx> txs = TxBuilder.getInstance().buildSplitCoinTxsFromAllAddress(outs, toAddress, Arrays.asList(amount), Arrays.asList(toAddress), splitCoin);
        return txs;
    }

    public List<Tx> newForkTx(String toAddress, Long amount, SplitCoin splitCoin) throws TxBuilderException,
            MnemonicException.MnemonicLengthException {
        List<Out> outs = AbstractDb.hdAccountAddressProvider.getUnspentOutputByBlockNo(splitCoin.getForkBlockHeight(), hdSeedId);
        List<Tx> txs = TxBuilder.getInstance().buildSplitCoinTxsFromAllAddress(outs, toAddress, Arrays.asList(amount), Arrays.asList(toAddress), splitCoin);
        return txs;
    }

    public Tx newTx(String toAddress, Long amount, boolean isSegwitChangeAddress) throws TxBuilderException, MnemonicException
            .MnemonicLengthException {
        return newTx(new String[]{toAddress}, new Long[]{amount}, isSegwitChangeAddress);
    }


    public Tx newTx(String[] toAddresses, Long[] amounts, boolean isSegwitChangeAddress) throws TxBuilderException,
            MnemonicException.MnemonicLengthException {
        List<Out> outs = AbstractDb.hdAccountAddressProvider.getUnspendOutByHDAccount(hdSeedId);
        Tx tx = TxBuilder.getInstance().buildTxFromAllAddress(outs, getNewChangeAddress(isSegwitChangeAddress), Arrays
                .asList(amounts), Arrays.asList(toAddresses));
        return tx;
    }

    public List<HDAccountAddress> getSigningAddressesForInputs(List<In> inputs) {
        return AbstractDb.hdAccountAddressProvider.getSigningAddressesForInputs(this.hdSeedId, inputs);
    }

    public boolean isSendFromMe(List<String> addresses) {
        List<HDAccountAddress> hdAccountAddressList = getAddressFromIn(addresses);
        return hdAccountAddressList.size() > 0;
    }

    private List<HDAccountAddress> getAddressFromIn(List<String> addresses) {
        List<HDAccountAddress> hdAccountAddressList = AbstractDb.hdAccountAddressProvider
                .belongAccount(this.hdSeedId, addresses);
        return hdAccountAddressList;
    }

    public void updateIssuedInternalIndex(int index, AbstractHD.PathType pathType) {
        AbstractDb.hdAccountAddressProvider.updateIssuedIndex(this.hdSeedId, pathType,
                index);
    }

    public void updateIssuedExternalIndex(int index, AbstractHD.PathType pathType) {
        AbstractDb.hdAccountAddressProvider.updateIssuedIndex(this.hdSeedId, pathType,
                index);
    }

    private String getNewChangeAddress(boolean isSegwitChangeAddress) {
        AbstractHD.PathType pathType = isSegwitChangeAddress ? AbstractHD.PathType.INTERNAL_BIP49_PATH : AbstractHD.PathType.INTERNAL_ROOT_PATH;
        return addressForPath(pathType,
                issuedInternalIndex(pathType) + 1)
                .getAddress();
    }

    public void updateSyncComplete(HDAccountAddress accountAddress) {
        AbstractDb.hdAccountAddressProvider.updateSyncdComplete(this.hdSeedId, accountAddress);
    }

    public int elementCountForBloomFilter() {
        return allGeneratedExternalAddressCount(AbstractHD.PathType.EXTERNAL_ROOT_PATH) * 2 +
                allGeneratedExternalAddressCount(AbstractHD.PathType.EXTERNAL_BIP49_PATH) * 2 +
                AbstractDb.hdAccountAddressProvider.getUnspendOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType.INTERNAL_ROOT_PATH) +
                AbstractDb.hdAccountAddressProvider .getUnconfirmedSpentOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType.INTERNAL_ROOT_PATH) +
                AbstractDb.hdAccountAddressProvider.getUnspendOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType.INTERNAL_BIP49_PATH) +
                AbstractDb.hdAccountAddressProvider .getUnconfirmedSpentOutCountByHDAccountWithPath(getHdSeedId(), AbstractHD.PathType.INTERNAL_BIP49_PATH);
    }

    public void addElementsForBloomFilter(BloomFilter filter) {
        List<byte[]> pubs = AbstractDb.hdAccountAddressProvider.getPubs(this.hdSeedId, AbstractHD
                .PathType.EXTERNAL_ROOT_PATH);
        for (byte[] pub : pubs) {
            filter.insert(pub);
            filter.insert(Utils.sha256hash160(pub));
        }
        pubs = AbstractDb.hdAccountAddressProvider.getPubs(this.hdSeedId, AbstractHD
                .PathType.EXTERNAL_BIP49_PATH);
        for (byte[] pub : pubs) {
            filter.insert(pub);
            filter.insert(Utils.sha256hash160(pub));
        }
        List<Out> outs = AbstractDb.hdAccountAddressProvider.getUnspendOutByHDAccountWithPath
                (getHdSeedId(), AbstractHD.PathType.INTERNAL_ROOT_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
        outs = AbstractDb.hdAccountAddressProvider.getUnconfirmedSpentOutByHDAccountWithPath
                (getHdSeedId(), AbstractHD.PathType.INTERNAL_ROOT_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
        outs = AbstractDb.hdAccountAddressProvider.getUnspendOutByHDAccountWithPath
                (getHdSeedId(), AbstractHD.PathType.INTERNAL_BIP49_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
        outs = AbstractDb.hdAccountAddressProvider.getUnconfirmedSpentOutByHDAccountWithPath
                (getHdSeedId(), AbstractHD.PathType.INTERNAL_BIP49_PATH);
        for (Out out : outs) {
            filter.insert(out.getOutpointData());
        }
    }

    public long getBalance() {
        return balance;
    }

    public boolean isSyncComplete() {
        int unsyncedAddressCount = AbstractDb.hdAccountAddressProvider.unSyncedAddressCount(this.hdSeedId);
        return unsyncedAddressCount == 0;
    }

    public List<Tx> getRecentlyTxsWithConfirmationCntLessThan(int confirmationCnt, int limit) {
        List<Tx> txList = new ArrayList<Tx>();
        int blockNo = BlockChain.getInstance().getLastBlock().getBlockNo() - confirmationCnt + 1;
        for (Tx tx : AbstractDb.hdAccountAddressProvider.getRecentlyTxsByAccount(this.hdSeedId, blockNo, limit)) {
            txList.add(tx);
        }
        return txList;
    }

    public Tx buildTx(String changeAddress, List<Long> amounts, List<String> addresses) {
        throw new RuntimeException("use newTx() for hdAccountHot");
    }

    public boolean hasPrivKey() {
        return hasSeed;
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

    protected DeterministicKey getAccount(DeterministicKey master, AbstractHD.PurposePathLevel... purposePathLevels) {
        DeterministicKey purpose = master.deriveHardened(getPurposePathLevel(purposePathLevels).getValue());
        DeterministicKey coinType = purpose.deriveHardened(0);
        DeterministicKey account = coinType.deriveHardened(0);
        purpose.wipe();
        coinType.wipe();
        return account;
    }

    protected DeterministicKey masterKey(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        long begin = System.currentTimeMillis();
        decryptHDSeed(password);
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        wipeHDSeed();
        log.info("hdm keychain decrypt time: {}", System.currentTimeMillis() - begin);
        return master;
    }

    protected void decryptHDSeed(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        if (hdSeedId < 0 || password == null) {
            return;
        }
        String encryptedHDSeed = getEncryptedHDSeed();
        if (!Utils.isEmpty(encryptedHDSeed)) {
            hdSeed = new EncryptedData(encryptedHDSeed).decrypt(password);
        }
    }

    public void decryptMnemonicSeed(CharSequence password) throws KeyCrypterException {
        if (hdSeedId < 0) {
            return;
        }
        String encrypted = getEncryptedMnemonicSeed();
        if (!Utils.isEmpty(encrypted)) {
            mnemonicSeed = new EncryptedData(encrypted).decrypt(password);
        }
    }

    public List<String> getSeedWords(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        decryptMnemonicSeed(password);
        List<String> words = mnemonicCode.toMnemonic(mnemonicSeed);
        wipeMnemonicSeed();
        return words;
    }

    public boolean checkWithPassword(CharSequence password) {
        if (!hasPrivKey()) {
            return true;
        }
        try {
            decryptHDSeed(password);
            decryptMnemonicSeed(password);
            byte[] hdCopy = Arrays.copyOf(hdSeed, hdSeed.length);
            boolean hdSeedSafe = Utils.compareString(getFirstAddressFromDb(),
                    getFirstAddressFromSeed(null, AbstractHD.PurposePathLevel.Normal));
            boolean mnemonicSeedSafe = Arrays.equals(seedFromMnemonic(mnemonicCode, mnemonicSeed), hdCopy);
            Utils.wipeBytes(hdCopy);
            wipeHDSeed();
            wipeMnemonicSeed();
            return hdSeedSafe && mnemonicSeedSafe;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    protected String getFirstAddressFromSeed(CharSequence password, AbstractHD.PurposePathLevel... purposePathLevels) {
        DeterministicKey key = getExternalKey(0, password, purposePathLevels);
        String address = Utils.toAddress(key.getPubKeyHash());
        key.wipe();
        return address;
    }

    public DeterministicKey getExternalKey(int index, CharSequence password, AbstractHD.PurposePathLevel... purposePathLevels) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master,purposePathLevels);
            DeterministicKey externalChainRoot = getChainRootKey(accountKey, AbstractHD.PathType
                    .EXTERNAL_ROOT_PATH);
            DeterministicKey key = externalChainRoot.deriveSoftened(index);
            master.wipe();
            accountKey.wipe();
            externalChainRoot.wipe();
            return key;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public DeterministicKey getInternalKey(int index, CharSequence password) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey externalChainRoot = getChainRootKey(accountKey, AbstractHD.PathType
                    .INTERNAL_ROOT_PATH);
            DeterministicKey key = externalChainRoot.deriveSoftened(index);
            master.wipe();
            accountKey.wipe();
            externalChainRoot.wipe();
            return key;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String xPubB58(CharSequence password, AbstractHD.PurposePathLevel... purposePathLevels) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey purpose = master.deriveHardened(getPurposePathLevel(purposePathLevels).getValue());
        DeterministicKey coinType = purpose.deriveHardened(0);
        DeterministicKey account = coinType.deriveHardened(0);
        String xpub = account.serializePubB58();
        master.wipe();
        purpose.wipe();
        coinType.wipe();
        account.wipe();
        return xpub;
    }

    protected void wipeHDSeed() {
        if (hdSeed == null) {
            return;
        }
        Utils.wipeBytes(hdSeed);
    }

    protected void wipeMnemonicSeed() {
        if (mnemonicSeed == null) {
            return;
        }
        Utils.wipeBytes(mnemonicSeed);
    }

    public int getHdSeedId() {
        return hdSeedId;
    }

    public static final byte[] seedFromMnemonic(MnemonicCode mnemonicCode, byte[] mnemonicSeed) throws MnemonicException
            .MnemonicLengthException {
        return mnemonicCode.toSeed(mnemonicCode.toMnemonic(mnemonicSeed), "");
    }

    public boolean isFromXRandom() {
        return isFromXRandom;
    }

    public void setIsSegwit(boolean isSegwit) {
        this.isSegwit = isSegwit;
    }

    public static class HDAccountAddress {
        private String address;
        private byte[] pub;
        private int index;
        private AbstractHD.PathType pathType;
        private boolean isSyncedComplete;
        private boolean isIssued;
        private long balance;


        private int hdAccountId;

        public HDAccountAddress(byte[] pub, AbstractHD.PathType pathType, int index, boolean
                isSyncedComplete, int hdAccountId) {

            this(((pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH || pathType == AbstractHD.PathType.INTERNAL_ROOT_PATH )
                            ? Utils.toAddress(Utils.sha256hash160(pub)) :
                    Utils.toSegwitAddress(Utils.sha256hash160(pub))),
                    pub, pathType, index, false, isSyncedComplete, hdAccountId);

        }

        public HDAccountAddress(String address, byte[] pub, AbstractHD.PathType pathType, int
                index, boolean isIssued, boolean isSyncedComplete, int hdAccountId) {
            this.pub = pub;
            this.address = address;
            this.pathType = pathType;
            this.index = index;
            this.isIssued = isIssued;
            this.isSyncedComplete = isSyncedComplete;
            this.hdAccountId = hdAccountId;
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

        public AbstractHD.PathType getPathType() {
            return pathType;
        }

        public boolean isIssued() {
            return isIssued;
        }

        public boolean isSyncedComplete() {
            return isSyncedComplete;
        }

        public void setIssued(boolean isIssued) {
            this.isIssued = isIssued;
        }

        public void setSyncedComplete(boolean isSynced) {
            this.isSyncedComplete = isSynced;
        }

        public int getHdAccountId() {
            return hdAccountId;
        }

        public void setHdAccountId(int hdAccountId) {
            this.hdAccountId = hdAccountId;
        }

        public long getBalance() {
            this.balance = AbstractDb.txProvider.getConfirmedBalanceWithAddress(getAddress())
                    + this.calculateUnconfirmedBalance();
            return balance;
        }

        private long calculateUnconfirmedBalance() {
            long balance = 0;

            List<Tx> txs = AbstractDb.txProvider.getUnconfirmedTxWithAddress(this.address);
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
                for (Out out : tx.getOuts()) {
                    if (Utils.compareString(this.getAddress(), out.getOutAddress())) {
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

    }

    public static final boolean checkDuplicated(byte[] ex, byte[] in) {
        return AbstractDb.hdAccountProvider.isPubExist(ex, in);
    }

    public static class DuplicatedHDAccountException extends RuntimeException {

    }

    public List<HDAccountAddress> getHdHotAddresses(int page, AbstractHD.PathType pathType,CharSequence password){
        ArrayList<HDAccountAddress> addresses = new ArrayList<HDAccountAddress>();
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master, AbstractHD.PurposePathLevel.Normal);
            DeterministicKey pathTypeKey = getChainRootKey(accountKey, pathType);
            for (int i = (page -1) * 10;i < page * 10; i ++) {
                DeterministicKey key = pathTypeKey.deriveSoftened(i);
                HDAccountAddress hdAccountAddress = new HDAccountAddress
                        (key.toAddress(),key.getPubKeyExtended(),pathType,i,false,true,hdSeedId);

                addresses.add(hdAccountAddress);
            }
            master.wipe();
            accountKey.wipe();
            pathTypeKey.wipe();
            return addresses;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
