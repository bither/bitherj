package net.bither.bitherj.core;


import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.api.CreateHDMAddressApi;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.crypto.SecureCharSequence;
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.annotation.Nullable;

public class HDMKeychain extends AbstractHD {

    public static interface HDMFetchRemotePublicKeys {
        void completeRemotePublicKeys(CharSequence password, List<HDMAddress.Pubs> partialPubs)
                throws Exception;
    }

    public static interface HDMFetchRemoteAddresses {
        List<HDMAddress.Pubs> getRemoteExistsPublicKeys(CharSequence password);
    }

    public static interface HDMAddressChangeDelegate {
        public void hdmAddressAdded(HDMAddress address);
    }

    private static final Logger log = LoggerFactory.getLogger(HDMKeychain.class);


    protected ArrayList<HDMAddress> allCompletedAddresses;
    private Collection<HDMAddress> addressesInUse;
    private Collection<HDMAddress> addressesTrashed;


    private HDMAddressChangeDelegate addressChangeDelegate;

    public HDMKeychain(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
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
        hdSeedId = AbstractDb.addressProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address);
        allCompletedAddresses = new ArrayList<HDMAddress>();

    }

    // Create With Random
    public HDMKeychain(SecureRandom random, CharSequence password) {
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
        hdSeedId = AbstractDb.addressProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address);
        allCompletedAddresses = new ArrayList<HDMAddress>();
    }

    // From DB
    public HDMKeychain(int seedId) {
        this.hdSeedId = seedId;
        allCompletedAddresses = new ArrayList<HDMAddress>();
        initFromDb();
    }

    // Import
    public HDMKeychain(EncryptedData encryptedMnemonicSeed, CharSequence password,
                       HDMFetchRemoteAddresses fetchDelegate) throws
            HDMBitherIdNotMatchException, MnemonicException.MnemonicLengthException {
        mnemonicSeed = encryptedMnemonicSeed.decrypt(password);
        hdSeed = seedFromMnemonic(mnemonicSeed);
        isFromXRandom = encryptedMnemonicSeed.isXRandom();
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        allCompletedAddresses = new ArrayList<HDMAddress>();
        ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
        ArrayList<HDMAddress.Pubs> uncompPubs = new ArrayList<HDMAddress.Pubs>();
        if (fetchDelegate != null) {
            List<HDMAddress.Pubs> pubs = fetchDelegate.getRemoteExistsPublicKeys(password);
            if (pubs.size() > 0) {
                try {
                    DeterministicKey root = externalChainRoot(password);
                    byte[] pubDerived = root.deriveSoftened(0).getPubKey();
                    byte[] pubFetched = pubs.get(0).hot;
                    root.wipe();
                    if (!Arrays.equals(pubDerived, pubFetched)) {
                        wipeMnemonicSeed();
                        wipeHDSeed();
                        throw new HDMBitherIdNotMatchException();
                    }
                } catch (MnemonicException.MnemonicLengthException e) {
                    wipeMnemonicSeed();
                    wipeHDSeed();
                    throw e;
                }
            }
            for (HDMAddress.Pubs p : pubs) {
                if (p.isCompleted()) {
                    as.add(new HDMAddress(p, this, false));
                } else {
                    uncompPubs.add(p);
                }
            }
        }
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        String firstAddress = getFirstAddressFromSeed(password);
        wipeMnemonicSeed();
        wipeHDSeed();

        this.hdSeedId = AbstractDb.addressProvider.addHDKey(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address);
        if (as.size() > 0) {
            AbstractDb.addressProvider.completeHDMAddresses(getHdSeedId(), as);
            allCompletedAddresses.addAll(as);
            if (uncompPubs.size() > 0) {
                AbstractDb.addressProvider.prepareHDMAddresses(getHdSeedId(), uncompPubs);
                for (HDMAddress.Pubs p : uncompPubs) {
                    AbstractDb.addressProvider.setHDMPubsRemote(getHdSeedId(), p.index, p.remote);
                }
            }
        }
    }


    public int prepareAddresses(int count, CharSequence password, byte[] coldExternalRootPub) {
        DeterministicKey externalRootHot;
        DeterministicKey externalRootCold = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (coldExternalRootPub);

        try {
            externalRootHot = externalChainRoot(password);
            externalRootHot.clearPrivateKey();
        } catch (MnemonicException.MnemonicLengthException e) {
            return 0;
        }
        ArrayList<HDMAddress.Pubs> pubs = new ArrayList<HDMAddress.Pubs>();
        int startIndex = 0;
        int maxIndex = AbstractDb.addressProvider.maxHDMAddressPubIndex(getHdSeedId());
        if (maxIndex >= 0) {
            startIndex = maxIndex + 1;
        }

        if (startIndex > 0) {
            HDMBId id = HDMBId.getHDMBidFromDb();
            if (id != null) {
                String hdmIdAddress = id.getAddress();
                if (!Utils.compareString(hdmIdAddress, Utils.toAddress(externalRootCold
                        .deriveSoftened(0).getPubKeyHash()))) {
                    throw new HDMColdPubNotSameException();
                }
            }
        }

        for (int i = startIndex;
             pubs.size() < count;
             i++) {
            HDMAddress.Pubs p = new HDMAddress.Pubs();
            try {
                p.hot = externalRootHot.deriveSoftened(i).getPubKey();
            } catch (Exception e) {
                e.printStackTrace();
                p.hot = HDMAddress.Pubs.EmptyBytes;
            }
            try {
                p.cold = externalRootCold.deriveSoftened(i).getPubKey();
            } catch (Exception e) {
                e.printStackTrace();
                p.cold = HDMAddress.Pubs.EmptyBytes;
            }
            p.index = i;
            pubs.add(p);
        }
        AbstractDb.addressProvider.prepareHDMAddresses(getHdSeedId(), pubs);
        if (externalRootHot != null) {
            externalRootHot.wipe();
        }
        if (externalRootCold != null) {
            externalRootCold.wipe();
        }
        return pubs.size();
    }

    public List<HDMAddress> completeAddresses(int count, CharSequence password,
                                              HDMFetchRemotePublicKeys fetchDelegate) {
        int uncompletedAddressCount = uncompletedAddressCount();
        if (uncompletedAddressCount < count) {
            throw new RuntimeException("Not enough uncompleted allCompletedAddresses " + count +
                    "/" + uncompletedAddressCount + " : " + getHdSeedId());
        }
        ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
        synchronized (allCompletedAddresses) {
            List<HDMAddress.Pubs> pubs = AbstractDb.addressProvider.getUncompletedHDMAddressPubs
                    (getHdSeedId(), count);
            try {
                fetchDelegate.completeRemotePublicKeys(password, pubs);
                for (HDMAddress.Pubs p : pubs) {
                    if (p.isCompleted()) {
                        as.add(new HDMAddress(p, this, true));
                    } else {
                        AbstractDb.addressProvider.setHDMPubsRemote(getHdSeedId(), p.index,
                                p.remote);
                    }
                }
                AbstractDb.addressProvider.completeHDMAddresses(getHdSeedId(), as);
            } catch (Exception e) {
                e.printStackTrace();
                return as;
            }
            if (addressChangeDelegate != null) {
                for (HDMAddress a : as) {
                    addressChangeDelegate.hdmAddressAdded(a);
                }
            }
            allCompletedAddresses.addAll(as);
        }
        return as;
    }

    public List<HDMAddress> getAddresses() {
        synchronized (allCompletedAddresses) {
            if (addressesInUse == null) {
                addressesInUse = Collections2.filter(allCompletedAddresses,
                        new Predicate<HDMAddress>() {
                            @Override
                            public boolean apply(@Nullable HDMAddress input) {
                                return !input.isTrashed();
                            }
                        });
            }
            return new ArrayList<HDMAddress>(addressesInUse);
        }
    }

    public List<HDMAddress> getTrashedAddresses() {
        synchronized (allCompletedAddresses) {
            if (addressesTrashed == null) {
                addressesTrashed = Collections2.filter(allCompletedAddresses,
                        new Predicate<HDMAddress>() {
                            @Override
                            public boolean apply(@Nullable HDMAddress input) {
                                return input.isTrashed();
                            }
                        });
            }
            return new ArrayList<HDMAddress>(addressesTrashed);
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
            for (HDMAddress address : allCompletedAddresses) {
                if (address.getIndex() > max) {
                    max = address.getIndex();
                }
            }
            return max;
        }
    }

    public List<HDMAddress> getAllCompletedAddresses() {
        synchronized (allCompletedAddresses) {
            return allCompletedAddresses;
        }
    }

    private void initFromDb() {
        isFromXRandom = AbstractDb.addressProvider.isHDSeedFromXRandom(getHdSeedId());
        initAddressesFromDb();
    }

    private void initAddressesFromDb() {
        synchronized (allCompletedAddresses) {
            List<HDMAddress> addrs = AbstractDb.addressProvider.getHDMAddressInUse(this);
            if (addrs != null) {
                allCompletedAddresses.addAll(addrs);
            }
        }
    }


    public int uncompletedAddressCount() {
        return AbstractDb.addressProvider.uncompletedHDMAddressCount(getHdSeedId());
    }

    public HDMAddressChangeDelegate getAddressChangeDelegate() {
        return addressChangeDelegate;
    }

    public void setAddressChangeDelegate(HDMAddressChangeDelegate addressChangeDelegate) {
        this.addressChangeDelegate = addressChangeDelegate;
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
        if (isInRecovery()) {
            throw new AssertionError("recover mode hdm keychain do not have encrypted hd seed");
        }
        String encrypted = AbstractDb.addressProvider.getEncryptHDSeed(hdSeedId);
        if (encrypted == null) {
            return null;
        }
        return encrypted.toUpperCase();
    }

    @Override
    public String getEncryptedMnemonicSeed() {
        if (isInRecovery()) {
            throw new AssertionError("recover mode hdm keychain do not have encrypted mnemonic "
                    + "seed");
        }
        return AbstractDb.addressProvider.getEncryptMnemonicSeed(hdSeedId).toUpperCase();
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.addressProvider.getHDMFristAddress(hdSeedId);
    }

    public boolean checkWithPassword(CharSequence password) {
        if (isInRecovery()) {
            return true;
        }
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

    public boolean checkSingularBackupWithPassword(CharSequence password) {
        if (isInRecovery()) {
            return true;
        }
        if (getAllCompletedAddresses().size() == 0) {
            return true;
        }
        String backup = AbstractDb.addressProvider.getSingularModeBackup(getHdSeedId());
        if (backup == null) {
            return true;
        }
        EncryptedData encrypted = new EncryptedData(backup);
        byte[] mnemonic = encrypted.decrypt(password);
        boolean result;
        try {
            byte[] seed = seedFromMnemonic(mnemonic);
            byte[] pub = getAllCompletedAddresses().get(0).getPubCold();
            DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(seed);
            DeterministicKey purpose = master.deriveHardened(44);
            DeterministicKey coinType = purpose.deriveHardened(0);
            DeterministicKey account = coinType.deriveHardened(0);
            DeterministicKey external = account.deriveSoftened(0);
            DeterministicKey first = external.deriveSoftened(0);
            master.wipe();
            purpose.wipe();
            coinType.wipe();
            account.wipe();
            external.wipe();
            Utils.wipeBytes(seed);
            result = Arrays.equals(first.getPubKey(), pub);
            first.wipe();
        } catch (MnemonicException.MnemonicLengthException e) {
            e.printStackTrace();
            result = false;
        }
        Utils.wipeBytes(mnemonic);
        return result;
    }

    public PasswordSeed createPasswordSeed(CharSequence password) {
        if (isInRecovery()) {
            throw new AssertionError("HDM in recovery can not create passwordSeed");
        }
        String encrypted = AbstractDb.addressProvider.getEncryptMnemonicSeed(hdSeedId);
        byte[] priv = new EncryptedData(encrypted).decrypt(password);
        ECKey k = new ECKey(priv, null);
        String address = k.toAddress();
        Utils.wipeBytes(priv);
        k.clearPrivateKey();
        return new PasswordSeed(address, encrypted);
    }

    public String signHDMBId(String messageHash, SecureCharSequence password) {
        DeterministicKey key = getExternalKey(0, password);
        log.info("messageHash:" + messageHash);
        if (key == null) {
            log.info("key:null");
        }

        byte[] signData = key.signHash(Utils.hexStringToByteArray(messageHash), null);

        return Utils.bytesToHexString(signData).toUpperCase();
    }

    public boolean isInRecovery() {
        return Utils.compareString(AbstractDb.addressProvider.getEncryptMnemonicSeed(hdSeedId),
                HDMKeychainRecover.RecoverPlaceHolder) ||
                Utils.compareString(AbstractDb.addressProvider.getEncryptHDSeed(hdSeedId),
                        HDMKeychainRecover.RecoverPlaceHolder) ||
                Utils.compareString(getFirstAddressFromDb(), HDMKeychainRecover.RecoverPlaceHolder);
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

    public static boolean checkPassword(MnemonicCode mnemonicCode, String keysString, CharSequence password) throws
            MnemonicException.MnemonicLengthException {
        String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keysString);
        String address = Base58.hexToBase58WithAddress(passwordSeeds[0]);
        String encreyptString = Utils.joinString(new String[]{passwordSeeds[1], passwordSeeds[2],
                passwordSeeds[3]}, QRCodeUtil.QR_CODE_SPLIT);
        byte[] seed = new EncryptedData(encreyptString).decrypt(password);

        byte[] s = mnemonicCode.toSeed(mnemonicCode.toMnemonic(seed), "");

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

    public static class HDMKeychainRecover extends HDMKeychain {
        public static final String RecoverPlaceHolder = "RECOVER";

        public HDMKeychainRecover(byte[] coldExternalRootPub, CharSequence password,
                                  HDMFetchRemoteAddresses fetchDelegate) {
            super(AbstractDb.addressProvider.addHDKey(RecoverPlaceHolder, RecoverPlaceHolder,
                    RecoverPlaceHolder, false, null));
            DeterministicKey coldRoot = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                    (Arrays.copyOf(coldExternalRootPub, coldExternalRootPub.length));
            ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
            ArrayList<HDMAddress.Pubs> uncompPubs = new ArrayList<HDMAddress.Pubs>();
            if (fetchDelegate != null) {
                List<HDMAddress.Pubs> pubs = fetchDelegate.getRemoteExistsPublicKeys(password);
                if (pubs.size() > 0) {
                    byte[] pubFetched = pubs.get(0).cold;
                    byte[] pubDerived = coldRoot.deriveSoftened(pubs.get(0).index).getPubKey();
                    coldRoot.wipe();
                    if (!Arrays.equals(pubDerived, pubFetched)) {
                        throw new HDMBitherIdNotMatchException();
                    }
                }
                for (HDMAddress.Pubs p : pubs) {
                    if (p.isCompleted()) {
                        as.add(new HDMAddress(p, this, false));
                    } else {
                        uncompPubs.add(p);
                    }
                }
            }
            if (as.size() > 0) {
                AbstractDb.addressProvider.recoverHDMAddresses(getHdSeedId(), as);
                allCompletedAddresses.addAll(as);
                if (uncompPubs.size() > 0) {
                    AbstractDb.addressProvider.prepareHDMAddresses(getHdSeedId(), uncompPubs);
                    for (HDMAddress.Pubs p : uncompPubs) {
                        AbstractDb.addressProvider.setHDMPubsRemote(getHdSeedId(), p.index, p.remote);
                    }
                }
            }
        }

        @Override
        public boolean isInRecovery() {
            return true;
        }
    }

    public int getCanAddHDMCount() {
        return AbstractApp.bitherjSetting.hdmAddressPerSeedPrepareCount() -
                uncompletedAddressCount();
    }

    public void setSingularModeBackup(String singularModeBackup) {
        AbstractDb.addressProvider.setSingularModeBackup(this.hdSeedId, singularModeBackup);
    }
}
