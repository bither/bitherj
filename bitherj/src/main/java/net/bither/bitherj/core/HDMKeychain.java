package net.bither.bitherj.core;


import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import com.google.common.primitives.Chars;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.annotation.Nullable;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMKeychain {
    public static interface HDMFetchRemotePublicKeys{
        void completeRemotePublicKeys(CharSequence password, List<HDMAddress.Pubs> partialPubs);
    }

    public static interface HDMFetchRemoteAddresses {
        List<HDMAddress.Pubs> getRemoteExistsPublicKeys(CharSequence password);
    }

    public static interface HDMAddressChangeDelegate {
        public void hdmAddressAdded(HDMAddress address);
    }

    private static final Logger log = LoggerFactory.getLogger(HDMKeychain.class);

    private transient byte[] seed;

    private ArrayList<HDMAddress> allCompletedAddresses;
    private Collection<HDMAddress> addressesInUse;
    private Collection<HDMAddress> addressesTrashed;

    private int hdSeedId;
    private boolean isFromXRandom;

    private HDMAddressChangeDelegate addressChangeDelegate;

    // Create With Random
    public HDMKeychain(SecureRandom random, CharSequence password) {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        seed = new byte[32];
        random.nextBytes(seed);
        EncryptedData encryptedSeed = new EncryptedData(seed, password);
        String firstAddress = getFirstAddressFromSeed(password);
        wipeSeed();
        hdSeedId = AbstractDb.addressProvider.addHDKey(encryptedSeed.toEncryptedString(), firstAddress, isFromXRandom);
        allCompletedAddresses = new ArrayList<HDMAddress>();
    }

    // From DB
    public HDMKeychain(int seedId) {
        this.hdSeedId = seedId;
        allCompletedAddresses = new ArrayList<HDMAddress>();
        initFromDb();
    }

    // Import
    public HDMKeychain(EncryptedData encryptedSeed, boolean isFromXRandom ,CharSequence password, HDMFetchRemoteAddresses fetchDelegate) throws HDMBitherIdNotMatchException, MnemonicException.MnemonicLengthException {
        seed = encryptedSeed.decrypt(password);
        allCompletedAddresses = new ArrayList<HDMAddress>();
        List<HDMAddress.Pubs> pubs = fetchDelegate.getRemoteExistsPublicKeys(password);
        if(pubs.size() > 0){
            try {
                DeterministicKey root = externalChainRoot(password);
                byte[] pubDerived = root.deriveSoftened(0).getPubKey();
                byte[] pubFetched = pubs.get(0).hot;
                root.wipe();
                if(!Arrays.equals(pubDerived, pubFetched)){
                    wipeSeed();
                    throw new HDMBitherIdNotMatchException();
                }
            } catch (MnemonicException.MnemonicLengthException e) {
                wipeSeed();
                throw e;
            }
        }
        String firstAddress = getFirstAddressFromSeed(password);
        wipeSeed();
        ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
        for (HDMAddress.Pubs p : pubs) {
            as.add(new HDMAddress(p, this));
        }
        this.hdSeedId = AbstractDb.addressProvider.addHDKey(encryptedSeed.toEncryptedString(), firstAddress, isFromXRandom);
        AbstractDb.addressProvider.completeHDMAddresses(getHdSeedId(), as);
        allCompletedAddresses.addAll(as);
    }

    public int prepareAddresses(int count, CharSequence password, byte[] coldExternalRootPub){
        DeterministicKey externalRootHot;
        DeterministicKey externalRootCold = HDKeyDerivation.createMasterPubKeyFromExtendedBytes(coldExternalRootPub);

        try {
            externalRootHot = externalChainRoot(password);
            externalRootHot.clearPrivateKey();
        } catch (MnemonicException.MnemonicLengthException e) {
            return 0;
        }
        ArrayList<HDMAddress.Pubs> pubs = new ArrayList<HDMAddress.Pubs>();
        for (int i = AbstractDb.addressProvider.maxHDMAddressPubIndex(getHdSeedId()) + 1;
             pubs.size() < count;
             i++) {
            HDMAddress.Pubs p = new HDMAddress.Pubs();
            try {
                p.hot = externalRootHot.deriveSoftened(i).getPubKey();
                p.cold = externalRootCold.deriveSoftened(i).getPubKey();
                p.index = i;
                pubs.add(p);
            } catch (Exception e) {
                e.printStackTrace();
            }
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

    public List<HDMAddress> completeAddresses(int count, CharSequence password, HDMFetchRemotePublicKeys fetchDelegate) {
        int uncompletedAddressCount = uncompletedAddressCount();
        if(uncompletedAddressCount < count){
            throw new RuntimeException("Not enough uncompleted allCompletedAddresses " + count + "/" + uncompletedAddressCount + " : " + getHdSeedId());
        }
        ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
        synchronized (allCompletedAddresses) {
            List<HDMAddress.Pubs> pubs = AbstractDb.addressProvider.getUncompletedHDMAddressPubs(getHdSeedId(), count);
            try {
                fetchDelegate.completeRemotePublicKeys(password, pubs);
                for (HDMAddress.Pubs p : pubs) {
                    as.add(new HDMAddress(p, this));
                }
                AbstractDb.addressProvider.completeHDMAddresses(getHdSeedId(), as);
            } catch (Exception e) {
                e.printStackTrace();
                return as;
            }
            if(addressChangeDelegate != null){
                for(HDMAddress a : as){
                    addressChangeDelegate.hdmAddressAdded(a);
                }
            }
            allCompletedAddresses.addAll(as);
        }
        return as;
    }

    public List<HDMAddress> getAddresses() {
        synchronized (allCompletedAddresses) {
            if(addressesInUse == null){
                addressesInUse = Collections2.filter(allCompletedAddresses, new Predicate<HDMAddress>() {
                    @Override
                    public boolean apply(@Nullable HDMAddress input) {
                        return !input.isTrashed();
                    }
                });
            }
            return new ArrayList<HDMAddress>(addressesInUse);
        }
    }

    public List<HDMAddress> getTrashedAddresses(){
        synchronized (allCompletedAddresses){
            if(addressesTrashed == null){
                addressesTrashed = Collections2.filter(allCompletedAddresses, new Predicate<HDMAddress>() {
                    @Override
                    public boolean apply(@Nullable HDMAddress input) {
                        return input.isTrashed();
                    }
                });
            }
            return new ArrayList<HDMAddress>(addressesTrashed);
        }
    }

    public DeterministicKey externalChainRoot(CharSequence password) throws MnemonicException.MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey purpose = master.deriveHardened(44);
        DeterministicKey coinType = purpose.deriveHardened(0);
        DeterministicKey account = coinType.deriveHardened(0);
        DeterministicKey external = account.deriveSoftened(0);
        master.wipe();
        purpose.wipe();
        coinType.wipe();
        account.wipe();
        return external;
    }

    public byte[] getExternalChainRootPubExtended(CharSequence password) throws MnemonicException.MnemonicLengthException{
        DeterministicKey ex = externalChainRoot(password);
        byte[] pub = ex.getPubKeyExtended();
        ex.wipe();
        return pub;
    }

    public String getExternalChainRootPubExtendedAsHex(CharSequence password) throws MnemonicException.MnemonicLengthException{
        return Utils.bytesToHexString(getExternalChainRootPubExtended(password));
    }

    private DeterministicKey masterKey(CharSequence password) throws MnemonicException.MnemonicLengthException {
        long begin = System.currentTimeMillis();
        MnemonicCode mnemonic = MnemonicCode.instance();
        decryptSeed(password);
        byte[] s = mnemonic.toSeed(mnemonic.toMnemonic(seed), "");
        wipeSeed();
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(s);
        Utils.wipeBytes(s);
        log.info("hdm keychain decrypt time: {}", System.currentTimeMillis() - begin);
        return master;
    }

    public DeterministicKey getExternalKey(int index, CharSequence password){
        try {
            DeterministicKey externalChainRoot = externalChainRoot(password);
            DeterministicKey key = externalChainRoot.deriveSoftened(index);
            externalChainRoot.wipe();
            return key;
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public int getCurrentMaxAddressIndex(){
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

    private void initFromDb(){
        isFromXRandom = AbstractDb.addressProvider.isHDSeedFromXRandom(getHdSeedId());
        initAddressesFromDb();
    }

    private void initAddressesFromDb(){
        synchronized (allCompletedAddresses){
            List<HDMAddress> addrs = AbstractDb.addressProvider.getHDMAddressInUse(this);
            if(addrs != null) {
                allCompletedAddresses.addAll(addrs);
            }
        }
    }

    public int getHdSeedId(){
        return hdSeedId;
    }

    public int uncompletedAddressCount(){
        return AbstractDb.addressProvider.uncompletedHDMAddressCount(getHdSeedId());
    }

    public HDMAddressChangeDelegate getAddressChangeDelegate() {
        return addressChangeDelegate;
    }

    public void setAddressChangeDelegate(HDMAddressChangeDelegate addressChangeDelegate) {
        this.addressChangeDelegate = addressChangeDelegate;
    }

    public boolean isFromXRandom(){
        return isFromXRandom;
    }

    public void decryptSeed(CharSequence password) throws KeyCrypterException{
        if(hdSeedId <= 0){
            return;
        }
        String encrypted = getEncryptedSeed();
        if(!Utils.isEmpty(encrypted)){
            seed = new EncryptedData(encrypted).decrypt(password);
        }
    }

    public String getEncryptedSeed(){
        return AbstractDb.addressProvider.getEncryptSeed(hdSeedId);
    }

    public void changePassword(CharSequence oldPassword, CharSequence newPassword){
        decryptSeed(oldPassword);
        AbstractDb.addressProvider.setEncryptSeed(getHdSeedId(), new EncryptedData(seed, newPassword).toEncryptedString());
        wipeSeed();
    }

    public List<String> getSeedWords(CharSequence password) throws MnemonicException.MnemonicLengthException {
        decryptSeed(password);
        List<String> words = MnemonicCode.instance().toMnemonic(seed);
        wipeSeed();
        return words;
    }

    public void wipeSeed(){
        Utils.wipeBytes(seed);
    }

    private String getFirstAddressFromSeed(CharSequence password){
        DeterministicKey key = getExternalKey(0, password);
        return Utils.toAddress(key.getPubKeyHash());
    }

    private String getFirstAddressFromDb(){
        return AbstractDb.addressProvider.getHDMFristAddress(hdSeedId);
    }

    public boolean checkWithPassword(CharSequence password){
        try{
            return Utils.compareString(getFirstAddressFromDb(), getFirstAddressFromSeed(password));
        }catch (Exception e){
            return false;
        }
    }

    public PasswordSeed createPasswordSeed(CharSequence password){
        String encrypted = AbstractDb.addressProvider.getEncryptSeed(hdSeedId);
        byte[] priv = new EncryptedData(encrypted).decrypt(password);
        ECKey k = new ECKey(priv, null);
        String address = k.toAddress();
        Utils.wipeBytes(priv);
        k.clearPrivateKey();
        return new PasswordSeed(address, encrypted);
    }

    public static final class HDMBitherIdNotMatchException extends RuntimeException{
        public static final String msg = "HDM Bid Not Match";

        public HDMBitherIdNotMatchException(){
            super(msg);
        }
    }
}
