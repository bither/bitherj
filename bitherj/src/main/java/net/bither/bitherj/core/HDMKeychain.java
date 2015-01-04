package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.crypto.EncryptedPrivateKey;
import net.bither.bitherj.crypto.KeyCrypterScrypt;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMKeychain {
    public static interface HDMFetchRemotePublicKeys{
        void completeRemotePublicKeys(String bitherId, CharSequence password, List<HDMAddress.Pubs> partialPubs);
    }

    public static interface HDMFetchRemoteAddresses {
        List<List<byte[]>> getRemoteExistsPublicKeys(String bitherId, CharSequence password);
    }

    private transient byte[] seed;

    private ArrayList<HDMAddress> addresses;
    private boolean isFromXRandom;

    private int hdSeedId;
    private String bitherId;
    private String encryptSeed;
    private String encryptBitherPassword;

    public HDMKeychain(SecureRandom random, CharSequence password, String bitherId, CharSequence bitherPasswordUnencrypted) {
        isFromXRandom = random.getClass().getCanonicalName().indexOf("XRandom") >= 0;
        seed = new byte[64];
        random.nextBytes(seed);
        KeyCrypterScrypt crypter = new KeyCrypterScrypt();
        EncryptedPrivateKey encryptedSeed = crypter.encrypt(seed, crypter.deriveKey(password));
        wipeSeed();
        addresses = new ArrayList<HDMAddress>();
    }

    public HDMKeychain(int seedId) {
        this.hdSeedId = seedId;
        addresses = new ArrayList<HDMAddress>();
        initFromDb();
    }

    public HDMKeychain(int seedId, String encryptSeed, String bitherId, String encryptBitherPassword) {
        this.hdSeedId = seedId;
        this.encryptSeed = encryptSeed;
        this.bitherId = bitherId;
        this.encryptBitherPassword = encryptBitherPassword;
    }

    public List<HDMAddress> createAddresses(int count, CharSequence password, HDMFetchRemotePublicKeys fetchDelegate, byte[] coldExternalRootPub) {
        ArrayList<HDMAddress> as = new ArrayList<HDMAddress>();
        DeterministicKey externalRootHot;
        DeterministicKey externalRootCold = HDKeyDerivation.createMasterPubKeyFromExtendedBytes(coldExternalRootPub);
        try {
            externalRootHot = externalChainRoot(password);
            externalRootHot.clearPrivateKey();
        } catch (MnemonicException.MnemonicLengthException e) {
            return as;
        }
        ArrayList<HDMAddress.Pubs> pubs = new ArrayList<HDMAddress.Pubs>();
        for(int i = getCurrentMaxAddressIndex() + 1; pubs.size() < count; i++){
            HDMAddress.Pubs p = new HDMAddress.Pubs();
            try {
                p.hot = externalRootHot.deriveSoftened(i).getPubKey();
                p.cold = externalRootCold.deriveSoftened(i).getPubKey();
                pubs.add(p);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        try {
            fetchDelegate.completeRemotePublicKeys(null, null, pubs);
        }catch (Exception e){
            e.printStackTrace();
            return addresses;
        }
        for(HDMAddress.Pubs p : pubs){
            as.add(new HDMAddress(p, false, isFromXRandom, this));
        }
        addresses.addAll(as);
        if(externalRootHot != null){
            externalRootHot.wipe();
        }
        if(externalRootCold != null){
            externalRootCold.wipe();
        }
        return as;
    }

    public List<HDMAddress> getAddresses() {
        synchronized (addresses) {
            return addresses;
        }
    }

    public HDMKeychain(String encryptSeed, String bitherId, String encryptBitherPassword, CharSequence password, HDMFetchRemoteAddresses fetchDelegate) {
//        this.hdKeyId = AbstractDb.addressProvider.addHDKey(encryptSeed, bitherId, encryptBitherPassword);
        this.encryptSeed = encryptSeed;
        this.bitherId = bitherId;
        this.encryptBitherPassword = encryptBitherPassword;
    }

    private DeterministicKey externalChainRoot(CharSequence password) throws MnemonicException.MnemonicLengthException {
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

    private DeterministicKey masterKey(CharSequence password) throws MnemonicException.MnemonicLengthException {
        MnemonicCode mnemonic = MnemonicCode.instance();
        decryptSeed(password);
        byte[] s = mnemonic.toSeed(mnemonic.toMnemonic(seed), "");
        wipeSeed();
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(s);
        Utils.wipeBytes(s);
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
        int max = Integer.MIN_VALUE;
        for(HDMAddress address : addresses){
            if(address.getIndex() > max){
                max = address.getIndex();
            }
        }
        return max;
    }

    private void initFromDb(){
        //TODO init from db by hdSeedId: isFromXRandom;
        initAddressesFromDb();
    }

    private void initAddressesFromDb(){
        //TODO get addresses from db by hdSeedId
    }

    public int getHdSeedId(){
        return hdSeedId;
    }

    public String getBitherId() {
        return bitherId;
    }

    public String getEncryptSeed() {
        return encryptSeed;
    }

    public String getEncryptBitherPassword() {
        return encryptBitherPassword;
    }

    public void decryptSeed(CharSequence password){
        //TODO decryptSeed
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

}
