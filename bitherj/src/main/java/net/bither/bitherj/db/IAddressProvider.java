package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMBId;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.PasswordSeed;

import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

public interface IAddressProvider {
    // password
    public boolean changePassword(CharSequence oldPassword, CharSequence newPassword);

    public PasswordSeed getPasswordSeed();

    public boolean hasPasswordSeed();

    //hd

    public int addHDAccount(String encryptedMnemonicSeed, String encryptSeed
            , String firstAddress, boolean isXrandom, String addressOfPS
            , byte[] externalPub, byte[] internalPub);

    public String getHDFristAddress(int hdSeedId);

    public byte[] getExternalPub(int hdSeedId);

    public byte[] getInternalPub(int hdSeedId);

    public String getHDAccountEncryptSeed(int hdSeedId);

    public String getHDAccountEncryptMnmonicSeed(int hdSeedId);

    public boolean hdAccountIsXRandom(int seedId);

    public List<Integer> getHDAccountSeeds();

    public List<Integer> getHDSeeds();

    public String getEncryptMnemonicSeed(int hdSeedId);

    public String getEncryptHDSeed(int hdSeedId);

    public void updateEncrypttMnmonicSeed(int hdSeedId, String encryptMnmonicSeed);

    public boolean isHDSeedFromXRandom(int hdSeedId);

    public String getHDMFristAddress(int hdSeedId);

    public String getSingularModeBackup(int hdSeedId);

    public void setSingularModeBackup(int hdSeedId, String singularModeBackup);

    public int addHDKey(String encryptedMnemonicSeed, String encryptHdSeed, String firstAddress, boolean isXrandom, String addressOfPS);

    public HDMBId getHDMBId();


    public void addAndUpdateHDMBId(HDMBId bitherId, String addressOfPS);


    public List<HDMAddress> getHDMAddressInUse(HDMKeychain keychain);

    public void prepareHDMAddresses(int hdSeedId, List<HDMAddress.Pubs> pubs);

    public List<HDMAddress.Pubs> getUncompletedHDMAddressPubs(int hdSeedId, int count);

    public int maxHDMAddressPubIndex(int hdSeedId);//including completed and uncompleted

    public void recoverHDMAddresses(int hdSeedId, List<HDMAddress> addresses);


    public void completeHDMAddresses(int hdSeedId, List<HDMAddress> addresses);

    public void setHDMPubsRemote(int hdSeedId, int index, byte[] remote);

    public int uncompletedHDMAddressCount(int hdSeedId);

    public void syncComplete(int hdSeedId, int hdSeedIndex);


    //normal
    public List<Address> getAddresses();

    public String getEncryptPrivateKey(String address);

    public void addAddress(Address address);

    public void updatePrivateKey(String address, String encryptPriv);

    public void removeWatchOnlyAddress(Address address);

    public void trashPrivKeyAddress(Address address);

    public void restorePrivKeyAddress(Address address);

    public void updateSyncComplete(Address address);

    // alias
    public String getAlias(String address);

    public Map<String, String> getAliases();

    public void updateAlias(String address, @Nullable String alias);

    //vanity_len
    public int getVanityLen(String address);

    public Map<String, Integer> getVanitylens();

    public void updateVaitylen(String address, int vanitylen);


}
