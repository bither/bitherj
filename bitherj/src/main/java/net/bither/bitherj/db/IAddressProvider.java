package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMKeychain;

import java.util.ArrayList;
import java.util.List;

public interface IAddressProvider {
    //hd
    public List<Integer> getHDSeeds();

    public String getEncryptSeed(int hdSeedId);

    public void setEncryptSeed(int hdSeedId, String encryptedSeed);

    public boolean isHDSeedFromXRandom(int hdSeedId);

    public int addHDKey(String encryptSeed, boolean isXrandom);

    public String getBitherId();

    public String getBitherEncryptPassword();

    public void addBitherId(String bitherId, String encryptBitherPassword);

    public void changeBitherPassword(String encryptBitherPassword);

    public List<HDMAddress> getHDMAddressInUse(HDMKeychain keychain);

    public void prepareHDMAddresses(int hdSeedId, List<HDMAddress.Pubs> pubs);

    public ArrayList<HDMAddress.Pubs> getUncompletedHDMAddressPubs(int hdSeedId, int count);

    public int maxHDMAddressPubIndex(int hdSeedId);//including completed and uncompleted

    public void completeHDMAddresses(int hdSeedId, List<HDMAddress> addresses);

    public int uncompletedHDMAddressCount(int hdSeedId);

    public void syncComplete(int hdSeedId, int hdSeedIndex);


    //normal
    public List<Address> getAddresses();

    public void addAddress(Address address);

    public void updatePrivateKey(Address address);

    public void removeWatchOnlyAddress(Address address);

    public void trashPrivKeyAddress(Address address);

    public void restorePrivKeyAddress(Address address);

    public void updateSyncComplete(Address address);

}
