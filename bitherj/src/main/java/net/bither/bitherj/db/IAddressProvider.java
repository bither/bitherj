package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMBId;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMKeychain;

import java.util.List;

public interface IAddressProvider {
    //hd
    public List<Integer> getHDSeeds();

    public String getEncryptSeed(int hdSeedId);
    public String getEncryptHDSeed(int hdSeedId);
    public void updateEncryptHDSeed(int hdSeedId, String encryptHDSeed);
    public void setEncryptSeed(int hdSeedId, String encryptSeed, String encryptHDSeed);

    public boolean isHDSeedFromXRandom(int hdSeedId);

    public String getHDMFristAddress(int hdSeedId);

    public int addHDKey(String encryptSeed, String encryptHdSeed, String firstAddress, boolean isXrandom);

    public HDMBId getHDMBId();


    public void addHDMBId(HDMBId bitherId);

    public void changeHDBIdPassword(HDMBId hdmbId);

    public void changeHDMBIdPassword(String encryptBitherPassword);

    public List<HDMAddress> getHDMAddressInUse(HDMKeychain keychain);

    public void prepareHDMAddresses(int hdSeedId, List<HDMAddress.Pubs> pubs);

    public List<HDMAddress.Pubs> getUncompletedHDMAddressPubs(int hdSeedId, int count);

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
