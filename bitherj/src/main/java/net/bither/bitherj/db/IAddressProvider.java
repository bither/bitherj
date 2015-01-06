package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMKeychain;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public interface IAddressProvider {
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

    public List<Address> getPrivKeyAddresses();
    public String getEncryptPrivKeyFromAddress(String address);
    public void addPrivKeyAddress(Address address);

    public List<Address> getWatchOnlyAddresses();
    public void addWatchOnlyAddress(Address address);
    public void removeWatchOnlyAddress(Address address);

    public List<Address> getTrashAddresses();
    public void trashPrivKeyAddress(Address address);
    public void restorePrivKeyAddress(Address address);

    public void syncComplete(Address address);
}
