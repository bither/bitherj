package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.BitherId;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMKeychain;

import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public interface IAddressProvider {
    public List<Integer> getHDSeeds();
    public String getEncryptSeed(int hdSeedId);
    public int addHDKey(String encryptSeed);

    public String getBitherId();
    public String getBitherEncryptPassword();
    public void addBitherId(String bitherId, String encryptBitherPassword);
    public void changeBitherPassword(String encryptBitherPassword);

    public List<HDMAddress> getHDMAddressInUse(int hdSeedId);
    public void addHDMAddress(int hdSeedId, List<Integer> indexes, List<byte[]> pubKeys1, List<byte[]> pubKeys2);
    public void completeHDMAddresses(int hdSeedId, List<Integer> indexes, List<byte[]> pubKeys3, List<String> addresses);
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
