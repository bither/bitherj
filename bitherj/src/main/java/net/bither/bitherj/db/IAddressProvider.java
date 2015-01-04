package net.bither.bitherj.db;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMKeychain;

import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public interface IAddressProvider {
    public List<HDMKeychain> getKeychains();
    public HDMKeychain getKeychain(int hdKeyId);

    public List<HDMAddress> getHDMAddress();
    public List<Address> getPrivKeyAddresses();
    public List<Address> getWatchOnlyAddresses();
    public List<Address> getTrashAddresses();

    public void addHDMAddress(List<HDMAddress> addresses);
    public int addHDKey(String encryptSeed, String bitherId, String encryptBitherPassword);
}
