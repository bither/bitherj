package net.bither.bitherj.db;

import java.util.List;

public interface IColdHDAccountAddressProvider {


    public int addHDAccount(String encryptedMnemonicSeed, String encryptSeed
            , String firstAddress, boolean isXrandom, String addressOfPS
            , byte[] externalPub, byte[] internalPub);

    public int addMonitoredHDAccount(boolean isXrandom, byte[] externalPub, byte[] internalPub);

    public String getHDFristAddress(int hdSeedId);

    public byte[] getExternalPub(int hdSeedId);

    public byte[] getInternalPub(int hdSeedId);

    public String getHDAccountEncryptSeed(int hdSeedId);

    public String getHDAccountEncryptMnmonicSeed(int hdSeedId);

    public boolean hdAccountIsXRandom(int seedId);

    public List<Integer> getHDAccountSeeds();

    public boolean hasHDAccountCold();
}
