/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.core;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by songchenwen on 15/6/2.
 */
public class EnterpriseHDMSeed extends AbstractHD {
    public static final String XPubPrefix = "EHDM:";

    public EnterpriseHDMSeed(byte[] mnemonicSeed, boolean isXRandom,CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
        isFromXRandom = isXRandom;
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
        hdSeedId = AbstractDb.addressProvider.addEnterpriseHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address);

    }

    public EnterpriseHDMSeed(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(mnemonicSeed, false, password);
    }

    // Create With Random
    public EnterpriseHDMSeed(SecureRandom random, CharSequence password) {
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
        hdSeedId = AbstractDb.addressProvider.addEnterpriseHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address);
    }

    // From DB
    public EnterpriseHDMSeed(int seedId) {
        this.hdSeedId = seedId;
        isFromXRandom = AbstractDb.enterpriseHDMProvider.isEnterpriseHDMSeedFromXRandom(hdSeedId);
    }

    public byte[] getExternalRootPubExtended(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey externalChainRoot = getChainRootKey(accountKey, PathType
                .EXTERNAL_ROOT_PATH);
        master.wipe();
        accountKey.wipe();
        byte[] ext = externalChainRoot.getPubKeyExtended();
        externalChainRoot.clearPrivateKey();
        externalChainRoot.clearChainCode();
        return ext;
    }

    public List<byte[]> signHashes(int index, List<byte[]> hashes, CharSequence password) {
        DeterministicKey key = getExternalKey(index, password);
        ArrayList<byte[]> sigs = new ArrayList<byte[]>();
        for (int i = 0;
             i < hashes.size();
             i++) {
            sigs.add(key.sign(hashes.get(i)).encodeToDER());
        }
        return sigs;
    }

    public boolean checkWithPassword(CharSequence password) {
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

    public boolean isFromXRandom() {
        return isFromXRandom;
    }

    @Override
    protected String getEncryptedHDSeed() {

        return AbstractDb.enterpriseHDMProvider.getEnterpriseEncryptHDSeed(this.hdSeedId);
    }

    @Override
    public String getEncryptedMnemonicSeed() {
        return AbstractDb.enterpriseHDMProvider.getEnterpriseEncryptMnemonicSeed(this.hdSeedId);
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.enterpriseHDMProvider.getEnterpriseHDFristAddress(this.hdSeedId);
    }

    public static boolean hasSeed() {
        return AbstractDb.enterpriseHDMProvider.getEnterpriseHDMSeedId() >= 0;
    }

    public static EnterpriseHDMSeed seed() {
        if (hasSeed()) {
            return new EnterpriseHDMSeed(AbstractDb.enterpriseHDMProvider.getEnterpriseHDMSeedId());
        }
        return null;
    }

}
