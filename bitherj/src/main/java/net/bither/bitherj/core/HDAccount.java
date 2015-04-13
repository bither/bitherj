/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.core;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;

import java.security.SecureRandom;

public abstract class HDAccount extends AbstractHD {
    private transient byte[] mnemonicSeed;
    private transient byte[] hdSeed;
    private boolean isFromXRandom;

    //    private int issuedExternalIndex;
//    private int issuedInternalIndex;
    private byte[] externalPub;
    private byte[] internalPub;
    private String externalAddress;

    public HDAccount(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
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

//        hdSeedId = AbstractDb.hdAccountProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
//                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address, null, null);

    }

    // Create With Random
    public HDAccount(SecureRandom random, CharSequence password) {
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
//        hdSeedId = AbstractDb.hdAccountProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
//                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address);

    }


    @Override
    protected String getEncryptedHDSeed() {
        return AbstractDb.hdAccountProvider.getEncryptHDSeed(hdSeedId);
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return AbstractDb.hdAccountProvider.getEncryptHDSeed(hdSeedId);
    }
}
