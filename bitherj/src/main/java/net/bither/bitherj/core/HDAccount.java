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
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;

public abstract class HDAccount extends AbstractHD {
    private transient byte[] mnemonicSeed;
    private transient byte[] hdSeed;
    private boolean isFromXRandom;
    private byte[] externalPub;
    private byte[] internalPub;
    private String externalAddress;

    public HDAccount(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
        String firstAddress = getFirstAddressFromSeed(password);
        hdSeed = seedFromMnemonic(mnemonicSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password, isFromXRandom);
        initHDAccount(encryptedMnemonicSeed, encryptedHDSeed, firstAddress);

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
        initHDAccount(encryptedMnemonicSeed, encryptedHDSeed, firstAddress);

    }

    private void initHDAccount(EncryptedData encryptedMnemonicSeed,
                               EncryptedData encryptedHDSeed, String firstAddress) {
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        DeterministicKey internalKey = internalChainRoot(master);
        DeterministicKey externalKey = externalChainRoot(master);
        byte[] internalPub = internalKey.getPubKeyExtended();
        byte[] externalPub = externalKey.getPubKeyExtended();
        internalKey.wipe();
        externalKey.wipe();
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = AbstractDb.hdAccountProvider.addHDKey(encryptedMnemonicSeed.toEncryptedString(),
                encryptedHDSeed.toEncryptedString(), firstAddress, isFromXRandom, address
                , externalPub, internalPub);

    }

    public HDAccount() {
        initFromDb();
    }

    private void initFromDb() {

    }


    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public byte[] getInternalPub() {
        return AbstractDb.hdAccountProvider.getInternalPub();
    }

    public byte[] getExternalPub() {
        return AbstractDb.hdAccountProvider.getExternalPub();
    }

    @Override
    protected String getEncryptedHDSeed() {
        return AbstractDb.hdAccountProvider.getEncryptHDSeed(hdSeedId);
    }


    @Override
    protected String getEncryptedMnemonicSeed() {
        return AbstractDb.hdAccountProvider.getEncryptHDSeed(hdSeedId);
    }

    public class HDAccountAddress {
        private String address;
        private byte[] pub;
        private int index;
        private int accountRoot;

        public HDAccountAddress(byte[] pub, int accountRoot, int index) {
            this.pub = pub;
            this.address = Utils.toAddress(Utils.sha256hash160(pub));
            this.accountRoot = accountRoot;
            this.index = index;

        }

        public String getAddress() {
            return address;
        }

        public byte[] getPub() {
            return pub;
        }

        public int getIndex() {
            return index;
        }

        public int getAccountRoot() {
            return accountRoot;
        }


    }
}
