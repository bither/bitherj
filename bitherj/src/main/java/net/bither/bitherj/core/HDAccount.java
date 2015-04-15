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
import java.util.List;

public class HDAccount extends AbstractHD {

    private int LOOK_AHEAD_SIZE = 100;

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
        master.wipe();
        List<HDAccountAddress> externalAddresses = new ArrayList<HDAccountAddress>();
        List<HDAccountAddress> internalAddresses = new ArrayList<HDAccountAddress>();
        for (int i = 0;
             i < LOOK_AHEAD_SIZE;
             i++) {
            byte[] subExternalPub = externalKey.deriveSoftened(i).getPubKey();
            byte[] subInternalPub = internalKey.deriveSoftened(i).getPubKey();
            HDAccountAddress externalAddress = new HDAccountAddress(subExternalPub
                    , PathType.EXTERNAL_ROOT_PATH, i, false);
            HDAccountAddress internalAddress = new HDAccountAddress(subInternalPub
                    , PathType.INTERNAL_ROOT_PATH, i, false);
            externalAddresses.add(externalAddress);
            internalAddresses.add(internalAddress);
        }
        wipeHDSeed();
        wipeMnemonicSeed();
        AbstractDb.hdAccountProvider.addExternalAddress(externalAddresses);
        AbstractDb.hdAccountProvider.addInternalAddress(internalAddresses);
        hdSeedId = AbstractDb.addressProvider.addHDAccount(encryptedMnemonicSeed
                .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                        .getPubKeyExtended());
        internalKey.wipe();
        externalKey.wipe();
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
        return AbstractDb.addressProvider.getInternalPub(hdSeedId);
    }

    public byte[] getExternalPub() {
        return AbstractDb.addressProvider.getExternalPub(hdSeedId);
    }

    @Override
    protected String getEncryptedHDSeed() {
        return AbstractDb.addressProvider.getHDAccountEncryptSeed(hdSeedId);
    }

    private void supplyEnoughKeys() {
        int lackOfExternal = LOOK_AHEAD_SIZE - (allGeneratedExternalAddressCount() -
                issuedExternalIndex());
        if (lackOfExternal > 0) {
            supplyNewExternalKey(lackOfExternal);
        }

        int lackOfInternal = LOOK_AHEAD_SIZE - (allGeneratedInternalAddressCount() -
                issuedInternalIndex());
        if (lackOfInternal > 0) {
            supplyNewInternalKey(lackOfInternal);
        }
    }

    private void supplyNewInternalKey(int count) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getInternalPub());
        int firstIndex = allGeneratedInternalAddressCount();
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .INTERNAL_ROOT_PATH, i, false));
        }
        AbstractDb.hdAccountProvider.addInternalAddress(as);
    }

    private void supplyNewExternalKey(int count) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (getExternalPub());
        int firstIndex = allGeneratedExternalAddressCount();
        ArrayList<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (int i = firstIndex;
             i < firstIndex + count;
             i++) {
            as.add(new HDAccountAddress(root.deriveSoftened(i).getPubKey(), PathType
                    .EXTERNAL_ROOT_PATH, i, false));
        }
        AbstractDb.hdAccountProvider.addExternalAddress(as);
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return AbstractDb.addressProvider.getHDAccountEncryptMnmonicSeed(hdSeedId);
    }

    public String getReceivingAddress() {
        return AbstractDb.hdAccountProvider.externalAddress();
    }

    public int issuedInternalIndex() {

        return AbstractDb.hdAccountProvider.issuedInternalIndex();
    }

    public int issuedExternalIndex() {
        return AbstractDb.hdAccountProvider.issuedExternalIndex();

    }

    private int allGeneratedInternalAddressCount() {
        //TODO
        return 0;
    }

    private int allGeneratedExternalAddressCount() {
        //TODO
        return 0;
    }

    private HDAccountAddress addressForPath(PathType type, int index) {
        assert index < (type == PathType.EXTERNAL_ROOT_PATH ? allGeneratedExternalAddressCount()
                : allGeneratedInternalAddressCount());
        //TODO read from db
        return null;
    }

    public boolean onNewTx(Tx tx) {
        List<HDAccountAddress> relatedAddresses = getRelatedAddressesForTx(tx);
        if (relatedAddresses.size() > 0) {
            //TODO should add this tx to db now
            int maxInternal = -1, maxExternal = -1;
            for (HDAccountAddress a : relatedAddresses) {
                if (a.pathType == PathType.EXTERNAL_ROOT_PATH) {
                    if (a.index > maxExternal) {
                        maxExternal = a.index;
                    }
                } else {
                    if (a.index > maxInternal) {
                        maxInternal = a.index;
                    }
                }
            }

            if (maxExternal > issuedExternalIndex()) {
                updateIssuedExternalIndex(maxExternal);
            }
            if (maxInternal > issuedInternalIndex()) {
                updateIssuedInternalIndex(maxInternal);
            }

            supplyEnoughKeys();
            return true;
        }
        return false;
    }

    public boolean isTxRelated(Tx tx){
        return getRelatedAddressesForTx(tx).size() > 0;
    }

    public List<HDAccountAddress> getRelatedAddressesForTx(Tx tx){
        //TODO from db
        return new ArrayList<HDAccountAddress>();
    }

    public Tx newTx(String toAddress, long amount, CharSequence password) {
        return newTx(new String[]{toAddress}, new long[]{amount}, password);
    }

    public Tx newTx(String[] toAddresses, long[] amounts, CharSequence password) {
        //TODO
        return null;
    }

    private void updateIssuedInternalIndex(int index) {
        //TODO update db
    }

    private void updateIssuedExternalIndex(int index) {
        //TODO update db
    }

    public int elementCountForBloomFilter() {
        return allGeneratedInternalAddressCount() * 2 + allGeneratedExternalAddressCount() * 2;
    }

    public void addElementsForBloomFilter(BloomFilter filter) {
        //TODO get all generated addresses
        List<HDAccountAddress> as = new ArrayList<HDAccountAddress>();
        for (HDAccountAddress a : as) {
            filter.insert(a.getPub());
            filter.insert(Utils.sha256hash160(a.getPub()));
        }
    }

    public static class HDAccountAddress {
        private String address;
        private byte[] pub;
        private int index;
        private PathType pathType;

        private boolean isIssued;

        public HDAccountAddress(byte[] pub, PathType pathType, int index, boolean isIssued) {
            this(Utils.toAddress(Utils.sha256hash160(pub)), pub, pathType, index, isIssued);
        }

        public HDAccountAddress(String address, byte[] pub, PathType pathType, int index, boolean isIssued) {
            this.pub = pub;
            this.address = address;
            this.pathType = pathType;
            this.index = index;
            this.isIssued = isIssued;
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

        public PathType getPathType() {
            return pathType;
        }

        public boolean isIssued() {
            return isIssued;
        }
    }
}
