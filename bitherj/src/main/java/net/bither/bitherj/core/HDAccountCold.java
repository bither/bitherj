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
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by songchenwen on 15/6/19.
 */
public class HDAccountCold extends AbstractHD {

    private static final Logger log = LoggerFactory.getLogger(HDAccountCold.class);

    public HDAccountCold(byte[] mnemonicSeed, CharSequence password, boolean isFromXRandom)
            throws MnemonicException.MnemonicLengthException {
        this.mnemonicSeed = mnemonicSeed;
        hdSeed = seedFromMnemonic(mnemonicSeed);
        this.isFromXRandom = isFromXRandom;
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password,
                isFromXRandom);
        String firstAddress;
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey externalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        DeterministicKey key = externalKey.deriveSoftened(0);
        firstAddress = key.toAddress();
        accountKey.wipe();
        master.wipe();
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = 0;//TODO AbstractDb.addressProvider.addHDAccount(encryptedMnemonicSeed
        // .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
        // isFromXRandom, address);
        externalKey.wipe();
    }

    public HDAccountCold(byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(mnemonicSeed, password, false);
    }

    public HDAccountCold(SecureRandom random, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(randomByteFromSecureRandom(random, 16), password, random.getClass().getCanonicalName
                ().indexOf("XRandom") >= 0);
    }

    public HDAccountCold(int hdSeedId) {
        this.hdSeedId = hdSeedId;
        this.isFromXRandom = false;// TODO AbstractDb.addressProvider.hdAccountIsXRandom(seedId);
    }

    public List<byte[]> signHashHexes(List<String> hashes, List<PathTypeIndex> paths,
                                      CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        ArrayList<byte[]> hashBytes = new ArrayList<byte[]>();
        for (String hash : hashes) {
            hashBytes.add(Utils.hexStringToByteArray(hash));
        }
        return signHashes(hashBytes, paths, password);
    }

    public List<byte[]> signHashes(List<byte[]> hashes, List<PathTypeIndex> paths, CharSequence
            password) throws MnemonicException.MnemonicLengthException {
        assert hashes.size() == paths.size();
        ArrayList<byte[]> sigs = new ArrayList<byte[]>();
        DeterministicKey master = masterKey(password);
        DeterministicKey account = getAccount(master);
        DeterministicKey external = getChainRootKey(account, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(account, PathType.INTERNAL_ROOT_PATH);
        master.wipe();
        account.wipe();
        for (int i = 0;
             i < hashes.size();
             i++) {
            byte[] hash = hashes.get(i);
            PathTypeIndex path = paths.get(i);
            DeterministicKey key;
            if (path.pathType == PathType.EXTERNAL_ROOT_PATH) {
                key = external.deriveSoftened(path.index);
            } else {
                key = internal.deriveSoftened(path.index);
            }
            ECKey.ECDSASignature sig = key.sign(hash);
            key.wipe();
            sigs.add(sig.encodeToDER());
        }
        external.wipe();
        internal.wipe();
        return sigs;
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.addressProvider.getHDFristAddress(hdSeedId);
    }

    @Override
    protected String getEncryptedHDSeed() {
        return null;//TODO EncryptedHDSeed for HD Account Cold
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return null;//TODO EncryptedMnemonicSeed for HD Account Cold
    }

    private static byte[] randomByteFromSecureRandom(SecureRandom random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static boolean hasHDAccountCold() {
        return false; //TODO check from db
    }

    public static HDAccountCold hdAccountCold() {
        return new HDAccountCold(0); //TODO get hd account cold id from db
    }
}
