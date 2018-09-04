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

import com.google.common.base.Function;
import com.google.common.collect.Collections2;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.annotation.Nullable;

/**
 * Created by songchenwen on 15/6/19.
 */
public class HDAccountCold extends AbstractHD {

    private static final Logger log = LoggerFactory.getLogger(HDAccountCold.class);

    public HDAccountCold(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password, boolean isFromXRandom)
            throws MnemonicException.MnemonicLengthException {
        this.mnemonicCode = mnemonicCode;
        this.mnemonicSeed = mnemonicSeed;
        hdSeed = seedFromMnemonic(mnemonicSeed, mnemonicCode);
        this.isFromXRandom = isFromXRandom;
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password,
                isFromXRandom);
        ECKey k = new ECKey(mnemonicSeed, null);
        String address = k.toAddress();
        k.clearPrivateKey();
        DeterministicKey accountKey = getAccount(master);
        DeterministicKey externalKey = getChainRootKey(accountKey, AbstractHD.PathType
                .EXTERNAL_ROOT_PATH);
        DeterministicKey internalKey = getChainRootKey(accountKey, PathType
                .INTERNAL_ROOT_PATH);
        DeterministicKey key = externalKey.deriveSoftened(0);
        String firstAddress = key.toAddress();
        accountKey.wipe();
        master.wipe();
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = AbstractDb.hdAccountProvider.addHDAccount(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                        .getPubKeyExtended());
        externalKey.wipe();
    }

    public HDAccountCold(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(mnemonicCode, mnemonicSeed, password, false);
    }

    public HDAccountCold(MnemonicCode mnemonicCode, SecureRandom random, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        this(mnemonicCode, randomByteFromSecureRandom(random, 16), password, random.getClass().getCanonicalName
                ().indexOf("XRandom") >= 0);
    }

    public HDAccountCold(MnemonicCode mnemonicCode, EncryptedData encryptedMnemonicSeed, CharSequence password) throws
            MnemonicException.MnemonicLengthException {
        this(mnemonicCode, encryptedMnemonicSeed.decrypt(password), password, encryptedMnemonicSeed.isXRandom());
    }

    public HDAccountCold(int hdSeedId) {
        this.hdSeedId = hdSeedId;
        this.isFromXRandom = AbstractDb.hdAccountProvider.hdAccountIsXRandom(hdSeedId);
    }

    public List<byte[]> signHashHexes(final Collection<String> hashes, Collection<PathTypeIndex>
            paths, CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        return signHashes(Collections2.transform(hashes, new Function<String, byte[]>() {
            @Nullable
            @Override
            public byte[] apply(String input) {
                return Utils.hexStringToByteArray(input);
            }
        }), paths, password);
    }

    public List<byte[]> signHashes(Collection<byte[]> hashes, Collection<PathTypeIndex> paths,
                                   CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        assert hashes.size() == paths.size();
        ArrayList<byte[]> sigs = new ArrayList<byte[]>();
        DeterministicKey master = masterKey(password);
        DeterministicKey account = getAccount(master);
        DeterministicKey external = getChainRootKey(account, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(account, PathType.INTERNAL_ROOT_PATH);
        master.wipe();
        account.wipe();
        Iterator<byte[]> hashIterator = hashes.iterator();
        Iterator<PathTypeIndex> pathIterator = paths.iterator();
        while (hashIterator.hasNext() && pathIterator.hasNext()) {
            byte[] hash = hashIterator.next();
            PathTypeIndex path = pathIterator.next();
            DeterministicKey key;
            if (path.pathType == PathType.EXTERNAL_ROOT_PATH) {
                key = external.deriveSoftened(path.index);
            } else {
                key = internal.deriveSoftened(path.index);
            }
            TransactionSignature sig = new TransactionSignature(key.sign(hash),
                    TransactionSignature.SigHash.ALL, false);
            sigs.add(ScriptBuilder.createInputScript(sig, key).getProgram());
            key.wipe();
        }
        external.wipe();
        internal.wipe();
        return sigs;
    }

    public String getFirstAddressFromDb() {
        return AbstractDb.hdAccountProvider.getHDFirstAddress(hdSeedId);
    }

    public boolean checkWithPassword(CharSequence password) {
        try {
            decryptHDSeed(password);
            decryptMnemonicSeed(password);
            byte[] hdCopy = Arrays.copyOf(hdSeed, hdSeed.length);
            boolean hdSeedSafe = Utils.compareString(getFirstAddressFromDb(),
                    getFirstAddressFromSeed(null));
            boolean mnemonicSeedSafe = Arrays.equals(seedFromMnemonic(mnemonicSeed, mnemonicCode), hdCopy);
            Utils.wipeBytes(hdCopy);
            wipeHDSeed();
            wipeMnemonicSeed();
            return hdSeedSafe && mnemonicSeedSafe;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    protected String getEncryptedHDSeed() {
        return AbstractDb.hdAccountProvider.getHDAccountEncryptSeed(hdSeedId);
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return AbstractDb.hdAccountProvider.getHDAccountEncryptMnemonicSeed(hdSeedId);
    }

    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public String getQRCodeFullEncryptPrivKey() {
        return MnemonicCode.instance().getMnemonicWordList().getHdQrCodeFlag() + getFullEncryptPrivKey();
    }

    private static byte[] randomByteFromSecureRandom(SecureRandom random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] accountPubExtended(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey account = getAccount(master);
        byte[] extended = account.getPubKeyExtended();
        master.wipe();
        account.wipe();
        return extended;
    }

    public String accountPubExtendedString(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        byte[] extended = accountPubExtended(password);
        String result = "";
        if (isFromXRandom) {
            result += QRCodeUtil.XRANDOM_FLAG;
        }
        result += Utils.bytesToHexString(extended).toUpperCase();
        return result;
    }


    public byte[] getInternalPub() {
        return AbstractDb.hdAccountProvider.getInternalPub(hdSeedId);
    }

    public byte[] getExternalPub() {
        return AbstractDb.hdAccountProvider.getExternalPub(hdSeedId);
    }

    public HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (type == AbstractHD.PathType.EXTERNAL_ROOT_PATH ? getExternalPub() : getInternalPub());
      return new HDAccount.HDAccountAddress(root.deriveSoftened(index).getPubKey(), type, index, true, hdSeedId);
    }

    public DeterministicKey getExternalKey(int index, CharSequence password) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey externalChainRoot = getChainRootKey(accountKey, AbstractHD.PathType
                    .EXTERNAL_ROOT_PATH);
            DeterministicKey key = externalChainRoot.deriveSoftened(index);
            master.wipe();
            accountKey.wipe();
            externalChainRoot.wipe();
            return key;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public DeterministicKey getInternalKey(int index, CharSequence password) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey externalChainRoot = getChainRootKey(accountKey, AbstractHD.PathType
                    .INTERNAL_ROOT_PATH);
            DeterministicKey key = externalChainRoot.deriveSoftened(index);
            master.wipe();
            accountKey.wipe();
            externalChainRoot.wipe();
            return key;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String xPubB58(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey purpose = master.deriveHardened(44);
        DeterministicKey coinType = purpose.deriveHardened(0);
        DeterministicKey account = coinType.deriveHardened(0);
        String xpub = account.serializePubB58();
        master.wipe();
        purpose.wipe();
        coinType.wipe();
        account.wipe();
        return xpub;
    }

    public List<HDAccount.HDAccountAddress> getHdColdAddresses(int page, AbstractHD.PathType pathType,CharSequence password){
        ArrayList<HDAccount.HDAccountAddress> addresses = new ArrayList<HDAccount.HDAccountAddress>();
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey pathTypeKey = getChainRootKey(accountKey, pathType);
            for (int i = (page -1) * 10;i < page * 10; i ++) {
                DeterministicKey key = pathTypeKey.deriveSoftened(i);
                HDAccount.HDAccountAddress hdAccountAddress = new HDAccount.HDAccountAddress
                        (key.toAddress(),key.getPubKeyExtended(),pathType,i,false,true,hdSeedId);

                addresses.add(hdAccountAddress);
            }
            master.wipe();
            accountKey.wipe();
            pathTypeKey.wipe();
            return addresses;
        } catch (KeyCrypterException e) {
            throw new PasswordException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
