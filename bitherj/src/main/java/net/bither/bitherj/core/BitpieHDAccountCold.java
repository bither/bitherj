package net.bither.bitherj.core;

import com.google.common.base.Function;
import com.google.common.collect.Collections2;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IHDAccountProvider;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Nullable;

import static net.bither.bitherj.utils.HDAccountUtils.getSign;
import static net.bither.bitherj.utils.HDAccountUtils.getWitness;

public class BitpieHDAccountCold extends AbstractHD {

    public static final String BitpieHDAccountPlaceHolder = "BitpieHDAccount";

    private IHDAccountProvider bitpieHDAccountProvicer = AbstractDb.bitpieHdAccountProvider;

    public BitpieHDAccountCold(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password, boolean isFromXRandom)
            throws MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException {
        this.mnemonicCode = mnemonicCode;
        this.mnemonicSeed = mnemonicSeed;
        hdSeed = seedFromMnemonic(mnemonicSeed, mnemonicCode);
        this.isFromXRandom = isFromXRandom;
        DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(hdSeed);
        EncryptedData encryptedHDSeed = new EncryptedData(hdSeed, password, isFromXRandom);
        EncryptedData encryptedMnemonicSeed = new EncryptedData(mnemonicSeed, password,
                isFromXRandom);

        byte[] validMnemonicSeed = encryptedMnemonicSeed.decrypt(password);
        byte[] validHdSeed = seedFromMnemonic(validMnemonicSeed, mnemonicCode);
        if (!Arrays.equals(mnemonicSeed, validMnemonicSeed) || !Arrays.equals(hdSeed, validHdSeed)) {
            wipeHDSeed();
            wipeMnemonicSeed();
            throw new MnemonicException.MnemonicWordException("seed error");
        }

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
        key.wipe();
        accountKey.wipe();
        master.wipe();
        wipeHDSeed();
        wipeMnemonicSeed();
        hdSeedId = bitpieHDAccountProvicer.addHDAccount(encryptedMnemonicSeed
                        .toEncryptedString(), encryptedHDSeed.toEncryptedString(), firstAddress,
                isFromXRandom, address, externalKey.getPubKeyExtended(), internalKey
                        .getPubKeyExtended());
        externalKey.wipe();
        internalKey.wipe();
    }

    public BitpieHDAccountCold(MnemonicCode mnemonicCode, byte[] mnemonicSeed, CharSequence password) throws MnemonicException
            .MnemonicLengthException, MnemonicException.MnemonicWordException {
        this(mnemonicCode, mnemonicSeed, password, false);
    }

    public BitpieHDAccountCold(MnemonicCode mnemonicCode, SecureRandom random, CharSequence password) throws MnemonicException
            .MnemonicLengthException, MnemonicException.MnemonicWordException {
        this(mnemonicCode, randomByteFromSecureRandom(random, 16), password, random.getClass().getCanonicalName
                ().indexOf("XRandom") >= 0);
    }

    public BitpieHDAccountCold(MnemonicCode mnemonicCode, EncryptedData encryptedMnemonicSeed, CharSequence password) throws
            MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException {
        this(mnemonicCode, encryptedMnemonicSeed.decrypt(password), password, encryptedMnemonicSeed.isXRandom());
    }

    public BitpieHDAccountCold(int hdSeedId) {
        this.hdSeedId = hdSeedId;
        this.isFromXRandom = bitpieHDAccountProvicer.hdAccountIsXRandom(hdSeedId);
    }

    public List<byte[]> signHashHexes(final Collection<String> hashes,
                                      Collection<PathTypeIndex> paths,
                                      BitpieColdCoinDetail coinDetail,
                                      BitpieColdCoinDetail feeCoinDetail,
                                      CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        if (coinDetail.bitpieColdCoin == BitpieColdCoin.BTC && feeCoinDetail == null) {
            return signBtcHashes(Collections2.transform(hashes, new Function<String, byte[]>() {
                @Nullable
                public byte[] apply(String input) {
                    return Utils.hexStringToByteArray(input);
                }
            }), paths, password);
        } else {
            return signHashes(Collections2.transform(hashes, new Function<String, byte[]>() {
                @Nullable
                public byte[] apply(String input) {
                    return Utils.hexStringToByteArray(input);
                }
            }), paths, coinDetail, feeCoinDetail, password);
        }
    }

    public List<byte[]> signHashes(Collection<byte[]> hashes,
                                      Collection<PathTypeIndex> paths,
                                      BitpieColdCoinDetail coinDetail,
                                      BitpieColdCoinDetail feeCoinDetail,
                                      CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        assert hashes.size() == paths.size();
        ArrayList<byte[]> sigs = new ArrayList<byte[]>();
        DeterministicKey master = masterKey(password);
        DeterministicKey account = getAccount(master, coinDetail.bitpieColdCoin.getPathNumber());
        DeterministicKey external = getChainRootKey(account, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(account, PathType.INTERNAL_ROOT_PATH);
        DeterministicKey feeAccount = null;
        DeterministicKey feeExternal = null;
        DeterministicKey feeInternal = null;
        if (feeCoinDetail != null) {
            feeAccount = getAccount(master, feeCoinDetail.bitpieColdCoin.getPathNumber());
            feeExternal = getChainRootKey(feeAccount, PathType.EXTERNAL_ROOT_PATH);
            feeInternal = getChainRootKey(feeAccount, PathType.INTERNAL_ROOT_PATH);
        }
        master.wipe();
        account.wipe();
        if (feeAccount != null) {
            feeAccount.wipe();
        }
        Iterator<byte[]> hashIterator = hashes.iterator();
        Iterator<PathTypeIndex> pathIterator = paths.iterator();
        while (hashIterator.hasNext() && pathIterator.hasNext()) {
            byte[] hash = hashIterator.next();
            PathTypeIndex path = pathIterator.next();
            DeterministicKey key;
            if (feeCoinDetail != null && path.coinCode.toUpperCase().equals(feeCoinDetail.bitpieColdCoin.code.toUpperCase())) {
                if (path.pathType == PathType.EXTERNAL_ROOT_PATH) {
                    key = feeExternal.deriveSoftened(path.index);
                } else {
                    key = feeInternal.deriveSoftened(path.index);
                }
            } else {
                if (path.pathType == PathType.EXTERNAL_ROOT_PATH) {
                    key = external.deriveSoftened(path.index);
                } else {
                    key = internal.deriveSoftened(path.index);
                }
            }
            sigs.add(key.sign(hash).encodeToDER());
            key.wipe();
        }
        external.wipe();
        internal.wipe();
        if (feeExternal != null) {
            feeExternal.wipe();
        }
        if (feeInternal != null) {
            feeInternal.wipe();
        }
        return sigs;
    }

    public List<byte[]> signBtcHashes(Collection<byte[]> hashes,
                                   Collection<PathTypeIndex> paths,
                                   CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        assert hashes.size() == paths.size();
        ArrayList<byte[]> sigs = new ArrayList<byte[]>();
        DeterministicKey master = masterKey(password);
        DeterministicKey account = getAccount(master);
        DeterministicKey purpose49Account = getAccount(master, AbstractHD.PurposePathLevel.P2SHP2WPKH);
        DeterministicKey external = getChainRootKey(account, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey internal = getChainRootKey(account, PathType.INTERNAL_ROOT_PATH);
        DeterministicKey purpose49External = getChainRootKey(purpose49Account, PathType.EXTERNAL_ROOT_PATH);
        DeterministicKey purpose49Internal = getChainRootKey(purpose49Account, PathType.INTERNAL_ROOT_PATH);
        master.wipe();
        account.wipe();
        purpose49Account.wipe();
        Iterator<byte[]> hashIterator = hashes.iterator();
        Iterator<PathTypeIndex> pathIterator = paths.iterator();
        while (hashIterator.hasNext() && pathIterator.hasNext()) {
            byte[] hash = hashIterator.next();
            PathTypeIndex path = pathIterator.next();
            DeterministicKey key;
            if (path.pathType == PathType.EXTERNAL_ROOT_PATH) {
                key = external.deriveSoftened(path.index);
            } else if (path.pathType == PathType.INTERNAL_ROOT_PATH) {
                key = internal.deriveSoftened(path.index);
            } else if (path.pathType == PathType.EXTERNAL_BIP49_PATH) {
                key = purpose49External.deriveSoftened(path.index);
            } else {
                key = purpose49Internal.deriveSoftened(path.index);
            }
            if (path.pathType.isSegwit()) {
                sigs.add(getWitness(key.getPubKey(), key.sign(hash).encodeToDER()));
            } else {
                sigs.add(key.sign(hash).encodeToDER());
            }
            key.wipe();
        }
        external.wipe();
        internal.wipe();
        purpose49External.wipe();
        purpose49Internal.wipe();
        return sigs;
    }

    public String getFirstAddressFromDb() {
        return bitpieHDAccountProvicer.getHDFirstAddress(hdSeedId);
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
        return bitpieHDAccountProvicer.getHDAccountEncryptSeed(hdSeedId);
    }

    @Override
    protected String getEncryptedMnemonicSeed() {
        return bitpieHDAccountProvicer.getHDAccountEncryptMnemonicSeed(hdSeedId);
    }

    public String getFullEncryptPrivKey() {
        String encryptPrivKey = getEncryptedMnemonicSeed();
        return PrivateKeyUtil.getFullencryptHDMKeyChain(isFromXRandom, encryptPrivKey);
    }

    public String getQRCodeFullEncryptPrivKey() {
        return MnemonicCode.instance().getMnemonicWordList().getBitpieColdQrCodeFlag() + getFullEncryptPrivKey();
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
        return bitpieHDAccountProvicer.getInternalPub(hdSeedId);
    }

    public byte[] getExternalPub() {
        return bitpieHDAccountProvicer.getExternalPub(hdSeedId);
    }

    public HDAccount.HDAccountAddress addressForPath(AbstractHD.PathType type, int index) {
        DeterministicKey root = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (type == AbstractHD.PathType.EXTERNAL_ROOT_PATH ? getExternalPub() : getInternalPub());
        return new HDAccount.HDAccountAddress(root.deriveSoftened(index).getPubKey(), type, index, true, hdSeedId);
    }

    public DeterministicKey getExternalKey(int index, CharSequence password) {
        return getExternalKey(index, 0, password);
    }

    public DeterministicKey getExternalKey(int index, int pathNumber, CharSequence password) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master, pathNumber);
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

    public DeterministicKey getSegwitExternalKey(int index, CharSequence password) {
        try {
            DeterministicKey master = masterKey(password);
            DeterministicKey accountKey = getAccount(master);
            DeterministicKey externalChainRoot = getChainRootKey(accountKey, AbstractHD.PathType
                    .EXTERNAL_BIP49_PATH);
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
        return xPubB58(password, 0);
    }

    public String xPubB58(CharSequence password, int coinPathNumber) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey purpose = master.deriveHardened(PurposePathLevel.Normal.getValue());
        DeterministicKey coinType = purpose.deriveHardened(coinPathNumber);
        DeterministicKey account = coinType.deriveHardened(0);
        String xpub = account.serializePubB58();
        master.wipe();
        purpose.wipe();
        coinType.wipe();
        account.wipe();
        return xpub;
    }

    public String p2shp2wpkhXPubB58(CharSequence password) throws MnemonicException
            .MnemonicLengthException {
        DeterministicKey master = masterKey(password);
        DeterministicKey purpose = master.deriveHardened(PurposePathLevel.P2SHP2WPKH.getValue());
        DeterministicKey coinType = purpose.deriveHardened(0);
        DeterministicKey account = coinType.deriveHardened(0);
        String xpub = account.serializePubB58();
        master.wipe();
        purpose.wipe();
        coinType.wipe();
        account.wipe();
        return xpub;
    }

    public List<HDAccount.HDAccountAddress> getHdColdAddresses(int page, AbstractHD.PathType pathType, CharSequence password){
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
