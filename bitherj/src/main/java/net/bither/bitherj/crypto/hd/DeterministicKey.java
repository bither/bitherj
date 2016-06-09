/**
 * Copyright 2013 Matija Mazi.
 * Copyright 2014 Andreas Schildbach
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.bither.bitherj.crypto.hd;

import com.google.common.base.Objects;
import com.google.common.base.Objects.ToStringHelper;
import com.google.common.collect.ImmutableList;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.KeyCrypter;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * A deterministic key is a node in a {@link DeterministicHierarchy}. As per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">the BIP 32 specification</a> it is a pair
 * (key, chaincode). If you know its path in the tree and its chain code you can derive more keys from this. To obtain
 * one of these, you can call {@link HDKeyDerivation#createMasterPrivateKey(byte[])}.
 */
public class DeterministicKey extends ECKey {
    private static final long serialVersionUID = 1L;

    private final DeterministicKey parent;
    private final ImmutableList<ChildNumber> childNumberPath;

    private int parentFingerprint;
    /**
     * 32 bytes
     */
    private final byte[] chainCode;

    /**
     * Constructs a key from its components. This is not normally something you should use.
     */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            ECPoint publicAsPoint,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, compressPoint(checkNotNull(publicAsPoint)).getEncoded(), true);
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
    }

    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            byte[] pub,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, pub, true);
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
    }

    /**
     * Constructs a key from its components. This is not normally something you should use.
     */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv);
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
    }

    /**
     * Constructs a key from its components, including its public key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    private DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                             byte[] chainCode,
                             ECPoint publicAsPoint,
                             @Nullable DeterministicKey parent,
                             int depth,
                             int parentFingerprint) {
        super(null, compressPoint(publicAsPoint).getEncoded());
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.parentFingerprint = ascertainParentFingerprint(parent, parentFingerprint);
    }

    /**
     * Constructs a key from its components, including its private key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    private DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                             byte[] chainCode,
                             BigInteger priv,
                             @Nullable DeterministicKey parent,
                             int depth,
                             int parentFingerprint) {
        super(priv.toByteArray(), ECKey.publicKeyFromPrivate(priv, true));
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.parentFingerprint = ascertainParentFingerprint(parent, parentFingerprint);
    }

    /**
     * Returns the path through some {@link DeterministicHierarchy} which reaches this keys position in the tree.
     * A path can be written as 1/2/1 which means the first child of the root, the second child of that node, then
     * the first child of that node.
     */
    public ImmutableList<ChildNumber> getPath() {
        return childNumberPath;
    }

    /**
     * Returns the path of this key as a human readable string starting with M to indicate the master key.
     */
    public String getPathAsString() {
        return HDUtils.formatPath(getPath());
    }

    private int getDepth() {
        return childNumberPath.size();
    }

    /**
     * Returns the last element of the path returned by {@link net.bither.bitherj.crypto.hd.DeterministicKey#getPath()}
     */
    public ChildNumber getChildNumber() {
        return getDepth() == 0 ? ChildNumber.ZERO : childNumberPath.get(childNumberPath.size() - 1);
    }

    /**
     * Returns the chain code associated with this key. See the specification to learn more about chain codes.
     */
    public byte[] getChainCode() {
        return chainCode;
    }

    /**
     * Returns RIPE-MD160(SHA256(pub key bytes)).
     */
    public byte[] getIdentifier() {
        return Utils.sha256hash160(getPubKey());
    }

    /**
     * Returns the first 32 bits of the result of {@link #getIdentifier()}.
     */
    public int getFingerprint() {
        // TODO: why is this different than armory's fingerprint? BIP 32: "The first 32 bits
        // of the identifier are called the fingerprint."
        return ByteBuffer.wrap(Arrays.copyOfRange(getIdentifier(), 0, 4)).getInt();
    }

    @Nullable
    public DeterministicKey getParent() {
        return parent;
    }

    /**
     * Returns private key bytes, padded with zeros to 33 bytes.
     *
     * @throws IllegalStateException if the private key bytes are missing.
     */
    public byte[] getPrivKeyBytes33() {
        byte[] bytes33 = new byte[33];
        byte[] priv = getPrivKeyBytes();
        System.arraycopy(priv, 0, bytes33, 33 - priv.length, priv.length);
        return bytes33;
    }

    /**
     * Returns the same key with the private part removed. May return the same instance.
     */
    public DeterministicKey getPubOnly() {
        if (isPubKeyOnly()) return this;
        return new DeterministicKey(getPath(), getChainCode(), pub, null, parent);
    }


    static byte[] addChecksum(byte[] input) {
        int inputLength = input.length;
        byte[] checksummed = new byte[inputLength + 4];
        System.arraycopy(input, 0, checksummed, 0, inputLength);
        byte[] checksum = Utils.doubleDigest(input);
        System.arraycopy(checksum, 0, checksummed, inputLength, 4);
        return checksummed;
    }

//    @Override
//    public DeterministicKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
//        throw new UnsupportedOperationException("Must supply a new parent for encryption");
//    }
//
//    public DeterministicKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey, @Nullable DeterministicKey newParent) throws KeyCrypterException {
//        // Same as the parent code, except we construct a DeterministicKey instead of an ECKey.
//        checkNotNull(keyCrypter);
//        if (newParent != null)
//            checkArgument(newParent.isEncrypted());
//        final byte[] privKeyBytes = getPrivKeyBytes();
//        checkState(privKeyBytes != null, "Private key is not available");
//        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
//        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, keyCrypter, pub, encryptedPrivateKey, newParent);
//        return key;
//    }

    /**
     * A deterministic key is considered to be encrypted if it has access to encrypted private key bytes, OR if its
     * parent does. The reason is because the parent would be encrypted under the same key and this key knows how to
     * rederive its own private key bytes from the parent, if needed.
     */
    @Override
    public boolean isEncrypted() {
        return priv == null && (super.isEncrypted() || (parent != null && parent.isEncrypted()));
    }

    /**
     * Returns this keys {@link net.bither.bitherj.crypto.KeyCrypter} <b>or</b> the keycrypter of its parent key.
     */
    @Override
    @Nullable
    public KeyCrypter getKeyCrypter() {
        if (keyCrypter != null)
            return keyCrypter;
        else if (parent != null)
            return parent.getKeyCrypter();
        else
            return null;
    }

//    @Override
//    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
//        if (isEncrypted()) {
//            // If the key is encrypted, ECKey.sign will decrypt it first before rerunning sign. Decryption walks the
//            // key heirarchy to find the private key (see below), so, we can just run the inherited method.
//            return super.sign(input, aesKey);
//        } else {
//            // If it's not encrypted, derive the private via the parents.
//            final BigInteger privateKey = findOrDerivePrivateKey();
//            if (privateKey == null) {
//                // This key is a part of a public-key only heirarchy and cannot be used for signing
//                throw new MissingPrivateKeyException();
//            }
//            return super.doSign(input, privateKey);
//        }
//    }

    @Override
    public DeterministicKey decrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        BigInteger privKey = findOrDeriveEncryptedPrivateKey(keyCrypter, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, privKey, parent);
        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException("Provided AES key is wrong");
        return key;
    }

    // For when a key is encrypted, either decrypt our encrypted private key bytes, or work up the tree asking parents
    // to decrypt and re-derive.
    private BigInteger findOrDeriveEncryptedPrivateKey(KeyCrypter keyCrypter, KeyParameter aesKey) {
        if (encryptedPrivateKey != null)
            return new BigInteger(1, keyCrypter.decrypt(encryptedPrivateKey, aesKey));
        // Otherwise we don't have it, but maybe we can figure it out from our parents. Walk up the tree looking for
        // the first key that has some encrypted private key data.
        DeterministicKey cursor = parent;
        while (cursor != null) {
            if (cursor.encryptedPrivateKey != null) break;
            cursor = cursor.parent;
        }
        if (cursor == null)
            throw new KeyCrypterException("Neither this key nor its parents have an encrypted private key");
        byte[] parentalPrivateKeyBytes = keyCrypter.decrypt(cursor.encryptedPrivateKey, aesKey);
        return derivePrivateKeyDownwards(cursor, parentalPrivateKeyBytes);
    }

    @Nullable
    private BigInteger findOrDerivePrivateKey() {
        DeterministicKey cursor = this;
        while (cursor != null) {
            if (cursor.priv != null) break;
            cursor = cursor.parent;
        }
        if (cursor == null)
            return null;
        return derivePrivateKeyDownwards(cursor, cursor.priv.toByteArray());
    }

    private BigInteger derivePrivateKeyDownwards(DeterministicKey cursor, byte[] parentalPrivateKeyBytes) {
        DeterministicKey downCursor = new DeterministicKey(cursor.childNumberPath, cursor.chainCode,
                cursor.pub, new BigInteger(1, parentalPrivateKeyBytes), cursor.parent);
        // Now we have to rederive the keys along the path back to ourselves. That path can be found by just truncating
        // our path with the length of the parents path.
        ImmutableList<ChildNumber> path = childNumberPath.subList(cursor.getDepth(), childNumberPath.size());
        for (ChildNumber num : path) {
            downCursor = HDKeyDerivation.deriveChildKey(downCursor, num);
        }
        // downCursor is now the same key as us, but with private key bytes.
        checkState(downCursor.pub.equals(pub));
        return checkNotNull(downCursor.priv);
    }


    public DeterministicKey deriveSoftened(int child) {
        return HDKeyDerivation.deriveChildKey(this, new ChildNumber(child, false));
    }

    public DeterministicKey deriveHardened(int child) {
        return HDKeyDerivation.deriveChildKey(this, new ChildNumber(child, true));
    }

    /**
     * Returns the private key of this deterministic key. Even if this object isn't storing the private key,
     * it can be re-derived by walking up to the parents if necessary and this is what will happen.
     *
     * @throws IllegalStateException if the parents are encrypted or a watching chain.
     */
    public BigInteger getPrivKey() {
        final BigInteger key = findOrDerivePrivateKey();
        checkState(key != null, "Private key bytes not available");
        return key;
    }

    /**
     * Verifies equality of all fields but NOT the parent pointer (thus the same key derived in two separate heirarchy
     * objects will equal each other.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DeterministicKey other = (DeterministicKey) o;

        return super.equals(other)
                && Arrays.equals(this.chainCode, other.chainCode)
                && Objects.equal(this.childNumberPath, other.childNumberPath);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + childNumberPath.hashCode();
        result = 31 * result + Arrays.hashCode(chainCode);
        return result;
    }

    @Override
    public String toString() {
        final ToStringHelper helper = Objects.toStringHelper(this).omitNullValues();
        helper.add("pub", Utils.bytesToHexString(pub));
        helper.add("chainCode", Utils.bytesToHexString(chainCode));
        helper.add("path", getPathAsString());
        if (creationTimeSeconds > 0)
            helper.add("creationTimeSeconds", creationTimeSeconds);
        helper.add("isEncrypted", isEncrypted());
        helper.add("isPubKeyOnly", isPubKeyOnly());
        return helper.toString();
    }

    @Override
    public void clearPrivateKey() {
        super.clearPrivateKey();
        priv = null;
    }

    public void clearChainCode() {
        Utils.wipeBytes(chainCode);
    }

    /**
     * Return the fingerprint of this key's parent as an int value, or zero if this key is the
     * root node of the key hierarchy.  Raise an exception if the arguments are inconsistent.
     * This method exists to avoid code repetition in the constructors.
     */
    private int ascertainParentFingerprint(DeterministicKey parentKey, int parentFingerprint)
            throws IllegalArgumentException {
        if (parentFingerprint != 0) {
            return parentFingerprint;
        } else return 0;
    }

    public String serializePubB58() {
        return toBase58(serialize(true));
    }

    public String serializePrivB58() {
        return toBase58(serialize(false));
    }

    static String toBase58(byte[] ser) {
        return Base58.encode(addChecksum(ser));
    }

    public byte[] serializePublic() {
        return serialize(true);
    }

    public byte[] serializePrivate() {
        return serialize(false);
    }

    private byte[] serialize(boolean pub) {
        ByteBuffer ser = ByteBuffer.allocate(78);
        ser.putInt(pub ? 0x0488B21E : 0x0488ADE4);
        ser.put((byte) getDepth());
        ser.putInt(getParent() == null ? parentFingerprint : getParent().getFingerprint());
        ser.putInt(getChildNumber().i());
        ser.put(getChainCode());
        ser.put(pub ? getPubKey() : getPrivKeyBytes33());
        assert ser.position() == 78;
        return ser.array();
    }

    /** Deserialize a base-58-encoded HD Key with no parent */
    public static DeterministicKey deserializeB58(String base58) throws AddressFormatException {
        return deserializeB58(null, base58);
    }

    /**
     * Deserialize a base-58-encoded HD Key.
     *  @param parent The parent node in the given key's deterministic hierarchy.
     *  @throws IllegalArgumentException if the base58 encoded key could not be parsed.
     */
    public static DeterministicKey deserializeB58(@Nullable DeterministicKey parent, String base58) throws AddressFormatException {
        return deserialize(Base58.decodeChecked(base58), parent);
    }

    /**
     * Deserialize an HD Key with no parent
     */
    public static DeterministicKey deserialize(byte[] serializedKey) {
        return deserialize(serializedKey, null);
    }

    /**
     * Deserialize an HD Key.
     * @param parent The parent node in the given key's deterministic hierarchy.
     */
    public static DeterministicKey deserialize(byte[] serializedKey, @Nullable DeterministicKey parent) {
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if (header != 0x0488B21E && header != 0x0488ADE4)
            throw new IllegalArgumentException("Unknown header bytes: " + toBase58(serializedKey).substring(0, 4));
        boolean pub = header == 0x0488B21E;
        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        final int parentFingerprint = buffer.getInt();
        final int i = buffer.getInt();
        final ChildNumber childNumber = new ChildNumber(i);
        List<ChildNumber> path;
        if (parent != null) {
            if (parentFingerprint == 0)
                throw new IllegalArgumentException("Parent was provided but this key doesn't have one");
            if (parent.getFingerprint() != parentFingerprint)
                throw new IllegalArgumentException("Parent fingerprints don't match");
            path = HDUtils.append(parent.getPath(), childNumber);
            if (path.size() != depth)
                throw new IllegalArgumentException("Depth does not match");
        } else {
            if (depth >= 1)
                // We have been given a key that is not a root key, yet we lack the object representing the parent.
                // This can happen when deserializing an account key for a watching wallet.  In this case, we assume that
                // the client wants to conceal the key's position in the hierarchy.  The path is truncated at the
                // parent's node.
                path = Arrays.asList(new ChildNumber[]{childNumber});
            else path = new ArrayList<ChildNumber>();
        }
        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        assert !buffer.hasRemaining();
        if (pub) {
            return new DeterministicKey(ImmutableList.copyOf(path), chainCode, ECKey.CURVE.getCurve().decodePoint(data), parent, depth, parentFingerprint);
        } else {
            return new DeterministicKey(ImmutableList.copyOf(path), chainCode, new BigInteger(1, data), parent, depth, parentFingerprint);
        }
    }

    public byte[] getPubKeyExtended() {
        byte[] pub = getPubKey();
        byte[] chainCode = getChainCode();
        byte[] extended = new byte[pub.length + chainCode.length];
        for (int i = 0; i < pub.length; i++) {
            extended[i] = pub[i];
        }
        for (int i = 0; i < chainCode.length; i++) {
            extended[i + pub.length] = chainCode[i];
        }
        return extended;
    }

    public void wipe() {
        clearPrivateKey();
        clearChainCode();
        Utils.wipeBytes(pub);
    }
}
