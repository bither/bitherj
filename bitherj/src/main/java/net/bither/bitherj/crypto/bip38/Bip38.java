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

package net.bither.bitherj.crypto.bip38;


import com.lambdaworks.crypto.SCrypt;

import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkNotNull;


public class Bip38 {

    public static final String BIP38_CHARACTER_ENCODING = "UTF-8";
    public static final int SCRYPT_N = 16384;
    public static final int SCRYPT_LOG2_N = 14;
    public static final int SCRYPT_R = 8;
    public static final int SCRYPT_P = 8;
    public static final int SCRYPT_LENGTH = 64;

    public static final BigInteger n = new BigInteger(1, Utils.hexStringToByteArray("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));

    /**
     * Encrypt a SIPA formatted private key with a passphrase using BIP38.
     * <p/>
     * This is a helper function that does everything in one go. You can call the
     * individual functions if you wish to separate it into more phases.
     *
     * @throws InterruptedException
     */
    public static String encryptNoEcMultiply(CharSequence passphrase, String base58EncodedPrivateKey) throws InterruptedException, AddressFormatException {
        DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(base58EncodedPrivateKey);
        ECKey key = dumpedPrivateKey.getKey();
        dumpedPrivateKey.clearPrivateKey();
        byte[] salt = Bip38.calculateScryptSalt(key.toAddress());
        byte[] stretchedKeyMaterial = bip38Stretch1(passphrase, salt, SCRYPT_LENGTH);
        return encryptNoEcMultiply(stretchedKeyMaterial, key, salt);
    }

    /**
     * Perform BIP38 compatible password stretching on a password to derive the
     * BIP38 key material
     *
     * @throws InterruptedException
     */
    public static byte[] bip38Stretch1(CharSequence passphrase, byte[] salt, int outputSize)
            throws InterruptedException {
        byte[] passwordBytes = null;
        byte[] derived;
        try {
            passwordBytes = convertToByteArray(passphrase);
            derived = SCrypt.scrypt(convertToByteArray(passphrase), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, outputSize
            );
            return derived;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } finally {
            // Zero the password bytes.
            if (passwordBytes != null) {
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }
        }
    }

    private static byte[] convertToByteArray(CharSequence charSequence) {
        checkNotNull(charSequence);
        ByteBuffer bb = Charset.forName("UTF-8").encode(CharBuffer.wrap(charSequence));
        byte[] result = new byte[bb.remaining()];
        bb.get(result);
        bb.clear();
        byte[] clearTest = new byte[bb.remaining()];
        java.util.Arrays.fill(clearTest, (byte) 0);
        bb.put(clearTest);
        return result;


    }

    public static String encryptNoEcMultiply(byte[] stretcedKeyMaterial, ECKey key, byte[] salt) {

        // Encoded result
        int checksumLength = 4;
        byte[] encoded = new byte[39 + checksumLength];
        int index = 0;
        encoded[index++] = (byte) 0x01;
        encoded[index++] = (byte) 0x42;

        // Flags byte
        byte non_EC_multiplied = (byte) 0xC0;
        byte compressedPublicKey = key.isCompressed() ? (byte) 0x20 : (byte) 0;
        encoded[index++] = (byte) (non_EC_multiplied | compressedPublicKey);

        // Salt
        System.arraycopy(salt, 0, encoded, index, salt.length);
        index += salt.length;

        // Derive Keys
        byte[] derivedHalf1 = new byte[32];
        System.arraycopy(stretcedKeyMaterial, 0, derivedHalf1, 0, 32);
        byte[] derivedHalf2 = new byte[32];
        System.arraycopy(stretcedKeyMaterial, 32, derivedHalf2, 0, 32);

        // Initialize AES key
        Rijndael aes = new Rijndael();
        aes.makeKey(derivedHalf2, 256);

        // Get private key bytes
        byte[] complete = key.getPrivKeyBytes();

        // Insert first encrypted key part
        byte[] toEncryptPart1 = new byte[16];
        for (int i = 0; i < 16; i++) {
            toEncryptPart1[i] = (byte) ((((int) complete[i]) & 0xFF) ^ (((int) derivedHalf1[i]) & 0xFF));
        }
        byte[] encryptedHalf1 = new byte[16];
        aes.encrypt(toEncryptPart1, encryptedHalf1);
        System.arraycopy(encryptedHalf1, 0, encoded, index, encryptedHalf1.length);
        index += encryptedHalf1.length;

        // Insert second encrypted key part
        byte[] toEncryptPart2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            toEncryptPart2[i] = (byte) ((((int) complete[16 + i]) & 0xFF) ^ (((int) derivedHalf1[16 + i]) & 0xFF));
        }
        byte[] encryptedHalf2 = new byte[16];
        aes.encrypt(toEncryptPart2, encryptedHalf2);
        System.arraycopy(encryptedHalf2, 0, encoded, index, encryptedHalf2.length);
        index += encryptedHalf2.length;

        // Checksum
        Sha256Hash checkSum = Bip38Util.doubleSha256(encoded, 0, 39);
        byte[] start = checkSum.firstFourBytes();
        System.arraycopy(start, 0, encoded, 39, checksumLength);

        // Base58 encode
        String result = Bip38Util.encode(encoded);
        return result;
    }

    public static boolean isBip38PrivateKey(String bip38PrivateKey) throws AddressFormatException {
        return parseBip38PrivateKey(bip38PrivateKey) != null;
    }

    public static class Bip38PrivateKey {
        public boolean ecMultiply;
        public boolean compressed;
        public boolean lotSequence;
        public byte[] salt;
        public byte[] data;

        public Bip38PrivateKey(boolean ecMultiply, boolean compressed, boolean lotSequence, byte[] salt, byte[] data) {
            this.ecMultiply = ecMultiply;
            this.compressed = compressed;
            this.lotSequence = lotSequence;
            this.salt = salt;
            this.data = data;
        }
    }

    public static Bip38PrivateKey parseBip38PrivateKey(String bip38PrivateKey) throws AddressFormatException {
        // Decode Base 58
        byte[] decoded = Bip38Util.decodeChecked(bip38PrivateKey);
        if (decoded == null) {
            return null;
        }

        // Validate length
        if (decoded.length != 39) {
            return null;
        }

        int index = 0;

        // Validate BIP 38 prefix
        if (decoded[index++] != (byte) 0x01) {
            return null;
        }
        boolean ecMultiply;
        if (decoded[index] == (byte) 0x42) {
            ecMultiply = false;
        } else if (decoded[index] == (byte) 0x43) {
            ecMultiply = true;
        } else {
            return null;
        }
        index++;

        // Validate flags and determine whether we have a compressed key
        int flags = ((int) decoded[index++]) & 0x00ff;

        boolean lotSequence;

        if (ecMultiply) {
            if ((flags | 0x0024) != 0x24) {
                // Only bit 3 and 6 can be set for EC-multiply keys
                return null;
            }
            lotSequence = (flags & 0x0004) == 0 ? false : true;
        } else {
            if ((flags | 0x00E0) != 0xE0) {
                // Only bit 6 7 and 8 can be set for non-EC-multiply keys
                return null;
            }
            if ((flags & 0x00c0) != 0x00c0) {
                // Upper two bits must be set for non-EC-multiplied key
                return null;
            }
            lotSequence = false;
        }

        boolean compressed = (flags & 0x0020) == 0 ? false : true;

        // Fetch salt
        byte[] salt = new byte[4];
        salt[0] = decoded[index++];
        salt[1] = decoded[index++];
        salt[2] = decoded[index++];
        salt[3] = decoded[index++];

        // Fetch data
        byte[] data = new byte[32];
        System.arraycopy(decoded, index, data, 0, data.length);
        index += data.length;

        return new Bip38PrivateKey(ecMultiply, compressed, lotSequence, salt, data);
    }

    /**
     * Decrypt a BIP38 formatted private key with a passphrase.
     * <p/>
     * This is a helper function that does everything in one go. You can call the
     * individual functions if you wish to separate it into more phases.
     *
     * @throws InterruptedException
     */
    public static SecureCharSequence decrypt(String bip38PrivateKeyString, CharSequence passphrase) throws InterruptedException, AddressFormatException {
        Bip38PrivateKey bip38Key = parseBip38PrivateKey(bip38PrivateKeyString);
        if (bip38Key == null) {
            return null;
        }
        if (bip38Key.ecMultiply) {
            return decryptEcMultiply(bip38Key, passphrase);
        } else {
            byte[] stretcedKeyMaterial = bip38Stretch1(passphrase, bip38Key.salt, SCRYPT_LENGTH);
            return decryptNoEcMultiply(bip38Key, stretcedKeyMaterial);
        }
    }

    public static SecureCharSequence decryptEcMultiply(Bip38PrivateKey bip38Key, CharSequence passphrase
    ) throws InterruptedException, AddressFormatException {
        // Get 8 byte Owner Salt
        byte[] ownerEntropy = new byte[8];
        System.arraycopy(bip38Key.data, 0, ownerEntropy, 0, 8);

        byte[] ownerSalt = ownerEntropy;
        if (bip38Key.lotSequence) {
            ownerSalt = new byte[4];
            System.arraycopy(ownerEntropy, 0, ownerSalt, 0, 4);
        }

        // Stretch to get Pass Factor
        byte[] passFactor = bip38Stretch1(passphrase, ownerSalt, 32);

        if (bip38Key.lotSequence) {
            byte[] tmp = new byte[40];
            System.arraycopy(passFactor, 0, tmp, 0, 32);
            System.arraycopy(ownerEntropy, 0, tmp, 32, 8);
            //we convert to byte[] here since this can be a sha256 or Scrypt result.
            // might make sense to introduce a 32 byte scrypt type
            passFactor = Bip38Util.doubleSha256(tmp).getBytes();
        }
        ECKey key = new ECKey(new BigInteger(1, passFactor), null, true);

        // Determine Pass Point
        byte[] passPoint = key.getPubKey();
        key.clearPrivateKey();

        // Get 8 byte encrypted part 1, only first half of encrypted part 1
        // (the rest is encrypted within encryptedpart2)
        byte[] encryptedPart1 = new byte[16];
        System.arraycopy(bip38Key.data, 8, encryptedPart1, 0, 8);
        // Get 16 byte encrypted part 2
        byte[] encryptedPart2 = new byte[16];
        System.arraycopy(bip38Key.data, 16, encryptedPart2, 0, 16);

        // Second stretch to derive decryption key
        byte[] saltPlusOwnerSalt = new byte[12];
        System.arraycopy(bip38Key.salt, 0, saltPlusOwnerSalt, 0, 4);
        System.arraycopy(ownerEntropy, 0, saltPlusOwnerSalt, 4, 8);
        byte[] derived;
        try {
            derived = SCrypt.scrypt(passPoint, saltPlusOwnerSalt, 1024, 1, 1, 64);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        byte[] derivedQuater1 = new byte[16];
        System.arraycopy(derived, 0, derivedQuater1, 0, 16);
        byte[] derivedQuater2 = new byte[16];
        System.arraycopy(derived, 16, derivedQuater2, 0, 16);
        byte[] derivedHalf2 = new byte[32];
        System.arraycopy(derived, 32, derivedHalf2, 0, 32);

        Rijndael aes = new Rijndael();
        aes.makeKey(derivedHalf2, 256);

        byte[] unencryptedPart2 = new byte[16];
        aes.decrypt(encryptedPart2, unencryptedPart2);
        xorBytes(derivedQuater2, unencryptedPart2);

        // Get second half of encrypted half 1
        System.arraycopy(unencryptedPart2, 0, encryptedPart1, 8, 8);

        // Decrypt part 1
        byte[] unencryptedPart1 = new byte[16];
        aes.decrypt(encryptedPart1, unencryptedPart1);
        xorBytes(derivedQuater1, unencryptedPart1);

        // Recover seedB
        byte[] seedB = new byte[24];
        System.arraycopy(unencryptedPart1, 0, seedB, 0, 16);
        System.arraycopy(unencryptedPart2, 8, seedB, 16, 8);

        // Generate factorB
        Sha256Hash factorB;
        factorB = Bip38Util.doubleSha256(seedB);

        BigInteger privateKey = new BigInteger(1, passFactor).multiply(factorB.toPositiveBigInteger()).mod(n);
        byte[] keyBytes = new byte[32];
        byte[] bytes = privateKey.toByteArray();
        if (bytes.length <= keyBytes.length) {
            System.arraycopy(bytes, 0, keyBytes, keyBytes.length - bytes.length, bytes.length);
        } else {
            // This happens if the most significant bit is set and we have an
            // extra leading zero to avoid a negative BigInteger
            assert bytes.length == 33 && bytes[0] == 0;
            System.arraycopy(bytes, 1, keyBytes, 0, bytes.length - 1);
        }
        ECKey ecKey = new ECKey(new BigInteger(1, keyBytes), null, bip38Key.compressed);

        // Validate result

        byte[] newSalt = calculateScryptSalt(ecKey.toAddress());
        if (!Arrays.equals(bip38Key.salt, newSalt)) {
            // The passphrase is either invalid or we are on the wrong network
            return null;
        }
        DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(ecKey.getPrivKeyBytes(), ecKey.isCompressed());
        // The result is returned in SIPA format
        SecureCharSequence secureCharSequence = dumpedPrivateKey.toSecureCharSequence();
        dumpedPrivateKey.clearPrivateKey();
        ecKey.clearPrivateKey();
        return secureCharSequence;
    }

    public static SecureCharSequence decryptNoEcMultiply(Bip38PrivateKey bip38Key, byte[] stretcedKeyMaterial) throws AddressFormatException {
        // Derive Keys
        byte[] derivedHalf1 = new byte[32];
        System.arraycopy(stretcedKeyMaterial, 0, derivedHalf1, 0, 32);
        byte[] derivedHalf2 = new byte[32];
        System.arraycopy(stretcedKeyMaterial, 32, derivedHalf2, 0, 32);

        // Initialize AES key
        Rijndael aes = new Rijndael();
        aes.makeKey(derivedHalf2, 256);

        // Fetch first encrypted half
        byte[] encryptedHalf1 = new byte[16];
        System.arraycopy(bip38Key.data, 0, encryptedHalf1, 0, encryptedHalf1.length);

        // Fetch second encrypted half
        byte[] encryptedHalf2 = new byte[16];
        System.arraycopy(bip38Key.data, 16, encryptedHalf2, 0, encryptedHalf2.length);

        byte[] decryptedHalf1 = new byte[16];
        aes.decrypt(encryptedHalf1, decryptedHalf1);

        byte[] decryptedHalf2 = new byte[16];
        aes.decrypt(encryptedHalf2, decryptedHalf2);

        byte[] complete = new byte[32];
        for (int i = 0; i < 16; i++) {
            complete[i] = (byte) ((((int) decryptedHalf1[i]) & 0xFF) ^ (((int) derivedHalf1[i]) & 0xFF));
            complete[i + 16] = (byte) ((((int) decryptedHalf2[i]) & 0xFF) ^ (((int) derivedHalf1[i + 16]) & 0xFF));
        }

        // Create private key
        ECKey key = new ECKey(new BigInteger(1, complete), null, bip38Key.compressed);

        // Validate result

        byte[] newSalt = calculateScryptSalt(key.toAddress());
        if (!Arrays.equals(bip38Key.salt, newSalt)) {
            // The passphrase is either invalid or we are on the wrong network
            return null;
        }

        // Get SIPA format
        DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(key.getPrivKeyBytes(), key.isCompressed());

        SecureCharSequence secureCharSequence = dumpedPrivateKey.toSecureCharSequence();
        dumpedPrivateKey.clearPrivateKey();
        key.clearPrivateKey();
        return secureCharSequence;
    }


    /**
     * Calculate scrypt salt from Bitcoin address
     * <p/>
     * BIP38 uses a scrypt salt which depends on the Bitcoin address. This method
     * takes a Bitcoin address and calculates the BIP38 salt.
     */
    public static byte[] calculateScryptSalt(String address) {
        Sha256Hash hash = Bip38Util.doubleSha256(address.getBytes());
        return hash.firstFourBytes();
    }

    private static void xorBytes(byte[] toApply, byte[] target) {
        if (toApply.length != target.length) {
            throw new RuntimeException();
        }
        for (int i = 0; i < toApply.length; i++) {
            target[i] = (byte) (target[i] ^ toApply[i]);
        }
    }


}
