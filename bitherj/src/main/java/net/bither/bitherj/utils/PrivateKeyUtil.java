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

package net.bither.bitherj.utils;

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedPrivateKey;
import net.bither.bitherj.crypto.KeyCrypter;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.KeyCrypterScrypt;
import net.bither.bitherj.exception.URandomNotFoundException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PrivateKeyUtil {
    private static final Logger log = LoggerFactory.getLogger(PrivateKeyUtil.class);

    public static final String QR_CODE_SPLIT = ":";

    private static final String QR_CODE_LETTER = "*";

    public static String getPrivateKeyString(ECKey ecKey) {
        String salt = "1";
        if (ecKey.getKeyCrypter() instanceof KeyCrypterScrypt) {
            KeyCrypterScrypt scrypt = (KeyCrypterScrypt) ecKey.getKeyCrypter();
            salt = Utils.bytesToHexString(scrypt.getSalt());
        }
        EncryptedPrivateKey key = ecKey.getEncryptedPrivateKey();
        return Utils.bytesToHexString(key.getEncryptedBytes()) + QR_CODE_SPLIT + Utils
                .bytesToHexString(key.getInitialisationVector()) + QR_CODE_SPLIT + salt;
    }

    public static ECKey getECKeyFromSingleString(String str, CharSequence password) {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length != 3) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));
        byte[] salt = Utils.hexStringToByteArray(strs[2]);
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        try {
            byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(password));
            byte[] pub = ECKey.publicKeyFromPrivate(new BigInteger(1, decrypted), true);
            PrivateKeyUtil.wipeDecryptedPrivateKey(decrypted);
            return new ECKey(epk, pub, crypter);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String changePassword(String str, CharSequence oldpassword, CharSequence newPassword) {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length != 3) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));
        byte[] salt = Utils.hexStringToByteArray(strs[2]);
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        try {
            byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(oldpassword));
            EncryptedPrivateKey encryptedPrivateKey = crypter.encrypt(decrypted, crypter.deriveKey(newPassword));
            PrivateKeyUtil.wipeDecryptedPrivateKey(decrypted);
            return Utils.bytesToHexString(encryptedPrivateKey.getEncryptedBytes())
                    + QR_CODE_SPLIT + Utils.bytesToHexString(encryptedPrivateKey.getInitialisationVector()) + QR_CODE_SPLIT + strs[2];
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getPrivateKeyString(String str, CharSequence password) {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length != 3) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));
        byte[] salt = Utils.hexStringToByteArray(strs[2]);
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        try {
            byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(password));
            DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(decrypted, true);
            return dumpedPrivateKey.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getPrivateKeyStringFromAllPrivateAddresses() {
        String content = "";
        List<Address> privates = AddressManager.getInstance().getPrivKeyAddresses();
        for (int i = 0;
             i < privates.size();
             i++) {
            Address address = privates.get(i);
            content += address.getEncryptPrivKey();
            if (i < privates.size() - 1) {
                content += QR_CODE_SPLIT;
            }
        }
        return content;
    }

    public static List<Address> getECKeysFromString(String str, CharSequence password) {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length % 3 != 0) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        ArrayList<Address> list = new ArrayList<Address>();
        for (int i = 0;
             i < strs.length;
             i += 3) {

            String encryptedString = strs[i] + QR_CODE_SPLIT + strs[i + 1]
                    + QR_CODE_SPLIT + strs[i + 2];
            ECKey key = getECKeyFromSingleString(encryptedString, password);

            if (key == null) {
                return null;
            } else {
                Address address = new Address(key.toAddress(), key.getPubKey(), encryptedString);
                list.add(address);
            }
        }
        return list;
    }

    public static void wipeDecryptedPrivateKey(byte[] decryted) {
        if (decryted != null) {
            Arrays.fill(decryted, (byte) 0);
        }
    }

    public static ECKey encrypt(ECKey key, CharSequence password) throws URandomNotFoundException {
        KeyCrypter scrypt = new KeyCrypterScrypt();
        KeyParameter derivedKey = scrypt.deriveKey(password);
        ECKey encryptedKey = key.encrypt(scrypt, derivedKey);

        // Check that the encrypted key can be successfully decrypted.
        // This is done as it is a critical failure if the private key cannot be decrypted successfully
        // (all bitcoin controlled by that private key is lost forever).
        // For a correctly constructed keyCrypter the encryption should always be reversible so it is just being as cautious as possible.
        if (!ECKey.encryptionIsReversible(key, encryptedKey, scrypt, derivedKey)) {
            // Abort encryption
            throw new KeyCrypterException("The key " + key.toString() + " cannot be successfully decrypted after encryption so aborting wallet encryption.");
        }

        return encryptedKey;
    }


}
