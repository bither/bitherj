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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PrivateKeyUtil {
    private static final Logger log = LoggerFactory.getLogger(PrivateKeyUtil.class);
    private static final int IS_COMPRESSED_FLAG = 1;
    private static final int IS_FROMXRANDOM_FLAG = 2;

    public static final String QR_CODE_SPLIT = ":";

    private static final String QR_CODE_LETTER = "*";

    public static String getPrivateKeyString(ECKey ecKey) {
        String salt = "1";
        if (ecKey.getKeyCrypter() instanceof KeyCrypterScrypt) {
            KeyCrypterScrypt scrypt = (KeyCrypterScrypt) ecKey.getKeyCrypter();
            byte[] saltBytes = new byte[KeyCrypterScrypt.SALT_LENGTH + 1];
            int flag = 0;
            if (ecKey.isCompressed()) {
                flag += IS_COMPRESSED_FLAG;
            }
            if (ecKey.isFromXRandom()) {
                flag += IS_FROMXRANDOM_FLAG;
            }
            saltBytes[0] = (byte) flag;
            System.arraycopy(scrypt.getSalt(), 0, saltBytes, 1, scrypt.getSalt().length);
            salt = Utils.bytesToHexString(saltBytes);
        }
        EncryptedPrivateKey key = ecKey.getEncryptedPrivateKey();
        return Utils.bytesToHexString(key.getEncryptedBytes()) + QR_CODE_SPLIT + Utils
                .bytesToHexString(key.getInitialisationVector()) + QR_CODE_SPLIT + salt;
    }

    public static ECKey getECKeyFromSingleString(String str, CharSequence password) {
        try {
            DecryptedECKey decryptedECKey = decryptionECKey(str, password, false);
            if (decryptedECKey != null && decryptedECKey.ecKey != null) {
                return decryptedECKey.ecKey;
            } else {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static DecryptedECKey decryptionECKey(String str, CharSequence password, boolean needPrivteKeyText) throws Exception {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length != 3) {
            log.error("decryption: PrivateKeyFromString format error");
            return null;
        }
        byte[] temp = Utils.hexStringToByteArray(strs[2]);
        if (temp.length != KeyCrypterScrypt.SALT_LENGTH + 1 && temp.length != KeyCrypterScrypt.SALT_LENGTH) {
            log.error("decryption:  salt lenth is {} not {}", temp.length, KeyCrypterScrypt.SALT_LENGTH + 1);
            return null;
        }
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        boolean isCompressed = true;
        boolean isFromXRandom = false;
        if (temp.length == KeyCrypterScrypt.SALT_LENGTH) {
            salt = temp;
        } else {
            System.arraycopy(temp, 1, salt, 0, salt.length);
            isCompressed = (((int) temp[0]) & IS_COMPRESSED_FLAG) == IS_COMPRESSED_FLAG;
            isFromXRandom = (((int) temp[0]) & IS_FROMXRANDOM_FLAG) == IS_FROMXRANDOM_FLAG;
        }
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));
        byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(password));
        ECKey ecKey = null;
        String privateKeyText = null;
        if (needPrivteKeyText) {
            DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(decrypted, true);
            privateKeyText = dumpedPrivateKey.toString();
        } else {
            byte[] pub = ECKey.publicKeyFromPrivate(new BigInteger(1, decrypted), isCompressed);
            ecKey = new ECKey(epk, pub, crypter);
            ecKey.setFromXRandom(isFromXRandom);
        }
        PrivateKeyUtil.wipeDecryptedPrivateKey(decrypted);
        return new DecryptedECKey(ecKey, privateKeyText);

    }

    public static String getPrivateKeyString(String str, CharSequence password) {
        try {

            DecryptedECKey decryptedECKey = decryptionECKey(str, password, true);
            if (decryptedECKey != null && decryptedECKey.privateKeyText != null) {
                return decryptedECKey.privateKeyText;
            } else {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String changePassword(String str, CharSequence oldpassword, CharSequence newPassword) {
        String[] strs = str.split(QR_CODE_SPLIT);
        if (strs.length != 3) {
            log.error("changePassword: PrivateKeyFromString format error");
            return null;
        }

        byte[] temp = Utils.hexStringToByteArray(strs[2]);
        if (temp.length != KeyCrypterScrypt.SALT_LENGTH + 1 && temp.length != KeyCrypterScrypt.SALT_LENGTH) {
            log.error("decryption:  salt lenth is {} not {}", temp.length, KeyCrypterScrypt.SALT_LENGTH + 1);
            return null;
        }
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        if (temp.length == KeyCrypterScrypt.SALT_LENGTH) {
            salt = temp;
        } else {
            System.arraycopy(temp, 1, salt, 0, salt.length);
        }
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));

        byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(oldpassword));
        EncryptedPrivateKey encryptedPrivateKey = crypter.encrypt(decrypted, crypter.deriveKey(newPassword));
        byte[] newDecrypted = crypter.decrypt(encryptedPrivateKey, crypter.deriveKey(newPassword));
        if (!Arrays.equals(decrypted, newDecrypted)) {
            throw new KeyCrypterException("changePassword, cannot be successfully decrypted after encryption so aborting wallet encryption.");
        }
        PrivateKeyUtil.wipeDecryptedPrivateKey(decrypted);
        PrivateKeyUtil.wipeDecryptedPrivateKey(newDecrypted);
        return Utils.bytesToHexString(encryptedPrivateKey.getEncryptedBytes())
                + QR_CODE_SPLIT + Utils.bytesToHexString(encryptedPrivateKey.getInitialisationVector()) + QR_CODE_SPLIT + strs[2];

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

    public static ECKey encrypt(ECKey key, CharSequence password) {
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

    public static class DecryptedECKey {
        public DecryptedECKey(ECKey ecKey, String privateKeyText) {
            this.ecKey = ecKey;
            this.privateKeyText = privateKeyText;
        }

        public ECKey ecKey;
        public String privateKeyText;
    }

}
