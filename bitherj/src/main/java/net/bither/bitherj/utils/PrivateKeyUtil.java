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

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.HDAccountCold;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.EncryptedPrivateKey;
import net.bither.bitherj.crypto.KeyCrypter;
import net.bither.bitherj.crypto.KeyCrypterException;
import net.bither.bitherj.crypto.KeyCrypterScrypt;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.crypto.bip38.Bip38;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.qrcode.SaltForQRCode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PrivateKeyUtil {
    private static final Logger log = LoggerFactory.getLogger(PrivateKeyUtil.class);


    public static String BACKUP_KEY_SPLIT_MUTILKEY_STRING = "\n";


    public static String getEncryptedString(ECKey ecKey) {
        String salt = "1";
        if (ecKey.getKeyCrypter() instanceof KeyCrypterScrypt) {
            KeyCrypterScrypt scrypt = (KeyCrypterScrypt) ecKey.getKeyCrypter();
            salt = Utils.bytesToHexString(scrypt.getSalt());
        }
        EncryptedPrivateKey key = ecKey.getEncryptedPrivateKey();
        return Utils.bytesToHexString(key.getEncryptedBytes()) + QRCodeUtil.QR_CODE_SPLIT + Utils
                .bytesToHexString(key.getInitialisationVector()) + QRCodeUtil.QR_CODE_SPLIT + salt;
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
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length != 3) {
            log.error("decryption: PrivateKeyFromString format error");
            return null;
        }
        byte[] temp = Utils.hexStringToByteArray(strs[2]);
        if (temp.length != KeyCrypterScrypt.SALT_LENGTH + 1 && temp.length != KeyCrypterScrypt.SALT_LENGTH) {
            log.error("decryption:  salt lenth is {} not {}", temp.length, KeyCrypterScrypt.SALT_LENGTH + 1);
            return null;
        }
        SaltForQRCode saltForQRCode = new SaltForQRCode(temp);
        byte[] salt = saltForQRCode.getSalt();
        boolean isCompressed = saltForQRCode.isCompressed();
        boolean isFromXRandom = saltForQRCode.isFromXRandom();

        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        EncryptedPrivateKey epk = new EncryptedPrivateKey(Utils.hexStringToByteArray
                (strs[1]), Utils.hexStringToByteArray(strs[0]));
        byte[] decrypted = crypter.decrypt(epk, crypter.deriveKey(password));
        
        ECKey ecKey = null;
        SecureCharSequence privateKeyText = null;
        if (needPrivteKeyText) {
            DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(decrypted, isCompressed);
            privateKeyText = dumpedPrivateKey.toSecureCharSequence();
            dumpedPrivateKey.clearPrivateKey();
        } else {
            BigInteger bigInteger = new BigInteger(1, decrypted);
            byte[] pub = ECKey.publicKeyFromPrivate(bigInteger, isCompressed);

            ecKey = new ECKey(epk, pub, crypter);
            ecKey.setFromXRandom(isFromXRandom);

        }
        Utils.wipeBytes(decrypted);
        return new DecryptedECKey(ecKey, privateKeyText);
    }

    public static String getBIP38PrivateKeyString(Address address, CharSequence password) throws
            AddressFormatException, InterruptedException {
        SecureCharSequence decrypted = getDecryptPrivateKeyString(address.getFullEncryptPrivKey()
                , password);
        String bip38 = Bip38.encryptNoEcMultiply(password, decrypted.toString());
        if (BitherjSettings.DEV_DEBUG) {
            SecureCharSequence d = Bip38.decrypt(bip38, password);
            if (d.equals(decrypted)) {
                log.info("BIP38 right");
            } else {
                throw new RuntimeException("BIP38 wrong " + d.toString() + " , " +
                        "" + decrypted.toString());
            }
        }
        decrypted.wipe();
        return bip38;
    }

    public static SecureCharSequence getDecryptPrivateKeyString(String str, CharSequence password) {
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
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length != 3) {
            log.error("change Password: PrivateKeyFromString format error");
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
            throw new KeyCrypterException("change Password, cannot be successfully decrypted after encryption so aborting wallet encryption.");
        }
        Utils.wipeBytes(decrypted);
        Utils.wipeBytes(newDecrypted);
        return Utils.bytesToHexString(encryptedPrivateKey.getEncryptedBytes())
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(encryptedPrivateKey.getInitialisationVector())
                + QRCodeUtil.QR_CODE_SPLIT + strs[2];

    }


    public static String getEncryptPrivateKeyStringFromAllAddresses() {
        String content = "";
        List<Address> privates = AddressManager.getInstance().getPrivKeyAddresses();
        for (int i = 0;
             i < privates.size();
             i++) {
            Address address = privates.get(i);
            content += address.getFullEncryptPrivKey();
            if (i < privates.size() - 1) {
                content += QRCodeUtil.QR_CODE_SPLIT;
            }
        }
        HDMKeychain keychain = AddressManager.getInstance().getHdmKeychain();
        if (keychain != null) {
            if (Utils.isEmpty(content)) {
                content += keychain.getQRCodeFullEncryptPrivKey();
            } else {
                content += QRCodeUtil.QR_CODE_SPLIT + keychain.getQRCodeFullEncryptPrivKey();
            }
        }
        HDAccount hdAccount = AddressManager.getInstance().getHDAccountHot();
        if (hdAccount != null) {
            if (Utils.isEmpty(content)) {
                content += hdAccount.getQRCodeFullEncryptPrivKey();
            } else {
                content += QRCodeUtil.QR_CODE_SPLIT + hdAccount.getQRCodeFullEncryptPrivKey();
            }
        }
        HDAccountCold hdAccountCold = AddressManager.getInstance().getHDAccountCold();
        if (hdAccountCold != null) {
            if (Utils.isEmpty(content)) {
                content += hdAccountCold.getQRCodeFullEncryptPrivKey();
            } else {
                content += QRCodeUtil.QR_CODE_SPLIT + hdAccountCold.getQRCodeFullEncryptPrivKey();
            }
        }
        return content;
    }

    public static HDMKeychain getHDMKeychain(String str, CharSequence password) {
        HDMKeychain hdmKeychain = null;
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length % 3 != 0) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        for (int i = 0;
             i < strs.length;
             i += 3) {

            if (strs[i].indexOf(QRCodeUtil.HDM_QR_CODE_FLAG) == 0) {
                try {
                    String encryptedString = strs[i].substring(1) + QRCodeUtil.QR_CODE_SPLIT + strs[i + 1]
                            + QRCodeUtil.QR_CODE_SPLIT + strs[i + 2];
                    hdmKeychain = new HDMKeychain(new EncryptedData(encryptedString)
                            , password, null);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return hdmKeychain;
    }

    public static HDAccountCold getHDAccountCold(String str, CharSequence password) {
        HDAccountCold hdAccountCold = null;
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length % 3 != 0) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        for (int i = 0;
             i < strs.length;
             i += 3) {

            if (strs[i].indexOf(QRCodeUtil.HD_QR_CODE_FLAG) == 0) {
                try {
                    String encryptedString = strs[i].substring(1) + QRCodeUtil.QR_CODE_SPLIT + strs[i + 1]
                            + QRCodeUtil.QR_CODE_SPLIT + strs[i + 2];
                    hdAccountCold = new HDAccountCold(new EncryptedData(encryptedString), password);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return hdAccountCold;
    }

    public static List<Address> getECKeysFromBackupString(String str, CharSequence password) {
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length % 3 != 0) {
            log.error("Backup: PrivateKeyFromString format error");
            return null;
        }
        ArrayList<Address> list = new ArrayList<Address>();
        for (int i = 0;
             i < strs.length;
             i += 3) {
            if (strs[i].indexOf(QRCodeUtil.HDM_QR_CODE_FLAG) == 0) {
                continue;
            }
            if (strs[i].indexOf(QRCodeUtil.HD_QR_CODE_FLAG) == 0){
                continue;
            }
            String encryptedString = strs[i] + QRCodeUtil.QR_CODE_SPLIT + strs[i + 1]
                    + QRCodeUtil.QR_CODE_SPLIT + strs[i + 2];
            ECKey key = getECKeyFromSingleString(encryptedString, password);

            if (key == null) {
                return null;
            } else {
                Address address = new Address(key.toAddress(), key.getPubKey(), encryptedString,
                        false, key.isFromXRandom());
                key.clearPrivateKey();
                list.add(address);
            }
        }
        return list;
    }

    /**
     * will release key
     *
     * @param key
     * @param password
     * @return
     */
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
        key.clearPrivateKey();
        return encryptedKey;
    }

    private static class DecryptedECKey {
        public DecryptedECKey(ECKey ecKey, SecureCharSequence privateKeyText) {
            this.ecKey = ecKey;
            this.privateKeyText = privateKeyText;
        }

        public ECKey ecKey;
        public SecureCharSequence privateKeyText;

    }

    public static boolean verifyMessage(String address, String messageText, String signatureText) {
        // Strip CRLF from signature text
        try {
            signatureText = signatureText.replaceAll("\n", "").replaceAll("\r", "");

            ECKey key = ECKey.signedMessageToKey(messageText, signatureText);
            String signAddress = key.toAddress();
            return Utils.compareString(address, signAddress);
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        }

    }

    public static String formatEncryptPrivateKeyForDb(String encryptPrivateKey) {
        if (Utils.isEmpty(encryptPrivateKey)) {
            return encryptPrivateKey;
        }
        String[] strs = QRCodeUtil.splitOfPasswordSeed(encryptPrivateKey);
        byte[] temp = Utils.hexStringToByteArray(strs[2]);
        byte[] salt = new byte[KeyCrypterScrypt.SALT_LENGTH];
        if (temp.length == KeyCrypterScrypt.SALT_LENGTH + 1) {
            System.arraycopy(temp, 1, salt, 0, salt.length);
        } else {
            salt = temp;
        }
        strs[2] = Utils.bytesToHexString(salt);
        return Utils.joinString(strs, QRCodeUtil.QR_CODE_SPLIT);

    }

    public static String getFullencryptPrivateKey(Address address, String encryptPrivKey) {
        String[] strings = QRCodeUtil.splitString(encryptPrivKey);
        byte[] salt = Utils.hexStringToByteArray(strings[2]);
        if (salt.length == KeyCrypterScrypt.SALT_LENGTH) {
            SaltForQRCode saltForQRCode = new SaltForQRCode(salt, address.isCompressed(), address.isFromXRandom());
            strings[2] = Utils.bytesToHexString(saltForQRCode.getQrCodeSalt());
        }
        return Utils.joinString(strings, QRCodeUtil.QR_CODE_SPLIT);
    }

    public static String getFullencryptHDMKeyChain(boolean isFromXRandom, String encryptPrivKey) {
        String[] strings = QRCodeUtil.splitString(encryptPrivKey);
        byte[] salt = Utils.hexStringToByteArray(strings[2]);
        if (salt.length == KeyCrypterScrypt.SALT_LENGTH) {
            SaltForQRCode saltForQRCode = new SaltForQRCode(salt, true, isFromXRandom);
            strings[2] = Utils.bytesToHexString(saltForQRCode.getQrCodeSalt()).toUpperCase();
        }
        return Utils.joinString(strings, QRCodeUtil.QR_CODE_SPLIT);
    }

    public static String getBackupPrivateKeyStr() {
        String backupString = "";
        for (Address address : AddressManager.getInstance().getPrivKeyAddresses()) {
            if (address != null) {
                PasswordSeed passwordSeed = new PasswordSeed(address.getAddress(), address.getFullEncryptPrivKey());
                backupString = backupString
                        + passwordSeed.toPasswordSeedString()
                        + BACKUP_KEY_SPLIT_MUTILKEY_STRING;

            }
        }
        HDMKeychain keychain = AddressManager.getInstance().getHdmKeychain();
        if (keychain != null) {
            try {
                if (!keychain.isInRecovery()) {
                    String address = keychain.getFirstAddressFromDb();
                    backupString += QRCodeUtil.HDM_QR_CODE_FLAG + Base58.bas58ToHexWithAddress(address)
                            + QRCodeUtil.QR_CODE_SPLIT
                            + keychain.getFullEncryptPrivKey() + BACKUP_KEY_SPLIT_MUTILKEY_STRING;
                }
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        HDAccount hdAccount = AddressManager.getInstance().getHDAccountHot();
        if (hdAccount != null) {
            try {
                String address = hdAccount.getFirstAddressFromDb();
                backupString += QRCodeUtil.HD_QR_CODE_FLAG + Base58.bas58ToHexWithAddress(address)
                        + QRCodeUtil.QR_CODE_SPLIT
                        + hdAccount.getFullEncryptPrivKey() + BACKUP_KEY_SPLIT_MUTILKEY_STRING;
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        HDAccountCold hdAccountCold = AddressManager.getInstance().getHDAccountCold();
        if (hdAccountCold != null) {
            try {
                String address = hdAccountCold.getFirstAddressFromDb();
                backupString += QRCodeUtil.HD_QR_CODE_FLAG + Base58.bas58ToHexWithAddress
                        (address) + QRCodeUtil.QR_CODE_SPLIT + hdAccountCold
                        .getFullEncryptPrivKey() + BACKUP_KEY_SPLIT_MUTILKEY_STRING;
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        return backupString;

    }

}
