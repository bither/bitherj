package net.bither.bitherj.crypto;

import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.qrcode.SaltForQRCode;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptedData {

    private static final Logger log = LoggerFactory.getLogger(EncryptedData.class);

    private byte[] encryptedData;
    private byte[] initialisationVector;
    private SaltForQRCode saltForQRCode;


    public EncryptedData(String str) {
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length != 3) {
            log.error("decryption: EncryptedData format error");
        }
        initialisationVector = Utils.hexStringToByteArray
                (strs[1]);
        encryptedData = Utils.hexStringToByteArray(strs[0]);
        byte[] saltQRCodes = Utils.hexStringToByteArray(strs[2]);
        saltForQRCode = new SaltForQRCode(saltQRCodes);
    }

    public EncryptedData(byte[] dataToEncrypt, CharSequence password) {
        this(dataToEncrypt, password, true, false);
    }

    public EncryptedData(byte[] dataToEncrypt, CharSequence password,
                         boolean isFromXRandom) {
        this(dataToEncrypt, password, true, isFromXRandom);
    }

    public EncryptedData(byte[] dataToEncrypt, CharSequence password, boolean isCompress,
                         boolean isFromXRandom) {
        KeyCrypterScrypt crypter = new KeyCrypterScrypt();
        byte[] salt = crypter.getSalt();
        EncryptedPrivateKey k = crypter.encrypt(dataToEncrypt, crypter.deriveKey(password));
        encryptedData = k.getEncryptedBytes();
        initialisationVector = k.getInitialisationVector();
        saltForQRCode = new SaltForQRCode(salt, isCompress, isFromXRandom);
    }

    public byte[] decrypt(CharSequence password) {
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(saltForQRCode.getSalt());
        return crypter.decrypt(new EncryptedPrivateKey(initialisationVector, encryptedData), crypter.deriveKey(password));
    }

    public String toEncryptedString() {
        return Utils.bytesToHexString(encryptedData).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(initialisationVector).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(saltForQRCode.getSalt()).toUpperCase();
    }

    public String toEncryptedStringForQRCode() {
        return Utils.bytesToHexString(encryptedData).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(initialisationVector).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(saltForQRCode.getQrCodeSalt()).toUpperCase();
    }

    public String toEncryptedStringForQRCode(boolean isCompress, boolean isFromXRandom) {
        SaltForQRCode newSaltForQRCode = new SaltForQRCode(saltForQRCode.getSalt(), isCompress, isFromXRandom);
        return Utils.bytesToHexString(encryptedData).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(initialisationVector).toUpperCase()
                + QRCodeUtil.QR_CODE_SPLIT + Utils.bytesToHexString(newSaltForQRCode.getQrCodeSalt()).toUpperCase();
    }

    public boolean isXRandom() {
        return saltForQRCode.isFromXRandom();
    }

    public boolean isCompressed() {
        return saltForQRCode.isCompressed();
    }

    public static String changePwd(String encryptStr, CharSequence oldPassword, CharSequence newPassword) {
        EncryptedData encrypted = new EncryptedData(encryptStr);
        return new EncryptedData(encrypted.decrypt(oldPassword), newPassword).toEncryptedString();
    }

    public static String changePwdKeepFlag(String encryptStr, CharSequence oldPassword, CharSequence newPassword) {
        EncryptedData encrypted = new EncryptedData(encryptStr);
        return new EncryptedData(encrypted.decrypt(oldPassword), newPassword, encrypted.isCompressed(), encrypted.isXRandom()).toEncryptedString();
    }
}
