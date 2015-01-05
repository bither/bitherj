package net.bither.bitherj.crypto;

import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptedData {

    private static final Logger log = LoggerFactory.getLogger(EncryptedData.class);

    private byte[] encryptedData;
    private byte[] initialisationVector;
    private byte[] salt;

    public EncryptedData(String str) {
        String[] strs = QRCodeUtil.splitOfPasswordSeed(str);
        if (strs.length != 3) {
            log.error("decryption: EncryptedData format error");
        }
        initialisationVector = Utils.hexStringToByteArray
                (strs[1]);
        encryptedData = Utils.hexStringToByteArray(strs[0]);
        salt = Utils.hexStringToByteArray(strs[2]);
    }

    public EncryptedData(byte[] dataToEncrypt, CharSequence password) {
        KeyCrypterScrypt crypter = new KeyCrypterScrypt();
        salt = crypter.getSalt();
        EncryptedPrivateKey k = crypter.encrypt(dataToEncrypt, crypter.deriveKey(password));
        encryptedData = k.getEncryptedBytes();
        initialisationVector = k.getInitialisationVector();
    }

    public byte[] decrypt(CharSequence password) {
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        return crypter.decrypt(new EncryptedPrivateKey(initialisationVector, encryptedData), crypter.deriveKey(password));
    }

    public String toString() {
        //TODO to string
        return null;
    }

}
