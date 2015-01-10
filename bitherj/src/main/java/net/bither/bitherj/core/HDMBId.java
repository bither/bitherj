package net.bither.bitherj.core;

import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;

public class HDMBId {
    private String address;
    private EncryptedData encryptedBitherPassword;


    public HDMBId(String address) {
        this.address = address;
    }


    public HDMBId(String addressForBitherId, String encryptedBitherPassword) {
        this(addressForBitherId, new EncryptedData(encryptedBitherPassword));
    }


    public HDMBId(String addressForBitherId, EncryptedData encryptedBitherPassword) {
        this.address = addressForBitherId;
        this.encryptedBitherPassword = encryptedBitherPassword;
    }

    public String getPreSignString() {
        SecureRandom random = new SecureRandom();
        byte[] decryptedPassword = new byte[32];
        random.nextBytes(decryptedPassword);
        //todo get random form api and preSign hdmid
        return "";
    }

    public boolean setSignString(String signString, SecureCharSequence secureCharSequence) {
        //todo check sign and pot to api
        return true;

    }

    public String getAddress() {
        return address;
    }


    public String getEncryptedBitherPasswordString() {
        return encryptedBitherPassword.toEncryptedString();
    }

    public byte[] decryptHDMBIdPassword(CharSequence password) {
        return encryptedBitherPassword.decrypt(password);
    }

    public String decryptBitherPasswordHex(CharSequence password) {
        return Utils.bytesToHexString(decryptHDMBIdPassword(password));
    }

    public static HDMBId getHDMBidFromDb() {
        HDMBId hdmbId = AbstractDb.addressProvider.getHDMBId();
        if (Utils.isEmpty(hdmbId.getAddress()) ||
                Utils.isEmpty(hdmbId.getEncryptedBitherPasswordString())) {
            return null;
        }
        return hdmbId;
    }

}
