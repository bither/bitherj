package net.bither.bitherj.core;

import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

public class BitherId {
    private String bitherId;
    private EncryptedData encryptedBitherPassword;

    public static final BitherId instance(){
        String address = AbstractDb.addressProvider.getBitherId();
        String password = AbstractDb.addressProvider.getBitherEncryptPassword();
        if(Utils.isEmpty(address) ||
                Utils.isEmpty(password)){
            return null;
        }
        return new BitherId(address, password);
    }

    public BitherId(String addressForBiterId, String decryptedBitherPassword, CharSequence password){
        this(addressForBiterId, new EncryptedData(Utils.hexStringToByteArray(decryptedBitherPassword), password));
    }
    public BitherId(String addressForBiterId, byte[] decryptedBitherPassword, CharSequence password){
        this(addressForBiterId, new EncryptedData(decryptedBitherPassword, password));
    }

    public BitherId(String addressForBitherId, String encryptedBitherPassword){
        this(addressForBitherId, new EncryptedData(encryptedBitherPassword));
    }

    public BitherId(String addressForBitherId, EncryptedData encryptedBitherPassword){
        this.bitherId = addressForBitherId;
        this.encryptedBitherPassword = encryptedBitherPassword;
    }

    public String getBitherId() {
        return bitherId;
    }

    public EncryptedData getEncryptBitherPassword() {
        return encryptedBitherPassword;
    }

    public String getEncryptedBitherPasswordString(){
        return  encryptedBitherPassword.toEncryptedString();
    }

    public byte[] decryptBitherPassword(CharSequence password){
        return encryptedBitherPassword.decrypt(password);
    }

    public String decryptBitherPasswordHex(CharSequence password){
        return Utils.bytesToHexString(decryptBitherPassword(password));
    }
}
