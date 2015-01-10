package net.bither.bitherj.core;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.api.GetHDMBIdRandomApi;
import net.bither.bitherj.api.UploadHDMBidApi;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Base64;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;
import java.security.SignatureException;

public class HDMBId {

    private final String BITID_STRING = "bitid://id.bither.net/%s/password/%s/%d";
    private String address;
    private EncryptedData encryptedBitherPassword;
    private byte[] decryptedPassword;
    private int serviceRandom;


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
        try {
            SecureRandom random = new SecureRandom();
            decryptedPassword = new byte[32];
            random.nextBytes(decryptedPassword);
            GetHDMBIdRandomApi getHDMBIdRandomApi = new GetHDMBIdRandomApi();
            getHDMBIdRandomApi.handleHttpGet();
            serviceRandom = getHDMBIdRandomApi.getResult();

            String message = Utils.format(BITID_STRING, address, Utils.bytesToHexString(decryptedPassword), serviceRandom);
            byte[] hash = Utils.getPreSignMessage(message);
            return Utils.bytesToHexString(hash);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public void setSignature(String signString, SecureCharSequence secureCharSequence) throws Exception {
        String message = Utils.format(BITID_STRING, address, Utils.bytesToHexString(decryptedPassword), serviceRandom);
        byte[] hash = Utils.getPreSignMessage(message);
        ECKey key = ECKey.signedMessageToKey(hash, Utils.hexStringToByteArray(signString));
        if (Utils.compareString(address, key.toAddress())) {
            throw new SignatureException();

        }
        String signature = Base64.encodeToString(Utils.hexStringToByteArray(signString), Base64.URL_SAFE);
        String passwrodString = Base64.encodeToString(decryptedPassword, Base64.URL_SAFE);
        UploadHDMBidApi uploadHDMBidApi = new UploadHDMBidApi(address, signature, passwrodString);
        uploadHDMBidApi.handleHttpPost();
        String str = uploadHDMBidApi.getResult();
        encryptedBitherPassword = new EncryptedData(decryptedPassword, secureCharSequence);
        AbstractDb.addressProvider.addHDMBId(HDMBId.this);


    }

    public String getAddress() {
        return address;
    }


    public String getEncryptedBitherPasswordString() {
        return encryptedBitherPassword.toEncryptedString();
    }

    public void decryptHDMBIdPassword(CharSequence password) {
        decryptedPassword = encryptedBitherPassword.decrypt(password);
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
