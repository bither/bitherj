package net.bither.bitherj.core;

import net.bither.bitherj.api.GetHDMBIdRandomApi;
import net.bither.bitherj.api.UploadHDMBidApi;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;

import org.spongycastle.util.encoders.Base64;

import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.SignatureException;

public class HDMBId {
    private static final Logger log = LoggerFactory.getLogger(HDMBId.class);

    public final static String BITID_STRING = "bitid://hdm.bither.net/%s/password/%s/%d";
    private String address;
    private EncryptedData encryptedBitherPassword;
    private byte[] decryptedPassword;
    private long serviceRandom;


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

    public String getPreSignString() throws Exception {
        SecureRandom random = new SecureRandom();
        decryptedPassword = new byte[32];
        random.nextBytes(decryptedPassword);
        GetHDMBIdRandomApi getHDMBIdRandomApi = new GetHDMBIdRandomApi(address);
        getHDMBIdRandomApi.handleHttpGet();
        serviceRandom = getHDMBIdRandomApi.getResult();
        String message = Utils.format(BITID_STRING, address, Utils.bytesToHexString(decryptedPassword), serviceRandom);
        byte[] hash = Utils.getPreSignMessage(message);
        return Utils.bytesToHexString(hash);


    }

    public void setSignature(String signString, SecureCharSequence secureCharSequence) throws Exception {
        String message = Utils.format(BITID_STRING, address, Utils.bytesToHexString(decryptedPassword), serviceRandom);
        byte[] hash = Utils.getPreSignMessage(message);
        ECKey key = ECKey.signedMessageToKey(hash, Utils.hexStringToByteArray(signString));
        if (Utils.compareString(address, key.toAddress())) {
            throw new SignatureException();

        }
//        String signature = new String(Base64.encode(Utils.hexStringToByteArray(signString)), Charset.forName("UTF-8"));
//
//        String passwrodString = new String(Base64.encode(decryptedPassword), Charset.forName("UTF-8"));
//
//        log.info("signature:" + signature + "." + passwrodString);
        UploadHDMBidApi uploadHDMBidApi = new UploadHDMBidApi(address, Utils.hexStringToByteArray(signString), decryptedPassword);
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

    public byte[] decryptHDMBIdPassword(CharSequence password) {
        decryptedPassword = encryptedBitherPassword.decrypt(password);
        return decryptedPassword;
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
