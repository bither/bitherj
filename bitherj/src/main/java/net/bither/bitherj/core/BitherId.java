package net.bither.bitherj.core;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;

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

    public BitherId(DecryptedBitherId bitherId, CharSequence password){
        this(bitherId.getBitherId(), bitherId.getDecryptedPassword(), password);
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

    public DecryptedBitherId decrypt(CharSequence password){
        return new DecryptedBitherId(getBitherId(), decryptBitherPassword(password), null);
    }

    public static final class DecryptedBitherId{
        private String bitherId;
        private byte[] decryptedPassword;
        private String signature;

        // From QR
        public DecryptedBitherId(String qr){
            //TODO qr code decrypted bither id
        }

        // Generat New DecryptedBitherId
        public DecryptedBitherId(SecureRandom random, HDMKeychain keychain, CharSequence password) throws MnemonicException.MnemonicLengthException {
            byte[] decryptedPassword = new byte[32];
            random.nextBytes(decryptedPassword);
            DeterministicKey key = keychain.getExternalKey(0, password);
            bitherId = Utils.toAddress(key.getPubKeyHash());
            signature = key.signMessage(Utils.bytesToHexString(decryptedPassword));
        }

        public DecryptedBitherId(String addressForBitherId, byte[] decryptedPassword, String signature){
            this.bitherId = addressForBitherId;
            this.decryptedPassword = decryptedPassword;
            this.signature = signature;
        }

        public BitherId encrypt(CharSequence password){
            return new BitherId(this, password);
        }


        public String getBitherId() {
            return bitherId;
        }

        public byte[] getDecryptedPassword() {
            return decryptedPassword;
        }

        public String getSignature() {
            return signature;
        }

        public String toQr(){
            // TODO decrypted bither id to qr
            return null;
        }
    }
}
