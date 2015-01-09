package net.bither.bitherj.core;

import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.mnemonic.MnemonicException;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import java.security.SecureRandom;

public class HDMBId {
    private String address;
    private EncryptedData encryptedBitherPassword;

    public static final HDMBId instance() {
        HDMBId hdmbId = AbstractDb.addressProvider.getHDMBId();
        if (Utils.isEmpty(hdmbId.getAddress()) ||
                Utils.isEmpty(hdmbId.getEncryptedBitherPasswordString())) {
            return null;
        }
        return hdmbId;
    }

    public HDMBId(String addressForBitherId, String encryptedBitherPassword) {
        this(addressForBitherId, new EncryptedData(encryptedBitherPassword));
    }

    public HDMBId(DecryptedBitherId bitherId, CharSequence password) {
        this(bitherId.getBitherId(), bitherId.getDecryptedPassword(), password);
    }

    public HDMBId(String addressForBiterId, String decryptedBitherPassword, CharSequence password) {
        this(addressForBiterId, new EncryptedData(Utils.hexStringToByteArray(decryptedBitherPassword), password));
    }

    public HDMBId(String addressForBiterId, byte[] decryptedBitherPassword, CharSequence password) {
        this(addressForBiterId, new EncryptedData(decryptedBitherPassword, password));
    }

    public HDMBId(String addressForBitherId, EncryptedData encryptedBitherPassword) {
        this.address = addressForBitherId;
        this.encryptedBitherPassword = encryptedBitherPassword;
    }

    public String getAddress() {
        return address;
    }

    public EncryptedData getEncryptBitherPassword() {
        return encryptedBitherPassword;
    }

    public String getEncryptedBitherPasswordString() {
        return encryptedBitherPassword.toEncryptedString();
    }

    public byte[] decryptBitherPassword(CharSequence password) {
        return encryptedBitherPassword.decrypt(password);
    }

    public String decryptBitherPasswordHex(CharSequence password) {
        return Utils.bytesToHexString(decryptBitherPassword(password));
    }

    public DecryptedBitherId decrypt(CharSequence password) {
        return new DecryptedBitherId(getAddress(), decryptBitherPassword(password), null);
    }

    public static final class DecryptedBitherId {
        private String bitherId;
        private byte[] decryptedPassword;
        private String signature;

        // From QR
        public DecryptedBitherId(String qr) {
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

        public DecryptedBitherId(String addressForBitherId, byte[] decryptedPassword, String signature) {
            this.bitherId = addressForBitherId;
            this.decryptedPassword = decryptedPassword;
            this.signature = signature;
        }

        public HDMBId encrypt(CharSequence password) {
            return new HDMBId(this, password);
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

        public String toQr() {
            // TODO decrypted bither id to qr
            return null;
        }
    }
}
