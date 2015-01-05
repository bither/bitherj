package net.bither.bitherj.crypto;

/**
 * Created by songchenwen on 15/1/4.
 */
public class EncryptedData {
    private byte[] encryptedData;
    private byte[] initialisationVector;
    private byte[] salt;

    public EncryptedData(String str){
        //TODO from encrypted string
    }

    public EncryptedData(byte[] dataToEncrypt, CharSequence password){
        KeyCrypterScrypt crypter = new KeyCrypterScrypt();
        salt = crypter.getSalt();
        EncryptedPrivateKey k = crypter.encrypt(dataToEncrypt, crypter.deriveKey(password));
        encryptedData = k.getEncryptedBytes();
        initialisationVector = k.getInitialisationVector();
    }

    public byte[] decrypt(CharSequence password){
        KeyCrypterScrypt crypter = new KeyCrypterScrypt(salt);
        return crypter.decrypt(new EncryptedPrivateKey(initialisationVector, encryptedData), crypter.deriveKey(password));
    }

    public String toString(){
        //TODO to string
        return null;
    }

}
