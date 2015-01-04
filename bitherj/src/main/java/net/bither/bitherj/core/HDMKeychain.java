package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.db.AbstractDb;

import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMKeychain {
    private int hdKeyId;
    private String bitherId;
    private String encryptSeed;
    private String encryptBitherPassword;

    public int getHdKeyId() {
        return hdKeyId;
    }

    public String getBitherId() {
        return bitherId;
    }

    public String getEncryptSeed() {
        return encryptSeed;
    }

    public String getEncryptBitherPassword() {
        return encryptBitherPassword;
    }

    public static interface HDMFetchRemotePublicKeys{
        List<byte[]> getRemotePublicKeys(String bitherId, CharSequence password, List<byte[]> pubHot, List<byte[]> pubCold);
    }

    public static interface HDMFetchRemoteAddresses {
        List<List<byte[]>> getRemoteExistsPublicKeys(String bitherId, CharSequence password);
    }

    public static interface HDMFetchRemoteSignature {
        List<byte[]> getRemoteSignature(String bitherId, CharSequence password, List<byte[]> unsignHash, int index);
    }

    public static interface HDMFetchColdSignature {
        List<byte[]> getColdSignature(List<byte[]> unsignHash, int index, Tx tx);
    }

    public HDMKeychain(SecureRandom random, CharSequence password, String bitherId, CharSequence bitherPassword) {

    }

    public HDMKeychain(int hdKeyId, String encryptSeed, String bitherId, String encryptBitherPassword) {
        this.hdKeyId = hdKeyId;
        this.encryptSeed = encryptSeed;
        this.bitherId = bitherId;
        this.encryptBitherPassword = encryptBitherPassword;
    }

    public HDMKeychain(String encryptSeed, String bitherId, String encryptBitherPassword, CharSequence password, HDMFetchRemoteAddresses fetchDelegate) {
        this.hdKeyId = AbstractDb.addressProvider.addHDKey(encryptSeed, bitherId, encryptBitherPassword);
        this.encryptSeed = encryptSeed;
        this.bitherId = bitherId;
        this.encryptBitherPassword = encryptBitherPassword;
    }

    public List<HDMAddress> createAddresses(int count, CharSequence password, byte[] masterPub, HDMFetchRemotePublicKeys fetchDelegate) {
        return null;
    }

    public List<HDMAddress> getAddresses() {
        return null;
    }

    public TransactionSignature signWithRemote(List<byte[]> unsignHash, int index, CharSequence password, HDMFetchRemoteSignature delegate) {
        return null;
    }

    public TransactionSignature signWithCold(List<byte[]> unsignHash, int index, CharSequence password, Tx tx, HDMFetchColdSignature delegate) {
        return null;
    }
}
