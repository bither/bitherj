package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;

import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMKeychain {
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

    public HDMKeychain(int hdKeyId) {

    }

    public HDMKeychain(String encryptSeed, String bitherId, String encryptBitherPassword, CharSequence password, HDMFetchRemoteAddresses fetchDelegate) {

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
