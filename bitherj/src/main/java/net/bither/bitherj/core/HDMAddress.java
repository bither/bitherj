package net.bither.bitherj.core;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.script.ScriptBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMAddress extends Address {
    public static interface HDMFetchRemoteSignature {
        List<byte[]> getRemoteSignature(String bitherId, CharSequence password, List<byte[]> unsignHash, int index);
    }

    public static interface HDMFetchColdSignature {
        List<byte[]> getColdSignature(List<byte[]> unsignHash, int index, Tx tx);
    }


    private HDMKeychain keychain;
    private Pubs pubs;

    public HDMAddress(Pubs pubs, boolean isSyncComplete, HDMKeychain keychain){
        super(addressFromPubs(pubs), pubs.hot, pubs.index, isSyncComplete, keychain.isFromXRandom(), true);
        this.keychain = keychain;
        this.pubs = pubs;
    }

    public int getIndex(){
        return pubs.index;
    }

    public HDMKeychain getKeychain(){
        return keychain;
    }

    public void setKeychain(HDMKeychain keychain) {
        this.keychain = keychain;
    }

    public List<byte[]> formatInScript(List<TransactionSignature> signs1, List<TransactionSignature> signs2, byte[] scriptPubKey) {
        List<byte[]> result = new ArrayList<byte[]>();
        for (int i = 0; i < signs1.size(); i++) {
            List<TransactionSignature> signs = new ArrayList<TransactionSignature>(2);
            signs.add(signs1.get(i));
            signs.add(signs2.get(i));
            result.add(ScriptBuilder.createP2SHMultiSigInputScript(signs, scriptPubKey).getProgram());

        }
        return result;
    }

    public TransactionSignature signWithRemote(List<byte[]> unsignHash, CharSequence password, HDMFetchRemoteSignature delegate) {
        ArrayList<ECKey.ECDSASignature> sigs = signMyPart(unsignHash, password);
        //TODO complete the signature for remote sign
        return null;
    }

    public TransactionSignature signWithCold(List<byte[]> unsignHash, CharSequence password, Tx tx, HDMFetchColdSignature delegate) {
        ArrayList<ECKey.ECDSASignature> sigs = signMyPart(unsignHash, password);
        //TODO complete the signature for cold sign
        return null;
    }

    public ArrayList<ECKey.ECDSASignature> signMyPart(List<byte[]> unsignedHashes, CharSequence password){
        DeterministicKey key = keychain.getExternalKey(pubs.index, password);
        ArrayList<ECKey.ECDSASignature> sigs = new ArrayList<ECKey.ECDSASignature>();
        for(int i = 0; i < unsignedHashes.size(); i++){
            sigs.add(key.sign(unsignedHashes.get(i)));
        }
        key.wipe();
        return sigs;
    }

    public static final String addressFromPubs(Pubs pubs){
        //TODO multisig address generation
        return null;
    }

    @Override
    public boolean isFromXRandom() {
        return keychain.isFromXRandom();
    }

    public static final class Pubs{
        public byte[] hot;
        public byte[] cold;
        public byte[] remote;
        public int index;
    }
}
