package net.bither.bitherj.core;

import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMAddress extends Address {
    public static interface HDMFetchRemoteSignature {
        List<byte[]> getRemoteSignature(CharSequence password, List<byte[]> unsignHash, int index);
    }

    public static interface HDMFetchColdSignature {
        List<byte[]> getColdSignature(List<byte[]> unsignHash, int index, Tx tx);
    }

    private HDMKeychain keychain;
    private Pubs pubs;

    public HDMAddress(Pubs pubs, boolean isSyncComplete, HDMKeychain keychain){
        super(addressFromPubs(pubs), pubs.getScriptPubKey(), pubs.index, isSyncComplete, true, true);
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
        ArrayList<TransactionSignature> hotSigs = signMyPart(unsignHash, password);
        //TODO complete the signature for remote sign
        return null;
    }

    public TransactionSignature signWithCold(List<byte[]> unsignHash, CharSequence password, Tx tx, HDMFetchColdSignature delegate) {
        ArrayList<TransactionSignature> hotSigs = signMyPart(unsignHash, password);
        //TODO complete the signature for cold sign
        return null;
    }

    public ArrayList<TransactionSignature> signMyPart(List<byte[]> unsignedHashes, CharSequence password){
        DeterministicKey key = keychain.getExternalKey(pubs.index, password);
        ArrayList<TransactionSignature> sigs = new ArrayList<TransactionSignature>();
        for(int i = 0; i < unsignedHashes.size(); i++){
            new TransactionSignature(key.sign(unsignedHashes.get(i)), TransactionSignature.SigHash.ALL, false);
        }
        key.wipe();
        return sigs;
    }

    public static final String addressFromPubs(Pubs pubs){
        return Utils.toP2SHAddress(pubs.getMultiSigScript().getPubKeyHash());
    }

    public byte[] getPubCold(){
        return pubs.cold;
    }

    public byte[] getPubHot(){
        return pubs.hot;
    }

    public byte[] getPubRemote(){
        return pubs.remote;
    }

    public List<byte[]> getPubs(){
        ArrayList<byte[]> list = new ArrayList<byte[]>();
        list.add(pubs.hot);
        list.add(pubs.cold);
        list.add(pubs.remote);
        return list;
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
        public Script getMultiSigScript(){
            return ScriptBuilder.createMultiSigOutputScript(2,Arrays.asList(
                    new ECKey(null, hot),
                    new ECKey(null, cold),
                    new ECKey(null, remote)));
        }

        public byte[] getScriptPubKey(){
            return getMultiSigScript().getPubKey();
        }
    }
}
