package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HDMAddress extends Address {
    public static interface HDMFetchOtherSignatureDelegate {
        List<TransactionSignature> getOtherSignature(int addressIndex, CharSequence password,
                                                     List<byte[]> unsignHash, Tx tx);
    }

    private HDMKeychain keychain;
    private Pubs pubs;

    public HDMAddress(Pubs pubs, HDMKeychain keychain, boolean isSyncComplete) {
        this(pubs, pubs.getAddress(), isSyncComplete, keychain);
    }

    public HDMAddress(Pubs pubs, String address, boolean isSyncComplete, HDMKeychain keychain) {
        super(address, pubs.getMultiSigScript().getProgram(), pubs.index, isSyncComplete, true,
                false, null);
        this.keychain = keychain;
        this.pubs = pubs;
    }

    public int getIndex() {
        return pubs.index;
    }

    public HDMKeychain getKeychain() {
        return keychain;
    }

    public void setKeychain(HDMKeychain keychain) {
        this.keychain = keychain;
    }

    @Override
    public List<byte[]> signHashes(List<byte[]> unsignedInHashes, CharSequence passphrase) throws
            PasswordException {
        throw new RuntimeException("hdm address can't sign transactions all by self");
    }

    public void signTx(Tx tx, CharSequence passphrase, HDMFetchOtherSignatureDelegate delegate) {
        tx.signWithSignatures(this.signWithOther(tx.getUnsignedInHashesForHDM(getPubKey()),
                passphrase, tx, delegate));
    }

    public void signTx(Tx tx, CharSequence password, HDMFetchOtherSignatureDelegate delegateCold,
                       HDMFetchOtherSignatureDelegate delegateRemote) {
        List<byte[]> unsigns = tx.getUnsignedInHashesForHDM(getPubKey());
        List<TransactionSignature> coldSigs = delegateCold.getOtherSignature(getIndex(),
                password, unsigns, tx);
        List<TransactionSignature> remoteSigs = delegateRemote.getOtherSignature(getIndex(),
                password, unsigns, tx);
        assert coldSigs.size() == remoteSigs.size() && coldSigs.size() == unsigns.size();
        List<byte[]> joined = formatInScript(coldSigs, remoteSigs, getPubKey());
        tx.signWithSignatures(joined);
    }

    public List<byte[]> signWithOther(List<byte[]> unsignHash, CharSequence password, Tx tx,
                                      HDMFetchOtherSignatureDelegate delegate) {
        ArrayList<TransactionSignature> hotSigs = signMyPart(unsignHash, password);
        List<TransactionSignature> otherSigs = delegate.getOtherSignature(getIndex(), password,
                unsignHash, tx);
        assert hotSigs.size() == otherSigs.size() && hotSigs.size() == unsignHash.size();
        return formatInScript(hotSigs, otherSigs, pubs.getMultiSigScript().getProgram());
    }

    public ArrayList<TransactionSignature> signMyPart(List<byte[]> unsignedHashes,
                                                      CharSequence password) {
        if (isInRecovery()) {
            throw new AssertionError("recovery hdm address can not sign");
        }
        DeterministicKey key = keychain.getExternalKey(pubs.index, password);
        ArrayList<TransactionSignature> sigs = new ArrayList<TransactionSignature>();
        for (int i = 0;
             i < unsignedHashes.size();
             i++) {
            TransactionSignature transactionSignature = new TransactionSignature(key.sign
                    (unsignedHashes.get(i)), TransactionSignature.SigHash.ALL, false);
            sigs.add(transactionSignature);
        }
        key.wipe();
        return sigs;
    }

    public String signMessage(String msg, CharSequence password) {
        DeterministicKey key = keychain.getExternalKey(pubs.index, password);
        String result = key.signMessage(msg);
        key.clearPrivateKey();
        return result;
    }

    @Override
    public String getFullEncryptPrivKey() {
        throw new RuntimeException("hdm address can't get encrypted private key");
    }

    public byte[] getPubCold() {
        return pubs.cold;
    }

    public byte[] getPubHot() {
        return pubs.hot;
    }

    public byte[] getPubRemote() {
        return pubs.remote;
    }

    public static List<byte[]> formatInScript(List<TransactionSignature> signs1,
                                              List<TransactionSignature> signs2,
                                              byte[] scriptPubKey) {
        List<byte[]> result = new ArrayList<byte[]>();
        for (int i = 0;
             i < signs1.size();
             i++) {
            List<TransactionSignature> signs = new ArrayList<TransactionSignature>(2);
            signs.add(signs1.get(i));
            signs.add(signs2.get(i));
            result.add(ScriptBuilder.createP2SHMultiSigInputScript(signs,
                    scriptPubKey).getProgram());
        }
        return result;
    }

    public List<byte[]> getPubs() {
        ArrayList<byte[]> list = new ArrayList<byte[]>();
        list.add(pubs.hot);
        list.add(pubs.cold);
        list.add(pubs.remote);
        return list;
    }

    @Override
    public void updateSyncComplete() {
        AbstractDb.addressProvider.syncComplete(keychain.getHdSeedId(), pubs.index);
    }

    @Override
    public boolean isFromXRandom() {
        return keychain.isFromXRandom();
    }

    @Override
    public boolean isHDM() {
        return true;
    }

    public boolean isInRecovery() {
        return getKeychain().isInRecovery();
    }

    public static final class Pubs {
        public static final byte[] EmptyBytes = new byte[]{0};

        public byte[] hot;
        public byte[] cold;
        public byte[] remote;
        public int index;

        public Pubs(byte[] hot, byte[] cold, byte[] remote, int index) {
            this.hot = hot;
            this.cold = cold;
            this.remote = remote;
            this.index = index;
        }

        public Pubs() {
        }

        public Script getMultiSigScript() {
            assert isCompleted();
            return ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(hot, cold, remote));
        }

        public boolean isCompleted() {
            return hasHot() && hasCold() && hasRemote();
        }

        public boolean hasHot() {
            return hot != null && !Arrays.equals(hot, EmptyBytes);
        }

        public boolean hasCold() {
            return cold != null && !Arrays.equals(cold, EmptyBytes);
        }

        public boolean hasRemote() {
            return remote != null && !Arrays.equals(remote, EmptyBytes);
        }

        public String getAddress() {
            return Utils.toP2SHAddress(Utils.sha256hash160(getMultiSigScript().getProgram()));
        }
    }

}
