/*
 *
 *  Copyright 2014 http://Bither.net
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * /
 */

package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.script.ScriptBuilder;

import java.util.ArrayList;
import java.util.List;

public class DesktopHDMAddress extends Address {
    public static interface HDMFetchOtherSignatureDelegate {
        List<TransactionSignature> getOtherSignature(int addressIndex, CharSequence password,
                                                     List<byte[]> unsignHash, Tx tx);
    }

    private DesktopHDMKeychain keychain;
    private HDMAddress.Pubs pubs;


    private AbstractHD.PathType pathType;


    private boolean isIssued;

    public DesktopHDMAddress(HDMAddress.Pubs pubs, AbstractHD.PathType pathType, DesktopHDMKeychain keychain, boolean isSyncComplete) {
        this(pubs, pubs.getAddress(), pathType, false, isSyncComplete, keychain);
    }

    public DesktopHDMAddress(HDMAddress.Pubs pubs, String address, AbstractHD.PathType pathType, boolean isIssued, boolean isSyncComplete, DesktopHDMKeychain keychain) {
        super(address, pubs.getMultiSigScript().getProgram(), pubs.index, isSyncComplete, true,
                false, null);
        this.isIssued = isIssued;
        this.keychain = keychain;
        this.pubs = pubs;
        this.pathType = pathType;
    }

    public AbstractHD.PathType getPathType() {
        return pathType;
    }

    public void setPathType(AbstractHD.PathType pathType) {
        this.pathType = pathType;
    }

    public boolean isIssued() {
        return isIssued;
    }

    public void setIssued(boolean isIssued) {
        this.isIssued = isIssued;
    }

    public int getIndex() {
        return pubs.index;
    }

    public DesktopHDMKeychain getKeychain() {
        return keychain;
    }

    public void setKeychain(DesktopHDMKeychain keychain) {
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


}
