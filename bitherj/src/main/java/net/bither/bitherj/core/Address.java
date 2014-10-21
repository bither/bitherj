/*
* Copyright 2014 http://Bither.net
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package net.bither.bitherj.core;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.PasswordException;
import net.bither.bitherj.exception.TxBuilderException;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.script.ScriptChunk;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.annotation.Nonnull;


public class Address implements Comparable<Address> {
    private static final Logger log = LoggerFactory.getLogger(Address.class);

    public static final String KEY_SPLIT_STRING = ":";
    public static final String PUBLIC_KEY_FILE_NAME_SUFFIX = ".pub";

    protected String encryptPrivKey;
    protected byte[] pubKey;
    protected String address;
    protected boolean hasPrivKey;

    protected boolean syncComplete = false;
    private long mSortTime;
    private long balance = 0;
    private boolean isFromXRandom;

    public Address(String address, byte[] pubKey, long sortTime, boolean isSyncComplete,
                   boolean isFromXRandom, boolean hasPrivKey) {
        this.hasPrivKey = hasPrivKey;
        this.encryptPrivKey = null;
        this.address = address;
        this.pubKey = pubKey;
        this.mSortTime = sortTime;
        this.syncComplete = isSyncComplete;
        this.isFromXRandom = isFromXRandom;
        this.updateBalance();
    }

    public Address(String address, byte[] pubKey, String encryptString, boolean isFromXRandom) {
        this.encryptPrivKey = encryptString;
        this.address = address;
        this.pubKey = pubKey;
        this.hasPrivKey = !Utils.isEmpty(encryptString);
        this.updateBalance();
        this.isFromXRandom = isFromXRandom;
    }

    public int txCount() {
        return AbstractDb.txProvider.txCount(this.address);
    }

    public List<Tx> getRecentlyTxsWithConfirmationCntLessThan(int confirmationCnt, int limit) {
        List<Tx> txList = new ArrayList<Tx>();
        int blockNo = BlockChain.getInstance().getLastBlock().getBlockNo() - confirmationCnt + 1;
        for (Tx tx : AbstractDb.txProvider.getRecentlyTxsByAddress(this.address, blockNo, limit)) {
            txList.add(tx);
        }
        return txList;
    }


    public List<Tx> getTxs() {
        List<Tx> txs = AbstractDb.txProvider.getTxAndDetailByAddress(this.address);
        Collections.sort(txs);
        return txs;
    }

    @Override
    public int compareTo(@Nonnull Address address) {
        return -1 * Long.valueOf(getmSortTime()).compareTo(Long.valueOf(address.getmSortTime()));
    }

    public void updateBalance() {
        long balance = 0;
        List<Tx> txs = this.getTxs();

        Set<byte[]> invalidTx = new HashSet<byte[]>();
        Set<OutPoint> spentOut = new HashSet<OutPoint>();
        Set<OutPoint> unspendOut = new HashSet<OutPoint>();

        for (int i = txs.size() - 1;
             i >= 0;
             i--) {
            Set<OutPoint> spent = new HashSet<OutPoint>();
            Tx tx = txs.get(i);

            Set<byte[]> inHashes = new HashSet<byte[]>();
            for (In in : tx.getIns()) {
                spent.add(new OutPoint(in.getPrevTxHash(), in.getPrevOutSn()));
                inHashes.add(in.getPrevTxHash());
            }

            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED && (this.isIntersects(spent,
                    spentOut) || this.isIntersects(inHashes, invalidTx))) {
                invalidTx.add(tx.getTxHash());
                continue;
            }

            spentOut.addAll(spent);
            for (Out out : tx.getOuts()) {
                if (Utils.compareString(this.getAddress(), out.getOutAddress())) {
                    unspendOut.add(new OutPoint(tx.getTxHash(), out.getOutSn()));
                    balance += out.getOutValue();
                }
            }
            spent.clear();
            spent.addAll(unspendOut);
            spent.retainAll(spentOut);

            for (OutPoint o : spent) {

                Tx tx1 = AbstractDb.txProvider.getTxDetailByTxHash(o.getTxHash());
                unspendOut.remove(o);
                balance -= tx1.getOuts().get(o.getOutSn()).getOutValue();
            }
        }
        this.balance = balance;
    }

    private boolean isIntersects(Set set1, Set set2) {
        Set result = new HashSet();
        result.addAll(set1);
        result.retainAll(set2);
        return !result.isEmpty();
    }

    public long getBalance() {
        return balance;
    }

    private long getDeltaBalance() {
        long oldBalance = this.balance;
        this.updateBalance();
        return this.balance - oldBalance;
    }

    public void notificatTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        long deltaBalance = getDeltaBalance();
        AbstractApp.notificationService.notificatTx(this, tx, txNotificationType, deltaBalance);
    }

    public void setBlockHeight(List<byte[]> txHashes, int height) {
        notificatTx(null, Tx.TxNotificationType.txDoubleSpend);
    }

    public void removeTx(byte[] txHash) {
        AbstractDb.txProvider.remove(txHash);
    }

    public boolean initTxs(List<Tx> txs) {
        AbstractDb.txProvider.addTxs(txs);
        if (txs.size() > 0) {
            notificatTx(null, Tx.TxNotificationType.txFromApi);
        }
        return true;
    }


    public byte[] getPubKey() {
        return this.pubKey;
    }

    public String getAddress() {
        return this.address;
    }

    public boolean hasPrivKey() {
        return this.hasPrivKey;
    }

    public boolean isSyncComplete() {
        return this.syncComplete;
    }

    public void setSyncComplete(boolean isSyncComplete) {
        this.syncComplete = isSyncComplete;
    }

    public boolean isFromXRandom() {
        return this.isFromXRandom;
    }

    public void setFromXRandom(boolean isFromXRAndom) {
        this.isFromXRandom = isFromXRAndom;
    }


    public void savePrivateKey() throws IOException {
        String privateKeyFullFileName = Utils.format(BitherjSettings.PRIVATE_KEY_FILE_NAME,
                Utils.getPrivateDir(), getAddress());
        Utils.writeFile(this.encryptPrivKey, new File(privateKeyFullFileName));
    }

    public void savePubKey(long sortTime) throws IOException {
        if (hasPrivKey()) {
            savePubKey(Utils.getPrivateDir().getAbsolutePath(), sortTime);
        } else {
            savePubKey(Utils.getWatchOnlyDir().getAbsolutePath(), sortTime);
        }

    }

    private void savePubKey(String dir, long sortTime) throws IOException {
        this.mSortTime = sortTime;
        String watchOnlyFullFileName = Utils.format(BitherjSettings.WATCH_ONLY_FILE_NAME, dir,
                getAddress());
        String watchOnlyContent = Utils.format("%s:%s:%s%s", Utils.bytesToHexString(this.pubKey),
                getSyncCompleteString(), Long.toString(this.mSortTime), getXRandomString());
        log.debug("address content " + watchOnlyContent);
        Utils.writeFile(watchOnlyContent, new File(watchOnlyFullFileName));
    }

    public void updatePubkey() throws IOException {
        if (hasPrivKey()) {
            updatePubKey(Utils.getPrivateDir().getAbsolutePath());
        } else {
            updatePubKey(Utils.getWatchOnlyDir().getAbsolutePath());
        }
    }

    private void updatePubKey(String dir) throws IOException {
        String watchOnlyFullFileName = Utils.format(BitherjSettings.WATCH_ONLY_FILE_NAME, dir,
                getAddress());
        String watchOnlyContent = Utils.format("%s:%s:%s%s", Utils.bytesToHexString(this.pubKey),
                getSyncCompleteString(), Long.toString(this.mSortTime), getXRandomString());
        log.debug("address content " + watchOnlyContent);
        Utils.writeFile(watchOnlyContent, new File(watchOnlyFullFileName));
    }


    private String getSyncCompleteString() {
        return isSyncComplete() ? "1" : "0";
    }

    private String getXRandomString() {
        return isFromXRandom() ? ":" + QRCodeUtil.XRANDOM_FLAG : "";
    }


    public void removeWatchOnly() {
        String watchOnlyFullFileName = Utils.format(BitherjSettings.WATCH_ONLY_FILE_NAME,
                Utils.getWatchOnlyDir(), getAddress());
        Utils.removeFile(new File(watchOnlyFullFileName));

    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Address) {
            Address other = (Address) o;
            return Utils.compareString(getAddress(), other.getAddress());
        }
        return false;
    }

    public long getmSortTime() {
        return mSortTime;
    }

    public String getEncryptPrivKey() {
        if (this.hasPrivKey) {
            if (Utils.isEmpty(this.encryptPrivKey)) {
                String privateKeyFullFileName = Utils.format(BitherjSettings
                        .PRIVATE_KEY_FILE_NAME, Utils.getPrivateDir(), getAddress());
                this.encryptPrivKey = Utils.readFile(new File(privateKeyFullFileName));
                if (this.encryptPrivKey == null) {
                    //todo backup?
                }
                //dispaly new version qrcode
                this.encryptPrivKey = QRCodeUtil.getNewVersionEncryptPrivKey(this.encryptPrivKey);
            }
            return this.encryptPrivKey;
        } else {
            return null;
        }
    }

    public void setEncryptPrivKey(String encryptPrivKey) {
        this.encryptPrivKey = encryptPrivKey;
        this.hasPrivKey = true;
    }

    public Tx buildTx(List<Long> amounts, List<String> addresses) throws TxBuilderException {
        return TxBuilder.getInstance().buildTx(this, amounts, addresses);
    }

    public Tx buildTx(long amount, String address) throws TxBuilderException {
        List<Long> amounts = new ArrayList<Long>();
        amounts.add(amount);
        List<String> addresses = new ArrayList<String>();
        addresses.add(address);
        return buildTx(amounts, addresses);
    }

    public List<Tx> getRecentlyTxs(int confirmationCnt, int limit) {
        int blockNo = BlockChain.getInstance().lastBlock.getBlockNo() - confirmationCnt + 1;
        return AbstractDb.txProvider.getRecentlyTxsByAddress(this.address, blockNo, limit);
    }

    public String getShortAddress() {
        return Utils.shortenAddress(getAddress());
    }

    public List<String> signStrHashes(List<String> unsignedInHashes, CharSequence passphrase) {
        ArrayList<byte[]> hashes = new ArrayList<byte[]>();
        for (String h : unsignedInHashes) {
            hashes.add(Utils.hexStringToByteArray(h));
        }
        List<byte[]> resultHashes = signHashes(hashes, passphrase);
        ArrayList<String> resultStrs = new ArrayList<String>();
        for (byte[] h : resultHashes) {
            resultStrs.add(Utils.bytesToHexString(h));
        }
        return resultStrs;
    }

    public List<byte[]> signHashes(List<byte[]> unsignedInHashes, CharSequence passphrase) throws
            PasswordException {
        ECKey key = PrivateKeyUtil.getECKeyFromSingleString(this.getEncryptPrivKey(), passphrase);
        if (key == null) {
            throw new PasswordException("do not decrypt eckey");
        }
        KeyParameter assKey = key.getKeyCrypter().deriveKey(passphrase);
        List<byte[]> result = new ArrayList<byte[]>();
        for (byte[] unsignedInHash : unsignedInHashes) {
            TransactionSignature signature = new TransactionSignature(key.sign(unsignedInHash,
                    assKey), TransactionSignature.SigHash.ALL, false);
            result.add(ScriptBuilder.createInputScript(signature, key).getProgram());
        }
        return result;
    }

    public void signTx(Tx tx, CharSequence passphrase) {
        tx.signWithSignatures(this.signHashes(tx.getUnsignedInHashes(), passphrase));
    }

    public void completeInSignature(List<In> ins) {
        AbstractDb.txProvider.completeInSignature(ins);
    }

    public int needCompleteInSignature() {
        return AbstractDb.txProvider.needCompleteInSignature(this.address);
    }

    public boolean checkRValues() {
        //TODO checkRValueForAddress
        return new Random().nextInt() % 2 == 0;
    }

    public boolean checkRValuesForTx(Tx tx) {
       HashSet<byte[]> rs = new HashSet<byte[]>();
        for (In in : tx.getIns()) {
            Script script = new Script(in.getInSignature());
            for (ScriptChunk chunk : script.getChunks()) {
                if (chunk.isPushData() && chunk.opcode == 71) {
                    TransactionSignature signature = TransactionSignature.decodeFromBitcoin(chunk
                            .data, false);
                    rs.add(signature.r.toByteArray());
                }
            }
        }

        //TODO checkRValueForTx
        return new Random().nextInt() % 2 == 0;
    }
}
