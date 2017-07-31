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
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;


public class Address implements Comparable<Address> {

    public static int VANITY_LEN_NO_EXSITS = -1;

    private static final Logger log = LoggerFactory.getLogger(Address.class);

    public static final String KEY_SPLIT_STRING = ":";
    public static final String PUBLIC_KEY_FILE_NAME_SUFFIX = ".pub";

    protected String encryptPrivKey;

    protected byte[] pubKey;
    protected String address;

    protected boolean syncComplete = false;
    private long mSortTime;
    private long balance = 0;
    private boolean isFromXRandom;
    private boolean isTrashed = false;
    private String alias;

    private int vanityLen = VANITY_LEN_NO_EXSITS;

    public Address() {
        super();
    }

    public Address(String address, byte[] pubKey, String encryptString, boolean isSyncComplete
            , boolean isFromXRandom) {
        this(address, pubKey, AddressManager.getInstance().getSortTime(!Utils.isEmpty
                (encryptString)), isSyncComplete, isFromXRandom, false, encryptString);

    }

    public Address(String address, byte[] pubKey, long sortTime, boolean isSyncComplete,
                   boolean isFromXRandom, boolean isTrashed, String encryptPrivKey) {
        this.encryptPrivKey = encryptPrivKey;
        this.address = address;
        this.pubKey = pubKey;
        this.mSortTime = sortTime;
        this.syncComplete = isSyncComplete;
        this.isFromXRandom = isFromXRandom;
        this.isTrashed = isTrashed;
        this.updateBalance();
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

    public List<Tx> getTxs(int page) {
        List<Tx> txs = AbstractDb.txProvider.getTxAndDetailByAddress(this.address, page);
        return txs;
    }

    public boolean isTrashed() {
        return isTrashed;
    }

    public void setTrashed(boolean isTrashed, boolean fromDb) {
        if (!fromDb && isTrashed() != isTrashed) {
            if (isTrashed) {
                AbstractDb.addressProvider.trashPrivKeyAddress(this);
            } else {
                AbstractDb.addressProvider.restorePrivKeyAddress(this);
            }
        }
        this.isTrashed = isTrashed;
    }

    public void setTrashed(boolean isTrashed) {
        setTrashed(isTrashed, false);
    }

    @Override
    public int compareTo(@Nonnull Address address) {
        return -1 * Long.valueOf(getSortTime()).compareTo(Long.valueOf(address.getSortTime()));
    }

    public void updateBalance() {
        this.balance = AbstractDb.txProvider.getConfirmedBalanceWithAddress(getAddress())
                + this.calculateUnconfirmedBalance();
    }

    private long calculateUnconfirmedBalance() {
        long balance = 0;

        List<Tx> txs = AbstractDb.txProvider.getUnconfirmedTxWithAddress(this.address);
        Collections.sort(txs);

        Set<byte[]> invalidTx = new HashSet<byte[]>();
        Set<OutPoint> spentOut = new HashSet<OutPoint>();
        Set<OutPoint> unspendOut = new HashSet<OutPoint>();

        for (int i = txs.size() - 1; i >= 0; i--) {
            Set<OutPoint> spent = new HashSet<OutPoint>();
            Tx tx = txs.get(i);

            Set<byte[]> inHashes = new HashSet<byte[]>();
            for (In in : tx.getIns()) {
                spent.add(new OutPoint(in.getPrevTxHash(), in.getPrevOutSn()));
                inHashes.add(in.getPrevTxHash());
            }

            if (tx.getBlockNo() == Tx.TX_UNCONFIRMED
                    && (Utils.isIntersects(spent, spentOut) || Utils.isIntersects(inHashes, invalidTx))) {
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
                for (Out out : tx1.getOuts()) {
                    if (out.getOutSn() == o.getOutSn()) {
                        balance -= out.getOutValue();
                    }
                }
            }
        }
        return balance;
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
        AbstractApp.notificationService.notificatTx(getAddress(), tx, txNotificationType, deltaBalance);
    }

    public void setBlockHeight(List<byte[]> txHashes, int height) {
        notificatTx(null, Tx.TxNotificationType.txDoubleSpend);
    }

    public boolean initTxs(List<Tx> txs) {
        AbstractDb.txProvider.addTxs(txs);
        notificatTx(null, Tx.TxNotificationType.txFromApi);
        return true;
    }


    public byte[] getPubKey() {
        return this.pubKey;
    }

    public String getAddress() {
        return this.address;
    }

    public boolean hasPrivKey() {
        return !Utils.isEmpty(this.encryptPrivKey);
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


    public void updateSyncComplete() {
        AbstractDb.addressProvider.updateSyncComplete(Address.this);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Address) {
            Address other = (Address) o;
            return Utils.compareString(getAddress(), other.getAddress());
        }
        return false;
    }

    public long getSortTime() {
        return mSortTime;
    }

    public void setSortTime(long mSortTime) {
        this.mSortTime = mSortTime;
    }

    public String getEncryptPrivKeyOfDb() {
        return PrivateKeyUtil.formatEncryptPrivateKeyForDb(this.encryptPrivKey);
    }

    public String getFullEncryptPrivKeyOfDb() {
        return PrivateKeyUtil.getFullencryptPrivateKey(Address.this, this.encryptPrivKey);
    }

    public void recoverFromBackup(String encryptPriv) {
        AbstractDb.addressProvider.updatePrivateKey(getAddress(), encryptPriv);
    }

    public String getFullEncryptPrivKey() {
        String encryptPrivKeyString = AbstractDb.addressProvider.getEncryptPrivateKey(getAddress());
        if (Utils.isEmpty(encryptPrivKeyString)) {
            return "";
        } else {
            return PrivateKeyUtil.getFullencryptPrivateKey(Address.this
                    , encryptPrivKeyString);
        }
    }


    public Tx buildTx(List<Long> amounts, List<String> addresses) throws TxBuilderException {
        return buildTx(getAddress(), amounts, addresses);
    }

    public Tx buildTx(String changeAddress, List<Long> amounts, List<String> addresses) throws TxBuilderException {
        return TxBuilder.getInstance().buildTx(this, changeAddress, amounts, addresses,true);
    }

    public Tx buildTx(String changeAddress, List<Long> amounts, List<String> addresses,boolean isBtc) throws TxBuilderException {
        return TxBuilder.getInstance().buildTx(this, changeAddress, amounts, addresses,isBtc);
    }

    public Tx buildTx(long amount, String address) throws TxBuilderException {
        return buildTx(amount, address, getAddress());
    }

    public Tx buildTx(long amount, String address, String changeAddress) throws TxBuilderException {
        List<Long> amounts = new ArrayList<Long>();
        amounts.add(amount);
        List<String> addresses = new ArrayList<String>();
        addresses.add(address);
        return buildTx(changeAddress, amounts, addresses);
    }

    public Tx buildTx(long amount, String address, String changeAddress,boolean isBtc) throws TxBuilderException {
        List<Long> amounts = new ArrayList<Long>();
        amounts.add(amount);
        List<String> addresses = new ArrayList<String>();
        addresses.add(address);
        return buildTx(changeAddress, amounts, addresses,isBtc);
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
        List<byte[]> resultHashes = signHashes(hashes, passphrase,TransactionSignature.SigHash.ALL);
        ArrayList<String> resultStrs = new ArrayList<String>();
        for (byte[] h : resultHashes) {
            resultStrs.add(Utils.bytesToHexString(h));
        }
        return resultStrs;
    }

    public List<byte[]> signHashes(List<byte[]> unsignedInHashes, CharSequence passphrase, TransactionSignature.SigHash sigHash) throws
            PasswordException {
        ECKey key = PrivateKeyUtil.getECKeyFromSingleString(this.getFullEncryptPrivKey(), passphrase);
        if (key == null) {
            throw new PasswordException("do not decrypt eckey");
        }
        KeyParameter assKey = key.getKeyCrypter().deriveKey(passphrase);
        List<byte[]> result = new ArrayList<byte[]>();
        for (byte[] unsignedInHash : unsignedInHashes) {
            TransactionSignature signature = new TransactionSignature(key.sign(unsignedInHash,
                    assKey), sigHash, false);
            result.add(ScriptBuilder.createInputScript(signature, key).getProgram());
        }
        key.clearPrivateKey();
        return result;
    }

    public List<byte[]> signHashes(List<byte[]> unsignedInHashes, CharSequence passphrase) throws
            PasswordException {
        return signHashes(unsignedInHashes, passphrase, TransactionSignature.SigHash.ALL);
    }

    public String signMessage(String msg, CharSequence passphrase) {

        ECKey key = PrivateKeyUtil.getECKeyFromSingleString(this.getFullEncryptPrivKey(), passphrase);
        if (key == null) {
            throw new PasswordException("do not decrypt eckey");
        }
        KeyParameter assKey = key.getKeyCrypter().deriveKey(passphrase);

        String result = key.signMessage(msg, assKey);


        key.clearPrivateKey();
        return result;


    }

    public void signTx(Tx tx, CharSequence passphrase,boolean isBtc) {
        if (isBtc) {
            tx.signWithSignatures(this.signHashes(tx.getUnsignedInHashes(), passphrase,TransactionSignature.SigHash.ALL));
        } else {
            tx.signWithSignatures(this.signHashes(tx.getBccForkUnsignedInHashes(), passphrase,TransactionSignature.SigHash.BCCFORK));
        }
    }

    public void completeInSignature(List<In> ins) {
        AbstractDb.txProvider.completeInSignature(ins);
    }

    public int needCompleteInSignature() {
        return AbstractDb.txProvider.needCompleteInSignature(this.address);
    }

    public long totalReceive() {
        return AbstractDb.txProvider.totalReceive(getAddress());
    }

    public boolean isHDM() {
        return false;
    }

    public boolean isCompressed() {
        return pubKey.length == 33;
    }

    public boolean removeTx(Tx tx) {
        AbstractDb.txProvider.remove(tx.getTxHash());
        return true;
    }

    public boolean isHDAccount() {
        return this instanceof HDAccount;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void updateAlias(String alias) {
        this.alias = alias;
        AbstractDb.addressProvider.updateAlias(this.address, this.alias);
    }

    public void removeAlias() {
        this.alias = null;
        AbstractDb.addressProvider.updateAlias(getAddress(), null);
    }

    public int getVanityLen() {
        return vanityLen;
    }

    public void setVanityLen(int vanityLen) {
        this.vanityLen = vanityLen;
    }

    public void updateVanityLen(int vanityLen) {
        this.vanityLen = vanityLen;
        AbstractDb.addressProvider.updateVaitylen(this.address, this.vanityLen);
    }

    public void removeVanitylen() {
        this.vanityLen = VANITY_LEN_NO_EXSITS;
        AbstractDb.addressProvider.updateVaitylen(this.address, VANITY_LEN_NO_EXSITS);

    }

    public boolean exsitsVanityLen() {
        return vanityLen != VANITY_LEN_NO_EXSITS;
    }


}
