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

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.exception.ScriptException;
import net.bither.bitherj.exception.VerificationException;
import net.bither.bitherj.message.BlockMessage;
import net.bither.bitherj.message.Message;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.script.ScriptOpCodes;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.UnsafeByteArrayOutputStream;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static net.bither.bitherj.utils.Utils.doubleDigest;
import static net.bither.bitherj.utils.Utils.uint32ToByteStreamLE;

public class Tx extends Message implements Comparable<Tx> {
    public enum TxNotificationType {
        txSend(0),
        txReceive(1),
        txDoubleSpend(2),
        txFromApi(3);

        private int mVal;

        private TxNotificationType(int val) {
            this.mVal = val;
        }

        public int getValue() {
            return this.mVal;
        }
    }

    public enum SourceType {
        network(0),
        self(1);

        private int mVal;

        private SourceType(int val) {
            this.mVal = val;
        }

        public int getValue() {
            return this.mVal;
        }
    }

    private static final Logger log = LoggerFactory.getLogger(Tx.class);

    /**
     * Threshold for lockTime: below this value it is interpreted as block number,
     * otherwise as timestamp. *
     */
    public static final int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC

    /**
     * How many bytes a transaction can be before it won't be relayed anymore. Currently 100kb.
     */
    public static final int MAX_STANDARD_TX_SIZE = 100 * 1024;

    /**
     * If fee is lower than this value (in satoshis), a default reference client will treat it as
     * if there were no fee.
     * Currently this is 10000 satoshis.
     */
    public static final long REFERENCE_DEFAULT_MIN_TX_FEE = 1000;

    /**
     * Any standard (ie pay-to-address) output smaller than this value (in satoshis) will most
     * likely be rejected by the network.
     * This is calculated by assuming a standard output will be 34 bytes,
     * and then using the formula used in
     */
    public static final long MIN_NONDUST_OUTPUT = 5460;


    public Tx() {
        this.ins = new ArrayList<In>();
        this.outs = new ArrayList<Out>();
        this.blockNo = TX_UNCONFIRMED;
        this.txVer = TX_VERSION;
        this.txLockTime = TX_LOCKTIME;
        this.txTime = (int) (new Date().getTime() / 1000);
    }

    public Tx(Tx tx) {
        this(tx.bitcoinSerialize());
    }

    public Tx(byte[] msg) {
        this(msg, 0, msg.length);
    }

    public Tx(byte[] msg, int offset, int length) {
        super(msg, offset, length);
        blockNo = TX_UNCONFIRMED;
        this.txTime = (int) (new Date().getTime() / 1000);
    }

    public static final int TX_UNCONFIRMED = Integer.MAX_VALUE;
    public static final long TX_VERSION = 1l;
    public static final long TX_LOCKTIME = 0l;

    private int blockNo;
    private byte[] txHash;
    private int txTime;
    private long txVer;
    private long txLockTime;
    private int source;
    private int sawByPeerCnt;
    private List<In> ins;
    private List<Out> outs;

//    public int length;

    private transient int optimalEncodingMessageSize;


    public int getBlockNo() {
        return blockNo;
    }

    public void setBlockNo(int blockNo) {
        this.blockNo = blockNo;
    }

    /**
     * Returns the transaction hash as you see them in the block explorer.
     */
    public byte[] getTxHash() {
        if (txHash == null) {
            byte[] bits = bitcoinSerialize();
            txHash = doubleDigest(bits);
        }
        return txHash;
    }

    public void recalculateTxHash() {
        byte[] bits = bitcoinSerialize();
        this.txHash = doubleDigest(bits);
        for (In in : this.getIns()) {
            in.setTx(this);
        }
        for (Out out : this.getOuts()) {
            out.setTx(this);
        }
    }

    public void setTxHash(byte[] txHash) {
        this.txHash = txHash;
    }

    public int getTxTime() {
        return txTime;
    }

    public void setTxTime(int txTime) {
        this.txTime = txTime;
    }

    public long getTxVer() {
        return txVer;
    }

    public void setTxVer(long txVer) {
        this.txVer = txVer;
    }

    public long getTxLockTime() {
        return txLockTime;
    }

    public void setTxLockTime(long txLockTime) {
        this.txLockTime = txLockTime;
    }

    public int getSource() {
        return source;
    }

    public void setSource(int source) {
        this.source = source;
    }

    public List<In> getIns() {
        for (In btIn : this.ins) {
            if (btIn.getTx() == null) {
                btIn.setTx(this);
            }
        }
        return ins;
    }

    public void setIns(List<In> ins) {
        this.ins = ins;
    }

    public List<Out> getOuts() {
        for (Out out : this.outs) {
            if (out.getTx() == null) {
                out.setTx(this);
            }
        }
        return outs;
    }

    public void setOuts(List<Out> outs) {
        this.outs = outs;
    }

    public int getSawByPeerCnt() {
        return sawByPeerCnt;
    }

    public void setSawByPeerCnt(int sawByPeerCnt) {
        this.sawByPeerCnt = sawByPeerCnt;
    }

    public void sawByPeer() {
        AbstractDb.txProvider.txSentBySelfHasSaw(getTxHash());
        setSawByPeerCnt(getSawByPeerCnt() + 1);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Tx) {
            Tx item = (Tx) o;
            if (getBlockNo() == item.getBlockNo() &&
                    Arrays.equals(getTxHash(), item.getTxHash()) &&
                    getSource() == item.getSource() &&
                    getSawByPeerCnt() == item.getSawByPeerCnt() &&
                    getTxTime() == item.getTxTime() &&
                    getTxVer() == item.getTxVer() &&
                    getTxLockTime() == item.getTxLockTime()) {
                if (getIns().size() != item.getIns().size()) {
                    return false;
                } else {
                    for (int i = 0;
                         i < getIns().size();
                         i++) {
                        if (!getIns().get(i).equals(item.getIns().get(i))) {
                            return false;
                        }
                    }
                }
                if (getOuts().size() == item.getOuts().size()) {
                    for (int i = 0;
                         i < getOuts().size();
                         i++) {
                        if (!getOuts().get(i).equals(item.getOuts().get(i))) {
                            return false;
                        }
                    }
                }
                return true;

            }
        }
        return false;

    }

    @Override
    public int compareTo(@Nonnull Tx tx) {
        if (this.getBlockNo() != tx.getBlockNo()) {
            return tx.getBlockNo() - this.getBlockNo();
        } else {
            boolean isTx2AfterTx1 = false;
            for (In in : tx.getIns()) {
                if (Arrays.equals(in.getPrevTxHash(), this.getTxHash())) {
                    isTx2AfterTx1 = true;
                    break;
                }
            }
            if (isTx2AfterTx1) {
                return 1;
            }
            boolean isTx1AfterTx2 = false;
            for (In in : this.getIns()) {
                if (Arrays.equals(in.getPrevTxHash(), tx.getTxHash())) {
                    isTx1AfterTx2 = true;
                }
            }
            if (isTx1AfterTx2) {
                return -1;
            }
            return tx.getTxTime() - this.getTxTime();
        }
    }

    public String getFirstOutAddressOtherThanChange(String changeAddress) {
        if (getOuts().size() > 0) {
            if (isCoinBase()) {
                return getOuts().get(0).getOutAddress();
            }
            for (Out out : getOuts()) {
                if (!Utils.compareString(out.getOutAddress(), getFromAddress()) && !Utils
                        .compareString(out.getOutAddress(), changeAddress)) {
                    return out.getOutAddress();
                }
            }
            return getOuts().get(0).getOutAddress();
        }
        return null;
    }

    public String getFirstOutAddress() {
        return getFirstOutAddressOtherThanChange(null);
    }

    public String getFromAddress() {
        if (isCoinBase()) {
            return null;
        }
        In in = getIns().get(0);
        String address = in.getFromAddress();
        if (address != null) {
            return address;
        } else {
            Tx preTx = AbstractDb.txProvider.getTxDetailByTxHash(in.getPrevTxHash());
            if (preTx == null) {
                return null;
            }
            for (Out out : preTx.getOuts()) {
                if (out.getOutSn() == in.getPrevOutSn()) {
                    return out.getOutAddress();
                }
            }
            return null;
        }
    }

    public long amountSentToAddress(String address) {
        long amount = 0;
        for (Out out : getOuts()) {
            if (Utils.compareString(out.getOutAddress(), address)) {
                amount += out.getOutValue();
            }
        }
        return amount;
    }

    public long getFee() {
        long amount = 0;
        for (In in : getIns()) {
            Tx preTx = AbstractDb.txProvider.getTxDetailByTxHash(in.getPrevTxHash());
            boolean hasOut = false;
            for (Out out : preTx.getOuts()) {
                if (in.getPrevOutSn() == out.getOutSn()) {
                    amount += out.getOutValue();
                    hasOut = true;
                }

            }
            if (!hasOut) {
                return Long.MAX_VALUE;
            }
        }
        for (Out out : getOuts()) {
            amount -= out.getOutValue();
        }
        return amount;
    }

    public String getHashAsString() {
        return Utils.hashToString(getTxHash());
    }

    public Date getTxDate() {
        return new Date((long) getTxTime() * 1000);
    }

    protected static int calcLength(byte[] buf, int offset) {
        VarInt varint;
        // jump past version (uint32)
        int cursor = offset + 4;

        int i;
        long scriptLen;

        varint = new VarInt(buf, cursor);
        long txInCount = varint.value;
        cursor += varint.getOriginalSizeInBytes();

        for (i = 0;
             i < txInCount;
             i++) {
            // 36 = length of previous_outpoint
            cursor += 36;
            varint = new VarInt(buf, cursor);
            scriptLen = varint.value;
            // 4 = length of sequence field (unint32)
            cursor += scriptLen + 4 + varint.getOriginalSizeInBytes();
        }

        varint = new VarInt(buf, cursor);
        long txOutCount = varint.value;
        cursor += varint.getOriginalSizeInBytes();

        for (i = 0;
             i < txOutCount;
             i++) {
            // 8 = length of tx value field (uint64)
            cursor += 8;
            varint = new VarInt(buf, cursor);
            scriptLen = varint.value;
            cursor += scriptLen + varint.getOriginalSizeInBytes();
        }
        // 4 = length of lock_time field (uint32)
        return cursor - offset + 4;
    }

    protected void parse() throws ProtocolException {
        //skip this if the length has been provided i.e. the tx is not part of a block
        if (length == UNKNOWN_LENGTH) {
            //If length hasn't been provided this tx is probably contained within a block.
            //In parseRetain mode the block needs to know how long the transaction is
            //unfortunately this requires a fairly deep (though not total) parse.
            //This is due to the fact that transactions in the block's list do not include a
            //size header and inputs/outputs are also variable length due the contained
            //script so each must be instantiated so the scriptlength varint can be read
            //to calculate total length of the transaction.
            //We will still persist will this semi-light parsing because getting the lengths
            //of the various components gains us the ability to cache the backing bytearrays
            //so that only those subcomponents that have changed will need to be reserialized.

            //parse();
            //parsed = true;
            length = calcLength(bytes, offset);
            cursor = offset + length;
        }
        byte[] b = new byte[length];
        System.arraycopy(bytes, cursor, b, 0, length);
        txHash = doubleDigest(b);

        cursor = offset;

        txVer = readUint32();
        optimalEncodingMessageSize = 4;

        // First come the inputs.
        long numInputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numInputs);
        this.ins = new ArrayList<In>((int) numInputs);
        for (int i = 0;
             i < numInputs;
             i++) {
            In in = new In(this, bytes, cursor);
            in.setInSn(i);
            this.ins.add(in);
            long scriptLen = readVarInt(In.OUTPOINT_MESSAGE_LENGTH);
            optimalEncodingMessageSize += In.OUTPOINT_MESSAGE_LENGTH + VarInt.sizeOf(scriptLen) +
                    scriptLen + 4;
            cursor += scriptLen + 4;
        }
        // Now the outputs
        long numOutputs = readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numOutputs);
        this.outs = new ArrayList<Out>((int) numOutputs);
        for (int i = 0;
             i < numOutputs;
             i++) {
            Out out = new Out(this, bytes, cursor);
            out.setOutSn(i);
            this.outs.add(out);
            long scriptLen = readVarInt(8);
            optimalEncodingMessageSize += 8 + VarInt.sizeOf(scriptLen) + scriptLen;
            cursor += scriptLen;
        }
        this.txLockTime = readUint32();
        optimalEncodingMessageSize += 4;
        this.length = cursor - offset;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0) {
            return optimalEncodingMessageSize;
        }
        if (optimalEncodingMessageSize != 0) {
            return optimalEncodingMessageSize;
        }
        optimalEncodingMessageSize = getMessageSize();
        return optimalEncodingMessageSize;
    }

    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in
     * each block and their
     * value is determined by a formula that all implementations of Bitcoin share. In 2011 the
     * value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined
     * not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return ins.size() == 1 && ins.get(0).isCoinBase();
    }

    /**
     * A transaction is mature if it is either a building coinbase tx that is as deep or deeper
     * than the required coinbase depth, or a non-coinbase tx.
     */
    public boolean isMature() {
        if (!isCoinBase()) {
            return true;
        }
        if (blockNo == TX_UNCONFIRMED) {
            return false;
        }
        return BlockChain.getInstance().lastBlock.getBlockNo() - blockNo + 1 >= BitherjSettings
                .spendableCoinbaseDepth;
    }

    /**
     * Removes all the inputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearInputs() {
        for (In input : ins) {
            input.setTx(null);
        }
        ins.clear();
        // You wanted to reserialize, right?
        this.length = this.bitcoinSerialize().length;
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this
     * input is NOT
     * complete and after every input is added with addInput() and every output is added with
     * addOutput(),
     * signInputs() must be called to finalize the transaction and finish the inputs off.
     * Otherwise it won't be
     * accepted by the network. Returns the newly created input.
     */
    public In addInput(Out from) {
        return addInput(new In(this, from));
    }

    /**
     * Adds an input directly, with no checking that it's valid. Returns the new input.
     */
    public In addInput(In input) {
        input.setTx(this);
        input.setInSn(this.getIns().size());
        ins.add(input);
        adjustLength(ins.size(), input.length);
        return input;
    }

    /**
     * Adds a new and fully signed input for the given parameters. Note that this method is
     * <b>not</b> thread safe
     * and requires external synchronization. Please refer to general documentation on Bitcoin
     * scripting and contracts
     * to understand the values of sigHash and anyoneCanPay: otherwise you can use the other form
     * of this method
     * that sets them to typical defaults.
     *
     * @throws net.bither.bitherj.exception.ScriptException if the scriptPubKey is not a pay to address or pay to pubkey script.
     */
    public In addSignedInput(Out prevOut, Script scriptPubKey, ECKey sigKey,
                             TransactionSignature.SigHash sigHash, boolean anyoneCanPay) throws
            ScriptException {
        In input = new In(this, new byte[]{}, prevOut);
        addInput(input);
        byte[] hash = hashForSignature(ins.size() - 1, scriptPubKey, sigHash, anyoneCanPay);
        ECKey.ECDSASignature ecSig = sigKey.sign(hash);
        TransactionSignature txSig = new TransactionSignature(ecSig, sigHash, anyoneCanPay);
        if (scriptPubKey.isSentToRawPubKey()) {
            input.setInSignature(ScriptBuilder.createInputScript(txSig).getProgram());
        } else if (scriptPubKey.isSentToAddress()) {
            input.setInSignature(ScriptBuilder.createInputScript(txSig, sigKey).getProgram());
        } else {
            throw new ScriptException("Don't know how to sign for this kind of scriptPubKey: " +
                    scriptPubKey);
        }
        return input;
    }

    /**
     * Same as {@link #addSignedInput(net.bither.bitherj.core.Out, net.bither.bitherj.script.Script, net.bither.bitherj.crypto.ECKey, net.bither.bitherj.crypto.TransactionSignature.SigHash, boolean)}
     * but defaults to {@link net.bither.bitherj.crypto.TransactionSignature.SigHash#ALL} and
     * "false" for the anyoneCanPay flag. This is normally what you want.
     */
    public In addSignedInput(Out prevOut, Script scriptPubKey,
                             ECKey sigKey) throws ScriptException {
        return addSignedInput(prevOut, scriptPubKey, sigKey, TransactionSignature.SigHash.ALL,
                false);
    }

    /**
     * Removes all the inputs from this transaction.
     * Note that this also invalidates the length attribute
     */
    public void clearOutputs() {
        for (Out output : outs) {
            output.setTx(null);
        }
        outs.clear();
        // You wanted to reserialize, right?
        this.length = this.bitcoinSerialize().length;
    }

    /**
     * Adds the given output to this transaction. The output must be completely initialized.
     * Returns the given output.
     */
    public Out addOutput(Out to) {
        to.setTx(this);
        to.setOutSn(this.outs.size());
        outs.add(to);
        adjustLength(outs.size(), to.length);
        return to;
    }

    /**
     * Creates an output based on the given address and value, adds it to this transaction,
     * and returns the new output.
     */
    public Out addOutput(long value, String address) {
        return addOutput(new Out(this, value, address));
    }

    /**
     * Creates an output that pays to the given pubkey directly (no address) with the given
     * value, adds it to this
     * transaction, and returns the new output.
     */
    public Out addOutput(long value, ECKey pubkey) {
        return addOutput(new Out(this, value, pubkey));
    }

    /**
     * Creates an output that pays to the given script. The address and key forms are
     * specialisations of this method,
     * you won't normally need to use it unless you're doing unusual things.
     */
    public Out addOutput(long value, Script script) {
        return addOutput(new Out(this, value, script.getProgram()));
    }

    /**
     * Once a transaction has some inputs and outputs added, the signatures in the inputs can be
     * calculated. The
     * signature is over the transaction itself, to prove the redeemer actually created that
     * transaction,
     * so we have to do this step last.<p>
     * <p/>
     * This method is similar to SignatureHash in script.cpp
     *
     * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
     * @param address  A wallet is required to fetch the keys needed for signing.
     */
    public synchronized void signInputs(TransactionSignature.SigHash hashType,
                                        Address address) throws ScriptException {
        signInputs(hashType, address, null);
    }


    public synchronized void signInputs(TransactionSignature.SigHash hashType, Address address,
                                        CharSequence password) throws ScriptException {
        checkState(ins.size() > 0);
        checkState(outs.size() > 0);

        // I don't currently have an easy way to test other modes work,
        // as the official client does not use them.
        checkArgument(hashType == TransactionSignature.SigHash.ALL,
                "Only SIGHASH_ALL is currently supported");

        // The transaction is signed with the input scripts empty except for the input we are
        // signing. In the case
        // where addInput has been used to set up a new transaction, they are already all empty.
        // The input being signed
        // has to have the connected OUTPUT program in it when the hash is calculated!
        //
        // Note that each input may be claiming an output sent to a different key. So we have to
        // look at the outputs
        // to figure out which key to sign with.

        TransactionSignature[] signatures = new TransactionSignature[ins.size()];
        ECKey[] signingKeys = new ECKey[ins.size()];
        for (int i = 0;
             i < ins.size();
             i++) {
            In input = ins.get(i);
            // We don't have the connected output, we assume it was signed already and move on
            // todo:
//            if (input.getOutpoint().getConnectedOutput() == null) {
//                log.warn("Missing connected output, assuming input {} is already signed.", i);
//                continue;
//            }
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will
                // not invalidate when
                // we sign missing pieces (to check this would require either assuming any
                // signatures are signing
                // standard output types or a way to get processed signatures out of script
                // execution)
                // todo:
//                input.getScriptSig().correctlySpends(this, i,
//  input.getOutpoint().getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends output, " +
                        "" + "assuming SIGHASH type used will be safe and skipping signing.", i);
                // all need to sign
//                continue;
            } catch (ScriptException e) {
                // Expected.
            }
            if (input.getInSignature() == null || input.getInSignature().length != 0) {
                log.warn("Re-signing an already signed transaction! Be sure this is what you " +
                        "want" + ".");
            }
            // Find the signing key we'll need to use.
            ECKey key = PrivateKeyUtil.getECKeyFromSingleString(address.getFullEncryptPrivKey(),
                    password);//input.getOutpoint().getConnectedKey(address);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s",
                    input.getPrevTxHash());
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            KeyParameter assKey = key.getKeyCrypter().deriveKey(password);
            // The anyoneCanPay feature isn't used at the moment.
            boolean anyoneCanPay = false;
            byte[] connectedPubKeyScript = input.getPrevOutScript();//input.getOutpoint()
            // .getConnectedPubKeyScript();
            if (key.hasPrivKey() || key.isEncrypted()) {
                signatures[i] = calculateSignature(i, key, assKey, connectedPubKeyScript,
                        hashType, anyoneCanPay);
            } else {
                // Create a dummy signature to ensure the transaction is of the correct size when
                // we try to ensure
                // the right fee-per-kb is attached. If the wallet doesn't have the privkey,
                // the user is assumed to
                // be doing something special and that they will replace the dummy signature with
                // a real one later.
                signatures[i] = TransactionSignature.dummy();
            }
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder:
        // the script consists:
        // 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction)
        // and the complete
        //    public key needed to sign for the connected output. The output script checks the
        // provided pubkey hashes
        //    to the address and then checks the signature.
        // 2) For pay-to-key outputs: just a signature.
        for (int i = 0;
             i < ins.size();
             i++) {
            if (signatures[i] == null) {
                continue;
            }
            In input = ins.get(i);
//            final TransactionOutput connectedOutput = input.getOutpoint().getConnectedOutput();
//            checkNotNull(connectedOutput);  // Quiet static analysis: is never null here but
//            cannot be statically proven
            Script scriptPubKey = new Script(input.getPrevOutScript()); //connectedOutput
            // .getScriptPubKey();
            if (scriptPubKey.isSentToAddress()) {
                input.setInSignature(ScriptBuilder.createInputScript(signatures[i],
                        signingKeys[i]).getProgram());
            } else if (scriptPubKey.isSentToRawPubKey()) {
                input.setInSignature(ScriptBuilder.createInputScript(signatures[i]).getProgram());
            } else {
                // Should be unreachable - if we don't recognize the type of script we're trying
                // to sign for, we should
                // have failed above when fetching the key to sign with.
                throw new RuntimeException("Do not understand script type: " + scriptPubKey);
            }
        }
        for (ECKey key : signingKeys) {
            if (key != null) {
                key.clearPrivateKey();
            }
        }

        // Every input is now complete.
    }

    public synchronized void signInputs(TransactionSignature.SigHash hashType, HashMap<String, Address> addressMap,
                                        CharSequence password) throws ScriptException {
        checkState(ins.size() > 0);
        checkState(outs.size() > 0);

        // I don't currently have an easy way to test other modes work,
        // as the official client does not use them.
        checkArgument(hashType == TransactionSignature.SigHash.ALL,
                "Only SIGHASH_ALL is currently supported");

        // The transaction is signed with the input scripts empty except for the input we are
        // signing. In the case
        // where addInput has been used to set up a new transaction, they are already all empty.
        // The input being signed
        // has to have the connected OUTPUT program in it when the hash is calculated!
        //
        // Note that each input may be claiming an output sent to a different key. So we have to
        // look at the outputs
        // to figure out which key to sign with.

        TransactionSignature[] signatures = new TransactionSignature[ins.size()];
        ECKey[] signingKeys = new ECKey[ins.size()];
        for (int i = 0; i < ins.size(); i++) {
            In input = ins.get(i);
            // We don't have the connected output, we assume it was signed already and move on
            // todo:
//            if (input.getOutpoint().getConnectedOutput() == null) {
//                log.warn("Missing connected output, assuming input {} is already signed.", i);
//                continue;
//            }
            try {
                // We assume if its already signed, its hopefully got a SIGHASH type that will
                // not invalidate when
                // we sign missing pieces (to check this would require either assuming any
                // signatures are signing
                // standard output types or a way to get processed signatures out of script
                // execution)
                // todo:
//                input.getScriptSig().correctlySpends(this, i,
//  input.getOutpoint().getConnectedOutput().getScriptPubKey(), true);
                log.warn("Input {} already correctly spends output, " +
                        "" + "assuming SIGHASH type used will be safe and skipping signing.", i);
                // all need to sign
//                continue;
            } catch (ScriptException e) {
                // Expected.
            }
            if (input.getInSignature() == null || input.getInSignature().length != 0) {
                log.warn("Re-signing an already signed transaction! Be sure this is what you " +
                        "want" + ".");
            }
            // Find the signing key we'll need to use.
            Script pubKeyScript = new Script(input.getPrevOutScript());
            ECKey key = PrivateKeyUtil.getECKeyFromSingleString(addressMap.get(pubKeyScript.getToAddress()).getFullEncryptPrivKey(), password);
            //input.getOutpoint().getConnectedKey(address);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s",
                    input.getPrevTxHash());
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            KeyParameter assKey = key.getKeyCrypter().deriveKey(password);
            // The anyoneCanPay feature isn't used at the moment.
            boolean anyoneCanPay = false;
            byte[] connectedPubKeyScript = input.getPrevOutScript();//input.getOutpoint()
            // .getConnectedPubKeyScript();
            if (key.hasPrivKey() || key.isEncrypted()) {
                signatures[i] = calculateSignature(i, key, assKey, connectedPubKeyScript,
                        hashType, anyoneCanPay);
            } else {
                // Create a dummy signature to ensure the transaction is of the correct size when
                // we try to ensure
                // the right fee-per-kb is attached. If the wallet doesn't have the privkey,
                // the user is assumed to
                // be doing something special and that they will replace the dummy signature with
                // a real one later.
                signatures[i] = TransactionSignature.dummy();
            }
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder:
        // the script consists:
        // 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction)
        // and the complete
        //    public key needed to sign for the connected output. The output script checks the
        // provided pubkey hashes
        //    to the address and then checks the signature.
        // 2) For pay-to-key outputs: just a signature.
        for (int i = 0; i < ins.size(); i++) {
            if (signatures[i] == null) {
                continue;
            }
            In input = ins.get(i);
//            final TransactionOutput connectedOutput = input.getOutpoint().getConnectedOutput();
//            checkNotNull(connectedOutput);  // Quiet static analysis: is never null here but
//            cannot be statically proven
            Script scriptPubKey = new Script(input.getPrevOutScript()); //connectedOutput
            // .getScriptPubKey();
            if (scriptPubKey.isSentToAddress()) {
                input.setInSignature(ScriptBuilder.createInputScript(signatures[i],
                        signingKeys[i]).getProgram());
            } else if (scriptPubKey.isSentToRawPubKey()) {
                input.setInSignature(ScriptBuilder.createInputScript(signatures[i]).getProgram());
            } else {
                // Should be unreachable - if we don't recognize the type of script we're trying
                // to sign for, we should
                // have failed above when fetching the key to sign with.
                throw new RuntimeException("Do not understand script type: " + scriptPubKey);
            }
        }
        for (ECKey key : signingKeys) {
            if (key != null) {
                key.clearPrivateKey();
            }
        }

        // Every input is now complete.
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given
     * position. This is simply
     * a wrapper around calling {@link net.bither.bitherj.core.Tx#hashForSignature(int, byte[],
     * net.bither.bitherj.crypto.TransactionSignature.SigHash, boolean)}
     * followed by {@link net.bither.bitherj.crypto.ECKey#sign(byte[], org.spongycastle.crypto.params.KeyParameter)} and
     * then returning
     * a new {@link net.bither.bitherj.crypto.TransactionSignature}.
     *
     * @param inputIndex            Which input to calculate the signature for, as an index.
     * @param key                   The private key used to calculate the signature.
     * @param aesKey                If not null, this will be used to decrypt the key.
     * @param connectedPubKeyScript Byte-exact contents of the scriptPubKey that is being
     *                              satisified.
     * @param hashType              Signing mode, see the enum for documentation.
     * @param anyoneCanPay          Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public synchronized TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                                @Nullable KeyParameter aesKey,
                                                                byte[] connectedPubKeyScript,
                                                                TransactionSignature.SigHash
                                                                        hashType,
                                                                boolean anyoneCanPay) {
        byte[] hash = hashForSignature(inputIndex, connectedPubKeyScript, hashType, anyoneCanPay);
        return new TransactionSignature(key.sign(hash, aesKey), hashType, anyoneCanPay);
    }

    /**
     * Calculates a signature that is valid for being inserted into the input at the given
     * position. This is simply
     * a wrapper around calling {@link net.bither.bitherj.core.Tx#hashForSignature(int, byte[],
     * net.bither.bitherj.crypto.TransactionSignature.SigHash, boolean)}
     * followed by {@link net.bither.bitherj.crypto.ECKey#sign(byte[])} and then returning a new {@link net.bither.bitherj.crypto.TransactionSignature}.
     *
     * @param inputIndex            Which input to calculate the signature for, as an index.
     * @param key                   The private key used to calculate the signature.
     * @param connectedPubKeyScript The scriptPubKey that is being satisified.
     * @param hashType              Signing mode, see the enum for documentation.
     * @param anyoneCanPay          Signing mode, see the SigHash enum for documentation.
     * @return A newly calculated signature object that wraps the r, s and sighash components.
     */
    public synchronized TransactionSignature calculateSignature(int inputIndex, ECKey key,
                                                                Script connectedPubKeyScript,
                                                                TransactionSignature.SigHash
                                                                        hashType,
                                                                boolean anyoneCanPay) {
        byte[] hash = hashForSignature(inputIndex, connectedPubKeyScript.getProgram(), hashType,
                anyoneCanPay);
        return new TransactionSignature(key.sign(hash), hashType, anyoneCanPay);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction.
     * How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     * <p/>
     * <p>You don't normally ever need to call this yourself. It will become more useful in
     * future as the contracts
     * features of Bitcoin are developed.</p>
     *
     * @param inputIndex      input the signature is being calculated for. Tx signatures are
     *                        always relative to an input.
     * @param connectedScript the bytes that should be in the given input during signing.
     * @param type            Should be SigHash.ALL
     * @param anyoneCanPay    should be false.
     */
    public synchronized byte[] hashForSignature(int inputIndex, byte[] connectedScript,
                                                TransactionSignature.SigHash type,
                                                boolean anyoneCanPay) {
        byte sigHashType = (byte) TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, connectedScript, sigHashType);
    }

    /**
     * <p>Calculates a signature hash, that is, a hash of a simplified form of the transaction.
     * How exactly the transaction
     * is simplified is specified by the type and anyoneCanPay parameters.</p>
     * <p/>
     * <p>You don't normally ever need to call this yourself. It will become more useful in
     * future as the contracts
     * features of Bitcoin are developed.</p>
     *
     * @param inputIndex      input the signature is being calculated for. Tx signatures are
     *                        always relative to an input.
     * @param connectedScript the script that should be in the given input during signing.
     * @param type            Should be SigHash.ALL
     * @param anyoneCanPay    should be false.
     */
    public synchronized byte[] hashForSignature(int inputIndex, Script connectedScript,
                                                TransactionSignature.SigHash type,
                                                boolean anyoneCanPay) {
        int sigHash = TransactionSignature.calcSigHashValue(type, anyoneCanPay);
        return hashForSignature(inputIndex, connectedScript.getProgram(), (byte) sigHash);
    }

    /**
     * This is required for signatures which use a sigHashType which cannot be represented using
     * SigHash and anyoneCanPay
     * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73,
     * which has sigHashType 0
     */
    public synchronized byte[] hashForSignature(int inputIndex, byte[] connectedScript,
                                                byte sigHashType) {
        // The SIGHASH flags are used in the design of contracts, please see this page for a
        // further understanding of
        // the purposes of the code in this method:
        //
        //   https://en.bitcoin.it/wiki/Contracts

        try {
            // Store all the input scripts and clear them in preparation for signing. If we're
            // signing a fresh
            // transaction that step isn't very helpful, but it doesn't add much cost relative to
            // the actual
            // EC math so we'll do it anyway.
            //
            // Also store the input sequence numbers in case we are clearing them with SigHash
            // .NONE/SINGLE
            byte[][] inputScripts = new byte[this.getIns().size()][];
            long[] inputSequenceNumbers = new long[this.getIns().size()];
            for (int i = 0;
                 i < this.getIns().size();
                 i++) {
                inputScripts[i] = this.getIns().get(i).getInSignature();
                inputSequenceNumbers[i] = this.getIns().get(i).getInSequence();
                this.getIns().get(i).setInSignature(new byte[0]);
            }

            // This step has no purpose beyond being synchronized with the reference clients bugs
            // . OP_CODESEPARATOR
            // is a legacy holdover from a previous, broken design of executing scripts that
            // shipped in Bitcoin 0.1.
            // It was seriously flawed and would have let anyone take anyone elses money. Later
            // versions switched to
            // the design we use today where scripts are executed independently but share a stack
            // . This left the
            // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used
            // internally, not actually
            // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be
            // required but if we don't
            // do it, we could split off the main chain.
            connectedScript = Script.removeAllInstancesOfOp(connectedScript,
                    ScriptOpCodes.OP_CODESEPARATOR);

            // Set the input to the script of its output. Satoshi does this but the step has no
            // obvious purpose as
            // the signature covers the hash of the prevout transaction which obviously includes
            // the output script
            // already. Perhaps it felt safer to him in some way, or is another leftover from how
            // the code was written.
            In input = this.getIns().get(inputIndex);
            input.setInSignature(connectedScript);

            List<Out> outputs = this.getOuts();
            if ((sigHashType & 0x1f) == (TransactionSignature.SigHash.NONE.ordinal() + 1)) {
                // SIGHASH_NONE means no outputs are signed at all - the signature is effectively
                // for a "blank cheque".
                this.outs = new ArrayList<Out>(0);
                // The signature isn't broken by new versions of the transaction issued by other
                // parties.
                for (int i = 0;
                     i < this.getIns().size();
                     i++)
                    if (i != inputIndex) {
                        this.getIns().get(i).setInSequence(0);
                    }
            } else if ((sigHashType & 0x1f) == (TransactionSignature.SigHash.SINGLE.ordinal() +
                    1)) {
                // SIGHASH_SINGLE means only sign the output at the same index as the input (ie,
                // my output).
                if (inputIndex >= this.getOuts().size()) {
                    // The input index is beyond the number of outputs,
                    // it's a buggy signature made by a broken
                    // Bitcoin implementation. The reference client also contains a bug in
                    // handling this case:
                    // any transaction output that is signed in this case will result in both the
                    // signed output
                    // and any future outputs to this public key being steal-able by anyone who has
                    // the resulting signature and the public key (both of which are part of the
                    // signed tx input).
                    // Put the transaction back to how we found it.
                    //
                    // TODO: Only allow this to happen if we are checking a signature,
                    // not signing a transactions
                    for (int i = 0;
                         i < this.getIns().size();
                         i++) {
                        this.getIns().get(i).setInSignature(inputScripts[i]);
                        this.getIns().get(i).setInSequence(inputSequenceNumbers[i]);
                    }
                    this.outs = outputs;
                    // Satoshis bug is that SignatureHash was supposed to return a hash and on
                    // this codepath it
                    // actually returns the constant "1" to indicate an error,
                    // which is never checked for. Oops.
                    return Utils.hexStringToByteArray
                            ("0100000000000000000000000000000000000000000000000000000000000000");
                }
                // In SIGHASH_SINGLE the outputs after the matching input index are deleted,
                // and the outputs before
                // that position are "nulled out". Unintuitively,
                // the value in a "null" transaction is set to -1.
                this.outs = new ArrayList<Out>(this.getOuts().subList(0, inputIndex + 1));
                for (int i = 0;
                     i < inputIndex;
                     i++)
                    this.getOuts().set(i, new Out(this, -1, new byte[]{}));
                // The signature isn't broken by new versions of the transaction issued by other
                // parties.
                for (int i = 0;
                     i < this.getIns().size();
                     i++)
                    if (i != inputIndex) {
                        this.getIns().get(i).setInSequence(0);
                    }
            }

            List<In> inputs = this.getIns();
            if ((sigHashType & TransactionSignature.SIGHASH_ANYONECANPAY_VALUE) ==
                    TransactionSignature.SIGHASH_ANYONECANPAY_VALUE) {
                // SIGHASH_ANYONECANPAY means the signature in the input is not broken by
                // changes/additions/removals
                // of other inputs. For example, this is useful for building assurance contracts.
                this.ins = new ArrayList<In>();
                this.getIns().add(input);
            }

            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH
                    ? 256 : length + 4);
            bitcoinSerialize(bos);
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were
            // to be printed out
            // however then we would expect that it is IS reversed.
            byte[] hash = doubleDigest(bos.toByteArray());
            bos.close();

            // Put the transaction back to how we found it.
            this.ins = inputs;
            for (int i = 0;
                 i < inputs.size();
                 i++) {
                inputs.get(i).setInSignature(inputScripts[i]);
                inputs.get(i).setInSequence(inputSequenceNumbers[i]);
            }
            this.outs = outputs;
            return hash;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(txVer, stream);
        stream.write(new VarInt(ins.size()).encode());
        for (In in : ins)
            in.bitcoinSerialize(stream);
        stream.write(new VarInt(outs.size()).encode());
        for (Out out : outs)
            out.bitcoinSerialize(stream);
        uint32ToByteStreamLE(txLockTime, stream);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getTxHash());
    }

    /**
     * Ensure object is fully parsed before invoking java serialization.  The backing byte array
     * is transient so if the object has parseLazy = true and hasn't invoked checkParse yet
     * then data will be lost during serialization.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
    }

    /**
     * Gets the count of regular SigOps in this transactions
     */
    public int getSigOpCount() throws ScriptException {
        int sigOps = 0;
        for (In input : ins)
            sigOps += Script.getSigOpCount(input.getInSignature());
        for (Out output : outs)
            sigOps += Script.getSigOpCount(output.getOutScript());
        return sigOps;
    }

    /**
     * Checks the transaction contents for sanity, in ways that can be done in a standalone manner.
     * Does <b>not</b> perform all checks on a transaction such as whether the inputs are already
     * spent.
     *
     * @throws net.bither.bitherj.exception.VerificationException
     */
    public void verify() throws VerificationException {
        if (ins.size() == 0 || outs.size() == 0) {
            throw new VerificationException("Transaction had no inputs or no outputs.");
        }
        if (this.getMessageSize() > BlockMessage.MAX_BLOCK_SIZE) {
            throw new VerificationException("Transaction larger than MAX_BLOCK_SIZE");
        }

        long valueOut = 0;
        for (Out output : outs) {
            if (output.getOutValue() < 0) {
                throw new VerificationException("Transaction output negative");
            }
            valueOut = valueOut + output.getOutValue();
        }
        if (valueOut > BitherjSettings.MAX_MONEY) {
            throw new VerificationException("Total transaction output value greater than possible");
        }

        if (isCoinBase()) {
            if (ins.get(0).getInSignature().length < 2 || ins.get(0).getInSignature().length >
                    100) {
                throw new VerificationException("Coinbase script size out of range");
            }
        } else {
            for (In input : ins)
                if (input.isCoinBase()) {
                    throw new VerificationException("Coinbase input as input in non-coinbase " +
                            "transaction");
                }
        }
    }

    /**
     * <p>A transaction is time locked if at least one of its inputs is non-final and it has a
     * lock time</p>
     * <p/>
     * <p>To check if this transaction is final at a given height and time,
     * see {@link net.bither.bitherj.core.Tx#isFinal(int, long)}
     * </p>
     */
    public boolean isTimeLocked() {
        if (getTxLockTime() == 0) {
            return false;
        }
        for (In input : getIns())
            if (input.hasSequence()) {
                return true;
            }
        return false;
    }

    /**
     * <p>Returns true if this transaction is considered finalized and can be placed in a block.
     * Non-finalized
     * transactions won't be included by miners and can be replaced with newer versions using
     * sequence numbers.
     * This is useful in certain types of <a href="http://en.bitcoin
     * .it/wiki/Contracts">contracts</a>, such as
     * micropayment channels.</p>
     * <p/>
     * <p>Note that currently the replacement feature is disabled in the Satoshi client and will
     * need to be
     * re-activated before this functionality is useful.</p>
     */
    public boolean isFinal(int height, long blockTimeSeconds) {
        long time = getTxLockTime();
        if (time < (time < LOCKTIME_THRESHOLD ? height : blockTimeSeconds)) {
            return true;
        }
        if (!isTimeLocked()) {
            return true;
        }
        return false;
    }

//    public long feeForTx() {
//        long amount = 0;
//        for (In in : this.ins) {
//            Tx tx = AbstractDb.txProvider.getTxDetailByTxHash(in.getPrevTxHash());
//            int n = in.getPrevOutSn();
//            if (n > tx.outs.size()) {
//                return Integer.MAX_VALUE;
//            }
//            amount += tx.outs.get(n).getOutValue();
//        }
//
//        for (Out out : this.outs) {
//            amount -= out.getOutValue();
//        }
//        return amount;
//    }

    public long amountReceivedFrom(Address address) {
        long amount = 0;
        for (Out out : this.outs) {
            if (Utils.compareString(address.getAddress(), out.getOutAddress())) {
                amount += out.getOutValue();
            }
        }
        return amount;
    }

//    public long amountSentFrom(Address address) {
//        long amount = 0;
//        for (In in : this.ins) {
//            Tx tx = AbstractDb.txProvider.getTxDetailByTxHash(in.getPrevTxHash());
//            int n = in.getPrevOutSn();
//            for (Out out : tx.getOuts()) {
//                if (n == out.getOutSn() && Utils.compareString(address.getAddress(),
//                        out.getOutAddress())) {
//                    amount += tx.outs.get(n).getOutValue();
//                }
//            }
//        }
//        return amount;
//    }

//    public long amountSentTo(Address address) {
//        long amount = 0;
//        for (Out out : this.outs) {
//            if (Utils.compareString(address.getAddress(), out.getOutAddress())) {
//                amount += out.getOutValue();
//            }
//        }
//        return amount;
//    }

    public long deltaAmountFrom(Address address) {
        if (address instanceof HDAccount) {
            return deltaAmountFrom((HDAccount) address);
        }
        long receive = 0;
        for (Out out : this.outs) {
            if (Utils.compareString(address.getAddress(), out.getOutAddress())) {
                receive += out.getOutValue();
            }
        }
        long sent = AbstractDb.txProvider.sentFromAddress(getTxHash(), address.getAddress());
        return receive - sent;
    }

    public long deltaAmountFrom(HDAccount account) {
        long receive = 0;
        HashSet<String> hashSet = account.getBelongAccountAddresses(getOutAddressList());
        for (Out out : this.outs) {
            if (hashSet.contains(out.getOutAddress())) {
                receive += out.getOutValue();
            }
        }
        long sent = AbstractDb.hdAccountAddressProvider.sentFromAccount(account.getHdSeedId(), getTxHash());
        return receive - sent;
    }

    public List<String> getOutAddressList() {
        List<String> outAddressList = new ArrayList<String>();
        for (Out out : this.outs) {
            String outAddress = out.getOutAddress();
            if (!Utils.isEmpty(outAddress)) {
                outAddressList.add(outAddress);
            }

        }
        return outAddressList;
    }

    public List<String> getInAddresses() {
        boolean canParseFromScript = true;
        List<String> fromAddress = new ArrayList<String>();
        for (In in : getIns()) {
            String address = in.getFromAddress();
            if (address != null) {
                fromAddress.add(address);
            } else {
                canParseFromScript = false;
                break;
            }
        }
        List<String> addresses;
        if (canParseFromScript) {
            addresses = fromAddress;
        } else {
            addresses = AbstractDb.txProvider.getInAddresses(Tx.this);
        }
        return addresses;

    }

    public int getConfirmationCount() {
        return Math.max(0, BlockChain.getInstance().getLastBlock().getBlockNo() - getBlockNo() + 1);
    }

    public List<byte[]> getUnsignedInHashes() {
        List<byte[]> result = new ArrayList<byte[]>();
        for (In in : this.getIns()) {
            byte sigHashType = (byte) TransactionSignature.calcSigHashValue(TransactionSignature
                    .SigHash.ALL, false);
            result.add(this.hashForSignature(in.getInSn(), in.getPrevOutScript(), sigHashType));
        }
        return result;
    }

    public List<byte[]> getUnsignedInHashesForHDM(byte[] pubs) {
        List<byte[]> result = new ArrayList<byte[]>();
        for (In in : this.getIns()) {
            byte sigHashType = (byte) TransactionSignature.calcSigHashValue(TransactionSignature
                    .SigHash.ALL, false);
            result.add(this.hashForSignature(in.getInSn(), pubs, sigHashType));
        }
        return result;
    }

    public List<byte[]> getUnsignedInHashesForDesktpHDM(byte[] pubs, int index) {
        List<byte[]> result = new ArrayList<byte[]>();
        In in = this.getIns().get(index);
        byte sigHashType = (byte) TransactionSignature.calcSigHashValue(TransactionSignature
                .SigHash.ALL, false);
        result.add(this.hashForSignature(in.getInSn(), pubs, sigHashType));
        return result;
    }

    public void signWithSignatures(List<byte[]> signatures) {
//        ECKey key = new ECKey(null, pubKey);
        int i = 0;
        for (In in : this.getIns()) {
            in.setInSignature(signatures.get(i));
            i++;
//            Script scriptPubKey = new Script(in.getPrevOutScript()); //connectedOutput
//            // .getScriptPubKey();
//            if (scriptPubKey.isSentToAddress()) {
//                in.setInSignature(ScriptBuilder.createInputScript(signatures.get(i),
//                        key).getProgram());
//            } else if (scriptPubKey.isSentToRawPubKey()) {
//                in.setInSignature(ScriptBuilder.createInputScript(signatures.get(i)).getProgram
// ());
//            } else {
//                // Should be unreachable - if we don't recognize the type of script we're trying
//                // to sign for, we should
//                // have failed above when fetching the key to sign with.
//                throw new RuntimeException("Do not understand script type: " + scriptPubKey);
//            }

        }
        this.recalculateTxHash();
    }

    public boolean isSigned() {
        boolean isSign = this.getIns().size() > 0;
        for (In in : this.getIns()) {
            isSign &= in.getInSignature() != null && in.getInSignature().length > 0;
        }
        return isSign;
    }

    @Deprecated
    public List<byte[]> getSignPubs(List<byte[]> pubKeys, byte[] params) {

        List<byte[]> pubs = new ArrayList<byte[]>();
        if (this.isSigned()) {
            try {
                In in = null;
                if (this.getIns().size() > 0) {
                    in = this.getIns().get(0);
                    Script scriptSig = new Script(in.getInSignature());

                    byte sigHashType = (byte) TransactionSignature.calcSigHashValue(TransactionSignature
                            .SigHash.ALL, false);
                    byte[] hash = hashForSignature(in.getInSn(), params, sigHashType);
                    List<byte[]> sigs = scriptSig.getSigs();
                    for (byte[] sig : sigs) {
                        byte[] pub = getSignPubs(hash, ECKey.ECDSASignature.decodeFromDER(sig), pubKeys);
                        if (pub != null) {
                            pubs.add(pub);
                        }

                    }

                }

            } catch (ScriptException ex) {
                ex.printStackTrace();

            } catch (Exception ex) {
                ex.printStackTrace();

            }

        }
        return pubs;
    }

    private byte[] getSignPubs(byte[] messageHash,
                               ECKey.ECDSASignature sig, List<byte[]> pubs) {

        for (int i = 0; i < 4; i++) {
            ECPoint point = ECKey.recoverECPointFromSignature(i, sig, messageHash);
            ECKey ecKeyCompress = new ECKey(null, point.getEncoded(true));
            ECKey ecKeyUnCompress = new ECKey(null, point.getEncoded(false));
            for (int j = 0; j < pubs.size(); j++) {
                if (Arrays.equals(ecKeyCompress.getPubKey(), pubs.get(j))) {
                    return ecKeyCompress.getPubKey();

                }
                if (Arrays.equals(ecKeyUnCompress.getPubKey(), pubs.get(j))) {
                    return ecKeyUnCompress.getPubKey();

                }
            }
        }
        return null;
    }


    public boolean verifySignatures() {
        if (this.isSigned()) {
            try {
                for (In in : this.getIns()) {
                    Script scriptSig = new Script(in.getInSignature());
                    byte[] pubkey;
                    if (in.getPrevOutScript() == null || in.getPrevOutScript().length == 0) {
                        return false;
                    }
                    System.out.println("in:" + in.getFromAddress() + "," + in.getInSn());
                    scriptSig.correctlySpends(this, in.getInSn(), new Script(in.getPrevOutScript
                            ()), true);

                }
            } catch (ScriptException ex) {
                ex.printStackTrace();
                return false;
            } catch (Exception ex) {
                ex.printStackTrace();
                return false;
            }
            return true;
        } else {
            return false;
        }
    }

    public boolean hasDustOut() {
        for (Out out : this.getOuts()) {
            if (out.getOutValue() <= Tx.MIN_NONDUST_OUTPUT) {
                return true;
            }
        }
        return false;
    }
}
