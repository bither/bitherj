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
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.exception.ScriptException;
import net.bither.bitherj.message.Message;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.UnsafeByteArrayOutputStream;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class Out extends Message {


    private static final Logger log = LoggerFactory.getLogger(Out.class);

    private byte[] txHash;
    private int outSn;
    private byte[] outScript;
    private long outValue;
    private OutStatus outStatus = OutStatus.unspent;
    private String outAddress;
    private long coinDepth;

    private int hdAccountId = -1;

    private int desktopHDMAccountId = -1;


//    private int coldHDAccountId=-1;

    private Tx tx;


    public Out() {

    }

    public Out(Tx tx, byte[] msg, int offset) {
        super(msg, offset);
        this.tx = tx;
        this.txHash = this.tx.getTxHash();
    }

    public Out(Tx parent, long value, String to) {
        this(parent, value, ScriptBuilder.createOutputScript(to).getProgram());
    }

    public Out(Tx parent, long value, ECKey to) {
        this(parent, value, ScriptBuilder.createOutputScript(to).getProgram());
    }

//    public Out(Tx parent, BigInteger value, byte[] scriptBytes) {
//        super();
//        // Negative values obviously make no sense, except for -1 which is used as a sentinel
// value when calculating
//        // SIGHASH_SINGLE signatures, so unfortunately we have to allow that here.
//        checkArgument(value.compareTo(BigInteger.ZERO) >= 0 || value.equals(Utils.NEGATIVE_ONE)
// , "Negative values not allowed");
//        checkArgument(value.compareTo(BitherjSettings.MAX_MONEY) < 0, "Values larger than
// MAX_MONEY not allowed");
//        this.value = value;
//        this.outScript = scriptBytes;
//        this.tx = parent;
////        availableForSpending = true;
//        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
//    }

    public Out(Tx parent, long value, byte[] scriptBytes) {
        super();
        // Negative values obviously make no sense, except for -1 which is used as a sentinel
        // value when calculating
        // SIGHASH_SINGLE signatures, so unfortunately we have to allow that here.
        checkArgument(value >= 0 || value == -1, "Negative values not allowed");
        checkArgument(value < BitherjSettings.MAX_MONEY, "Values larger than MAX_MONEY not " +
                "allowed");
        this.outValue = value;
        this.outScript = scriptBytes;
        this.tx = parent;
        this.txHash = this.tx.getTxHash();
//        availableForSpending = true;
        length = 8 + VarInt.sizeOf(scriptBytes.length) + scriptBytes.length;
    }


    public byte[] getTxHash() {
        return txHash;
    }

    public void setTxHash(byte[] txHash) {
        this.txHash = txHash;
    }

    public int getOutSn() {
        return outSn;
    }

    public void setOutSn(int outSn) {
        this.outSn = outSn;
    }

    public byte[] getOutScript() {
        return outScript;
    }

    public void setOutScript(byte[] outScript) {
        this.outScript = outScript;
    }

    public long getOutValue() {
        return outValue;
    }

    public void setOutValue(long outValue) {
        this.outValue = outValue;
    }

    public OutStatus getOutStatus() {
        return outStatus;
    }

    public void setOutStatus(OutStatus outStatus) {
        this.outStatus = outStatus;
    }

    public String getOutAddress() {
        if (outAddress == null) {
            try {
                Script pubKeyScript = new Script(this.getOutScript());
                outAddress = pubKeyScript.getToAddress();
            } catch (ScriptException e) {
//                if (this.getOutScript() != null) {
//                    log.warn("out script : " + Utils.bytesToHexString(this.getOutScript()));
//                }
            }
        }
        return outAddress;
    }

    public void setOutAddress(String outAddress) {
        this.outAddress = outAddress;
    }

    public long getCoinDepth() {
        return coinDepth;
    }

    public void setCoinDepth(long coinDepth) {
        this.coinDepth = coinDepth;
    }

    public Tx getTx() {
        return tx;
    }

    public void setTx(Tx tx) {
        this.tx = tx;
        this.txHash = tx.getTxHash();
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Out) {
            Out outItem = (Out) o;
            return getOutSn() == outItem.getOutSn() &&
                    Arrays.equals(getTxHash(), outItem.getTxHash()) &&
                    Arrays.equals(getOutScript(), outItem.getOutScript()) &&
                    getOutValue() == outItem.getOutValue() &&
                    getOutStatus() == outItem.getOutStatus() &&
                    Utils.compareString(getOutAddress(), outItem.getOutAddress());

        } else {
            return false;
        }
    }

    public enum OutStatus {
        unspent(0), spent(1);
        private int mValue;

        OutStatus(int value) {
            this.mValue = value;
        }

        public int getValue() {
            return this.mValue;
        }

    }

    public static OutStatus getOutStatus(int status) {
        if (status == 1) {
            return OutStatus.spent;
        } else {
            return OutStatus.unspent;
        }
    }

    public int getHDAccountId() {
        return hdAccountId;
    }

    public void setHDAccountId(int hdAccountId) {
        this.hdAccountId = hdAccountId;
    }

//    public int getColdHDAccountId() {
//        return coldHDAccountId;
//    }

//    public void setColdHDAccountId(int coldHDAccountId) {
//        this.coldHDAccountId = coldHDAccountId;
//    }


    public int getDesktopHDMAccountId() {
        return desktopHDMAccountId;
    }

    public void setDesktopHDMAccountId(int desktopHDMAccountId) {
        this.desktopHDMAccountId = desktopHDMAccountId;
    }

    public byte[] getOutpointData() {
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(36 + 32);
        try {
            stream.write(getTxHash());
            Utils.uint32ToByteStreamLE(getOutSn(), stream);
        } catch (IOException e) {
            return null;
        }
        return stream.toByteArray();
    }

    //    // The script bytes are parsed and turned into a Script on demand.
    private transient WeakReference<Script> scriptPubKey;
    //
//    // These fields are Java serialized but not Bitcoin serialized. They are used for tracking
// purposes in our wallet
//    // only. If set to true, this output is counted towards our balance. If false and spentBy
// is null the tx output
//    // was owned by us and was sent to somebody else. If false and spentBy is set it means this
// output was owned by
//    // us and used in one of our own transactions (eg, because it is a change output).
//    private boolean availableForSpending;
////    private In spentBy;
//
//    // A reference to the transaction which holds this output.
//    Tx parentTransaction;
    private transient int scriptLen;

    //
    public Script getScriptPubKey() throws ScriptException {
        // Quick hack to try and reduce memory consumption on Androids. SoftReference is the same
        // as WeakReference
        // on Dalvik (by design), so this arrangement just means that we can avoid the cost of
        // re-parsing the script
        // bytes if getScriptPubKey is called multiple times in quick succession in between
        // garbage collections.
        Script script = scriptPubKey == null ? null : scriptPubKey.get();
        if (script == null) {
            script = new Script(outScript);
            scriptPubKey = new WeakReference<Script>(script);
            return script;
        }
        return script;
    }

    protected void parse() throws ProtocolException {
        outValue = readInt64();

        scriptLen = (int) readVarInt();
        length = cursor - offset + scriptLen;
        outScript = readBytes(scriptLen);
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        checkNotNull(outScript);
        Utils.int64ToByteStreamLE(outValue, stream);
        // TODO: Move script serialization into the Script class, where it belongs.
        stream.write(new VarInt(outScript.length).encode());
        stream.write(outScript);
    }

    /**
     * <p>Gets the minimum value for a txout of this size to be considered non-dust by a
     * reference client
     * (and thus relayed). See: CTxOut::IsDust() in the reference client. The assumption is that
     * any output that would
     * consume more than a third of its value in fees is not something the Bitcoin system wants
     * to deal with right now,
     * so we call them "dust outputs" and they're made non standard. The choice of one third is
     * somewhat arbitrary and
     * may change in future.</p>
     * <p/>
     * <p>You probably should use {@link net.bither.bitherj.core.Out#getMinNonDustValue()} which
     * uses
     * a safe fee-per-kb by default.</p>
     *
     * @param feePerKbRequired The fee required per kilobyte. Note that this is the same as the
     *                         reference client's -minrelaytxfee * 3
     *                         If you want a safe default, use {@link net.bither.bitherj.core
     *                         .Tx#REFERENCE_DEFAULT_MIN_TX_FEE}*3
     */
    public BigInteger getMinNonDustValue(BigInteger feePerKbRequired) {
        // A typical output is 33 bytes (pubkey hash + opcodes) and requires an input of 148
        // bytes to spend so we add
        // that together to find out the total amount of data used to transfer this amount of
        // value. Note that this
        // formula is wrong for anything that's not a pay-to-address output, unfortunately, we
        // must follow the reference
        // clients wrongness in order to ensure we're considered standard. A better formula would
        // either estimate the
        // size of data needed to satisfy all different script types, or just hard code 33 below.
        final BigInteger size = BigInteger.valueOf(this.bitcoinSerialize().length + 148);
        BigInteger[] nonDustAndRemainder = feePerKbRequired.multiply(size).divideAndRemainder
                (BigInteger.valueOf(1000));
        return nonDustAndRemainder[1].equals(BigInteger.ZERO) ? nonDustAndRemainder[0] :
                nonDustAndRemainder[0].add(BigInteger.ONE);
    }

    /**
     * Returns the minimum value for this output to be considered "not dust", i.e. the
     * transaction will be relayable
     * and mined by default miners. For normal pay to address outputs, this is 5460 satoshis, the
     * same as
     * {@link net.bither.bitherj.core.Tx#MIN_NONDUST_OUTPUT}.
     */
    public BigInteger getMinNonDustValue() {
        return getMinNonDustValue(BigInteger.valueOf(Tx.REFERENCE_DEFAULT_MIN_TX_FEE * 3));
    }
}
