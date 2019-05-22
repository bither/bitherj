/*
 * Copyright 2013 Google Inc.
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

package net.bither.bitherj.script;

import com.google.common.collect.Lists;
import com.google.common.primitives.UnsignedBytes;

import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.utils.Utils;

import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkArgument;
import static net.bither.bitherj.script.ScriptOpCodes.OP_0;
import static net.bither.bitherj.script.ScriptOpCodes.OP_CHECKMULTISIG;
import static net.bither.bitherj.script.ScriptOpCodes.OP_CHECKSIG;
import static net.bither.bitherj.script.ScriptOpCodes.OP_DUP;
import static net.bither.bitherj.script.ScriptOpCodes.OP_EQUAL;
import static net.bither.bitherj.script.ScriptOpCodes.OP_EQUALVERIFY;
import static net.bither.bitherj.script.ScriptOpCodes.OP_HASH160;
import static net.bither.bitherj.script.ScriptOpCodes.OP_PUSHDATA1;
import static net.bither.bitherj.script.ScriptOpCodes.OP_PUSHDATA2;
import static net.bither.bitherj.script.ScriptOpCodes.OP_PUSHDATA4;

/**
 * <p>Tools for the construction of commonly used script types. You don't normally need this as it's hidden behind
 * convenience methods on {@link Tx}, but they are useful when working with the
 * protocol at a lower level.</p>
 */
public class ScriptBuilder {
    private List<ScriptChunk> chunks;

    public ScriptBuilder() {
        chunks = Lists.newLinkedList();
    }

    public ScriptBuilder addChunk(ScriptChunk chunk) {
        chunks.add(chunk);
        return this;
    }

    public ScriptBuilder op(int opcode) {
        checkArgument(opcode > OP_PUSHDATA4);
        return addChunk(new ScriptChunk(opcode, null));
    }

    public ScriptBuilder data(byte[] data) {
        // implements BIP62
        byte[] copy = Arrays.copyOf(data, data.length);
        int opcode;
        if (data.length == 0) {
            opcode = OP_0;
        } else if (data.length == 1) {
            byte b = data[0];
            if (b >= 1 && b <= 16)
                opcode = Script.encodeToOpN(b);
            else
                opcode = 1;
        } else if (data.length < OP_PUSHDATA1) {
            opcode = data.length;
        } else if (data.length < 256) {
            opcode = OP_PUSHDATA1;
        } else if (data.length < 65536) {
            opcode = OP_PUSHDATA2;
        } else {
            throw new RuntimeException("Unimplemented");
        }
        return addChunk(new ScriptChunk(opcode, copy));
    }

    public ScriptBuilder smallNum(int num) {
        checkArgument(num >= 0, "Cannot encode negative numbers with smallNum");
        checkArgument(num <= 16, "Cannot encode numbers larger than 16 with smallNum");
        return addChunk(new ScriptChunk(Script.encodeToOpN(num), null));
    }

    public Script build() {
        return new Script(chunks);
    }

    /**
     * Creates a scriptPubKey that encodes payment to the given address.
     */
    public static Script createOutputScript(String to) {
        try {
            if (PrimerjSettings.validAddressPrefixScript(Utils.getAddressHeader(to))) {
                // OP_HASH160 <scriptHash> OP_EQUAL
                return new ScriptBuilder()
                        .op(OP_HASH160)
                        .data(Utils.getAddressHash(to))
                        .op(OP_EQUAL)
                        .build();
            } else if (PrimerjSettings.validAddressPrefixPubkey(Utils.getAddressHeader(to))){
                // OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                return new ScriptBuilder()
                        .op(OP_DUP)
                        .op(OP_HASH160)
                        .data(Utils.getAddressHash(to))
                        .op(OP_EQUALVERIFY)
                        .op(OP_CHECKSIG)
                        .build();
            } else {
                return null;
            }
        } catch (AddressFormatException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    /**
     * Creates a scriptPubKey that encodes payment to the given raw public key.
     */
    public static Script createOutputScript(ECKey key) {
        return new ScriptBuilder().data(key.getPubKey()).op(OP_CHECKSIG).build();
    }

    /**
     * Creates a scriptSig that can redeem a pay-to-address output.
     */
    public static Script createInputScript(TransactionSignature signature, ECKey pubKey) {
        byte[] pubkeyBytes = pubKey.getPubKey();
        return new ScriptBuilder().data(signature.encodeToBitcoin()).data(pubkeyBytes).build();
    }

    /**
     * Creates a scriptSig that can redeem a pay-to-pubkey output.
     */
    public static Script createInputScript(TransactionSignature signature) {
        return new ScriptBuilder().data(signature.encodeToBitcoin()).build();
    }

    /**
     * Creates a program that requires at least N of the given keys to sign, using OP_CHECKMULTISIG.
     */
    public static Script createMultiSigOutputScript(int threshold, List<byte[]> pubkeys) {
        checkArgument(threshold > 0);
        checkArgument(threshold <= pubkeys.size());
        checkArgument(pubkeys.size() <= 16);  // That's the max we can represent with a single opcode.
        ScriptBuilder builder = new ScriptBuilder();
        builder.smallNum(threshold);
        for (byte[] pubs : pubkeys) {
            builder.data(pubs);
        }
        builder.smallNum(pubkeys.size());
        builder.op(OP_CHECKMULTISIG);
        return builder.build();
    }

    /**
     * Create a program that satisfies an OP_CHECKMULTISIG program.
     */
    public static Script createMultiSigInputScript(List<TransactionSignature> signatures) {
        return createP2SHMultiSigInputScript(signatures, null);
    }

    /**
     * Create a program that satisfies an OP_CHECKMULTISIG program.
     */
    public static Script createMultiSigInputScript(TransactionSignature... signatures) {
        return createMultiSigInputScript(Arrays.asList(signatures));
    }

    /**
     * Create a program that satisfies an OP_CHECKMULTISIG program, using pre-encoded signatures.
     */
    public static Script createMultiSigInputScriptBytes(List<byte[]> signatures) {
        return createMultiSigInputScriptBytes(signatures, null);
    }

    /**
     * Create a program that satisfies a pay-to-script hashed OP_CHECKMULTISIG program.
     */
    public static Script createP2SHMultiSigInputScript(List<TransactionSignature> signatures,
                                                       byte[] multisigProgramBytes) {
        List<byte[]> sigs = new ArrayList<byte[]>(signatures.size());
        for (TransactionSignature signature : signatures)
            sigs.add(signature.encodeToBitcoin());
        return createMultiSigInputScriptBytes(sigs, multisigProgramBytes);
    }

    /**
     * Create a program that satisfies an OP_CHECKMULTISIG program, using pre-encoded signatures.
     * Optionally, appends the script program bytes if spending a P2SH output.
     */
    public static Script createMultiSigInputScriptBytes(List<byte[]> signatures, @Nullable byte[] multisigProgramBytes) {
        checkArgument(signatures.size() <= 16);
        ScriptBuilder builder = new ScriptBuilder();
        builder.smallNum(0);  // Work around a bug in CHECKMULTISIG that is now a required part of the protocol.
        for (byte[] signature : signatures)
            builder.data(signature);
        if (multisigProgramBytes != null)
            builder.data(multisigProgramBytes);
        return builder.build();
    }

    /**
     * Creates a scriptPubKey that sends to the given script hash. Read
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP 16</a> to learn more about this
     * kind of script.
     */
    public static Script createP2SHOutputScript(byte[] hash) {
        checkArgument(hash.length == 20);
        return new ScriptBuilder().op(OP_HASH160).data(hash).op(OP_EQUAL).build();
    }

    /**
     * Creates a scriptPubKey for the given redeem script.
     */
    public static Script createP2SHOutputScript(Script redeemScript) {
        byte[] hash = Utils.sha256hash160(redeemScript.getProgram());
        return ScriptBuilder.createP2SHOutputScript(hash);
    }

    /**
     * Creates a P2SH output script with given public keys and threshold. Given public keys will be placed in
     * redeem script in the lexicographical sorting order.
     */
    public static Script createP2SHOutputScript(int threshold, List<byte[]> pubkeys) {
        Script redeemScript = createRedeemScript(threshold, pubkeys);
        return createP2SHOutputScript(redeemScript);
    }

    /**
     * Creates redeem script with given public keys and threshold. Given public keys will be placed in
     * redeem script in the lexicographical sorting order.
     */
    public static Script createRedeemScript(int threshold, List<byte[]> pubkeys) {
        pubkeys = new ArrayList<byte[]>(pubkeys);
        final Comparator comparator = UnsignedBytes.lexicographicalComparator();
        Collections.sort(pubkeys, new Comparator<byte[]>() {
            @Override
            public int compare(byte[] k1, byte[] k2) {
                return comparator.compare(k1, k2);
            }
        });

        return ScriptBuilder.createMultiSigOutputScript(threshold, pubkeys);
    }
}
