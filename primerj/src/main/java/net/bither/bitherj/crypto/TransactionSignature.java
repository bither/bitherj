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

package net.bither.bitherj.crypto;

import net.bither.bitherj.exception.VerificationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * A TransactionSignature wraps an {@link ECKey.ECDSASignature} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */
public class TransactionSignature extends ECKey.ECDSASignature {
    public enum SigHash {
        ALL(0),         // 1
        NONE(1),       // 2
        SINGLE(2),     // 3
        BCCFORK(1|0x40|0),  // 65
        BTGFORK(1|0x40|(79<<8)),
        BTWFORK(1|0x40|87 << 8),
        BTFFORK(1|0x40|70 << 8),
        BTPFORK(1|0x40|80 << 8),
        BTNFORK(1|0x40|88 << 8),
        SBTCFORK(1|0x40);  // 65
        public int value;
        private SigHash (int value) {
            this.value = value;
        }
    }

    public static final byte SIGHASH_ANYONECANPAY_VALUE = (byte) 0x80;

    /**
     * A byte that controls which parts of a transaction are signed. This is exposed because signatures
     * parsed off the wire may have sighash flags that aren't "normal" serializations of the enum values.
     * Because Satoshi's code works via bit testing, we must not lose the exact value when round-tripping
     * otherwise we'll fail to verify signature hashes.
     */
    public int sighashFlags = SigHash.ALL.ordinal() + 1;

    /**
     * Constructs a signature with the given components and SIGHASH_ALL.
     */
    public TransactionSignature(BigInteger r, BigInteger s) {
        super(r, s);
    }

    /**
     * Constructs a transaction signature based on the ECDSA signature.
     */
    public TransactionSignature(ECKey.ECDSASignature signature, SigHash mode, boolean anyoneCanPay) {
        super(signature.r, signature.s);
        setSigHash(mode, anyoneCanPay);
    }

    /**
     * Returns a dummy invalid signature whose R/S values are set such that they will take up the same number of
     * encoded bytes as a real signature. This can be useful when you want to fill out a transaction to be of the
     * right size (e.g. for fee calculations) but don't have the requisite signing key yet and will fill out the
     * real signature later.
     */
    public static TransactionSignature dummy() {
        BigInteger val = ECKey.HALF_CURVE_ORDER;
        return new TransactionSignature(val, val);
    }

    /**
     * Calculates the byte used in the protocol to represent the combination of mode and anyoneCanPay.
     */
    public static int calcSigHashValue(SigHash mode, boolean anyoneCanPay) {
        int sighashFlags = mode.ordinal() + 1;
        if (anyoneCanPay)
            sighashFlags |= SIGHASH_ANYONECANPAY_VALUE;
        if (mode != SigHash.ALL && mode != SigHash.NONE && mode != SigHash.SINGLE) {
           return mode.value;
        }
        return sighashFlags;
    }

    /**
     * Returns true if the given signature is has canonical encoding, and will thus be accepted as standard by
     * the reference client. DER and the SIGHASH encoding allow for quite some flexibility in how the same structures
     * are encoded, and this can open up novel attacks in which a man in the middle takes a transaction and then
     * changes its signature such that the transaction hash is different but it's still valid. This can confuse wallets
     * and generally violates people's mental model of how Bitcoin should work, thus, non-canonical signatures are now
     * not relayed by default.
     */
    public static boolean isEncodingCanonical(byte[] signature) {
        // See reference client's IsCanonicalSignature, https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
        // A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
        // Where R and S are not negative (their first byte has its highest bit not set), and not
        // excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
        // in which case a single 0 byte is necessary and even required).
        if (signature.length < 9 || signature.length > 73)
            return false;

        int hashType = signature[signature.length - 1] & ((int) (~SIGHASH_ANYONECANPAY_VALUE));
        if (hashType < (SigHash.ALL.ordinal() + 1) || hashType > (SigHash.SINGLE.ordinal() + 1))
            return false;

        //                   "wrong type"                  "wrong length marker"
        if ((signature[0] & 0xff) != 0x30 || (signature[1] & 0xff) != signature.length - 3)
            return false;

        int lenR = signature[3] & 0xff;
        if (5 + lenR >= signature.length || lenR == 0)
            return false;
        int lenS = signature[5 + lenR] & 0xff;
        if (lenR + lenS + 7 != signature.length || lenS == 0)
            return false;

        //    R value type mismatch          R value negative
        if (signature[4 - 2] != 0x02 || (signature[4] & 0x80) == 0x80)
            return false;
        if (lenR > 1 && signature[4] == 0x00 && (signature[4 + 1] & 0x80) != 0x80)
            return false; // R value excessively padded

        //       S value type mismatch                    S value negative
        if (signature[6 + lenR - 2] != 0x02 || (signature[6 + lenR] & 0x80) == 0x80)
            return false;
        if (lenS > 1 && signature[6 + lenR] == 0x00 && (signature[6 + lenR + 1] & 0x80) != 0x80)
            return false; // S value excessively padded

        return true;
    }

    /**
     * Configures the sighashFlags field as appropriate.
     */
    public void setSigHash(SigHash mode, boolean anyoneCanPay) {
        sighashFlags = calcSigHashValue(mode, anyoneCanPay);
    }

    public boolean anyoneCanPay() {
        return (sighashFlags & SIGHASH_ANYONECANPAY_VALUE) != 0;
    }

    public SigHash sigHashMode() {
        final int mode = sighashFlags & 0x1f;
        if (mode == SigHash.NONE.ordinal() + 1)
            return SigHash.NONE;
        else if (mode == SigHash.SINGLE.ordinal() + 1)
            return SigHash.SINGLE;
        else if (mode == SigHash.ALL.ordinal() + 1)
            return SigHash.ALL;
        else
            return SigHash.BCCFORK;
    }

    /**
     * What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
     * of the type used by Bitcoin we have to encode them using DER encoding, which is just a way to pack the two
     * components into a structure, and then we append a byte to the end for the sighash flags.
     */
    public byte[] encodeToBitcoin() {
        try {
            ByteArrayOutputStream bos = derByteStream();
            bos.write(sighashFlags);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns a decoded signature.
     *
     * @throws RuntimeException if the signature is invalid or unparseable in some way.
     */
    public static TransactionSignature decodeFromBitcoin(byte[] bytes, boolean requireCanonical) throws VerificationException {
        // Bitcoin encoding is DER signature + sighash byte.
        if (requireCanonical && !isEncodingCanonical(bytes))
            throw new VerificationException("Signature encoding is not canonical.");
        ECKey.ECDSASignature sig;
        try {
            sig = decodeFromDER(bytes);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("Could not decode DER", e);
        }
        TransactionSignature tsig = new TransactionSignature(sig.r, sig.s);
        // In Bitcoin, any value of the final byte is valid, but not necessarily canonical. See javadocs for
        // isEncodingCanonical to learn more about this.
        tsig.sighashFlags = bytes[bytes.length - 1];
        return tsig;
    }
}
