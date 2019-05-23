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

import com.google.common.primitives.Ints;

import java.util.Arrays;

import javax.annotation.Nonnull;

public class OutPoint implements Comparable<OutPoint> {
    private byte[] txHash;
    private int outSn;
    private byte[] bytes;

    public OutPoint(byte[] txHash, int outSn) {
        this.txHash = txHash;
        this.outSn = outSn;
        this.bytes = new byte[In.OUTPOINT_MESSAGE_LENGTH];
        System.arraycopy(this.txHash, 0, this.bytes, 0, this.txHash.length);
        System.arraycopy(Ints.toByteArray(this.outSn), 0, this.bytes, this.txHash.length
                , In.OUTPOINT_MESSAGE_LENGTH - this.txHash.length);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof OutPoint)) return false;
        OutPoint otherOutPoint = (OutPoint) other;
        return Arrays.equals(this.txHash, otherOutPoint.txHash) && this.outSn == otherOutPoint.outSn;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.bytes);
    }

    @Override
    public int compareTo(@Nonnull OutPoint other) {
        if (!Arrays.equals(this.txHash, other.txHash) || this.outSn != other.outSn) {
            if (Arrays.equals(this.txHash, other.txHash)) {
                return this.outSn - other.outSn;
            } else {
                return Arrays.hashCode(this.txHash) - Arrays.hashCode(other.txHash);
            }
        } else {
            return 0;
        }
    }

    public int getOutSn() {
        return this.outSn;
    }

    public byte[] getTxHash() {
        return this.txHash;
    }
}
