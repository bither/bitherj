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

package net.bither.bitherj.crypto;

import net.bither.bitherj.crypto.ec.Parameters;
import net.bither.bitherj.exception.URandomNotFoundException;

import java.math.BigInteger;

public class XRandom {

    private IUEntropy uEntropy;

    public XRandom(IUEntropy uEntropy) {
        this.uEntropy = uEntropy;
    }

    public byte[] getRandomBytes() throws URandomNotFoundException {
        int nBitLength = Parameters.n.bitLength();
        int byteLength = nBitLength / 8;
        byte[] uRandomBytes = getURandomBytes(byteLength);
        if (this.uEntropy == null) {
            return uRandomBytes;
        }
        byte[] result = new byte[byteLength];
        byte[] userEntropyBytes = getUEntropyBytes(byteLength);
        for (int i = 0; i < uRandomBytes.length; i++) {
            result[i] = (byte) (uRandomBytes[i] ^ userEntropyBytes[i]);
        }
        return result;

    }

    private byte[] getURandomBytes(int length) throws URandomNotFoundException {
        BigInteger d;
        byte[] uRandomBytes;
        do {
            uRandomBytes = new byte[length];
            URandom.nextBytes(uRandomBytes);
            uRandomBytes[0] = (byte) (uRandomBytes[0] & 0x7F); // ensure positive number
            d = new BigInteger(uRandomBytes);

        } while (d.equals(BigInteger.ZERO) || (d.compareTo(Parameters.n) >= 0));
        return uRandomBytes;
    }

    private byte[] getUEntropyBytes(int length) {
        BigInteger d;
        byte[] uEntropyBytes;
        do {
            uEntropyBytes = new byte[length];
            this.uEntropy.nextBytes(uEntropyBytes);
            uEntropyBytes[0] = (byte) (uEntropyBytes[0] & 0x7F); // ensure positive number
            d = new BigInteger(uEntropyBytes);
        } while (d.equals(BigInteger.ZERO) || (d.compareTo(Parameters.n) >= 0));
        return uEntropyBytes;
    }
}
