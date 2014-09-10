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

public class XRandom {

    private byte[] userEntropyBytes;

    public XRandom(byte[] userEntropyBytes) {
        this.userEntropyBytes = userEntropyBytes;
    }

    public byte[] getRandomBytes() {
        int nBitLength = Parameters.n.bitLength();
        if (userEntropyBytes.length < nBitLength / 8) {
            throw new RuntimeException("user entropy bytes is not enough ");
        }
        byte[] uRandomBytes = new byte[nBitLength / 8];
        URandom.nextBytes(uRandomBytes);
        byte[] result = new byte[nBitLength / 8];
        for (int i = 0; i < uRandomBytes.length; i++) {
            result[i] = (byte) (uRandomBytes[i] ^ userEntropyBytes[i]);
        }
        return result;

    }
}
