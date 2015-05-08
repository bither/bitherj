/**
 * Copyright 2011 Google Inc.
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.crypto;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import java.math.BigInteger;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Parses and generates private keys in the form used by the Bitcoin "dumpprivkey" command. This is the private key
 * bytes with a header byte and 4 checksum bytes at the end. If there are 33 private key bytes instead of 32, then
 * the last byte is a discriminator value for the compressed pubkey.
 */
public class DumpedPrivateKey {
    private boolean compressed;

    protected int version;
    protected byte[] bytes;

    // Used by ECKey.getPrivateKeyEncoded()
    public DumpedPrivateKey(byte[] keyBytes, boolean compressed) {
        version = BitherjSettings.dumpedPrivateKeyHeader;
        bytes = encode(keyBytes, compressed);
        checkArgument(version < 256 && version >= 0);
        this.compressed = compressed;
    }

    private static byte[] encode(byte[] keyBytes, boolean compressed) {
        Preconditions.checkArgument(keyBytes.length == 32, "Private keys must be 32 bytes");
        if (!compressed) {
            return keyBytes;
        } else {
            // Keys that have compressed public components have an extra 1 byte on the end in dumped form.
            byte[] bytes = new byte[33];
            System.arraycopy(keyBytes, 0, bytes, 0, 32);
            bytes[32] = 1;
            Utils.wipeBytes(keyBytes);
            return bytes;
        }
    }

    /**
     * Parses the given private key as created by the "dumpprivkey" Bitcoin C++ RPC.
     *
     * @param encoded The base58 encoded string.
     * @throws net.bither.bitherj.exception.AddressFormatException If the string is invalid or the header byte doesn't match the network params.
     */
    public DumpedPrivateKey(String encoded) throws AddressFormatException {
        //todo string encoded
        byte[] tmp = Base58.decodeChecked(encoded);
        version = tmp[0] & 0xFF;
        bytes = new byte[tmp.length - 1];
        System.arraycopy(tmp, 1, bytes, 0, tmp.length - 1);

        if (version != BitherjSettings.dumpedPrivateKeyHeader)
            throw new AddressFormatException("Mismatched version number, trying to cross networks? " + version +
                    " vs " + BitherjSettings.dumpedPrivateKeyHeader);
        if (bytes.length == 33 && bytes[32] == 1) {
            compressed = true;
            bytes = Arrays.copyOf(bytes, 32);  // Chop off the additional marker byte.
        } else if (bytes.length == 32) {
            compressed = false;
        } else {
            throw new AddressFormatException("Wrong number of bytes for a private key, not 32 or 33");
        }
    }

    public void clearPrivateKey() {
        Utils.wipeBytes(bytes);
    }

    /**
     * Returns an ECKey created from this encoded private key.
     */
    public ECKey getKey() {
        return new ECKey(new BigInteger(1, bytes), null, compressed);
    }

    @Override
    public boolean equals(Object other) {
        // This odd construction is to avoid anti-symmetry of equality: where a.equals(b) != b.equals(a).
        boolean result = false;
        if (other instanceof DumpedPrivateKey) {
            result = Arrays.equals(bytes, ((DumpedPrivateKey) other).bytes);
        }
        if (other instanceof DumpedPrivateKey) {
            DumpedPrivateKey o = (DumpedPrivateKey) other;
            result = Arrays.equals(bytes, o.bytes) &&
                    version == o.version &&
                    compressed == o.compressed;
        }
        return result;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(bytes, version, compressed);
    }

    public SecureCharSequence toSecureCharSequence() {
        byte[] addressBytes = new byte[1 + bytes.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, bytes.length + 1);
        System.arraycopy(check, 0, addressBytes, bytes.length + 1, 4);
        return Base58.encodeSecure(addressBytes);
    }

    /**
     * Returns the "version" or "header" byte: the first byte of the data. This is used to disambiguate what the
     * contents apply to, for example, which network the key or address is valid on.
     *
     * @return A positive number between 0 and 255.
     */
    public int getVersion() {
        return version;
    }
}
