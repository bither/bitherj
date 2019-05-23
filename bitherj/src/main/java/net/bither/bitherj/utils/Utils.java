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

package net.bither.bitherj.utils;

import com.google.common.base.Charsets;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.common.primitives.UnsignedLongs;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.core.Coin;
import net.bither.bitherj.core.SplitCoin;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.core.Coin;
import net.bither.bitherj.core.SplitCoin;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.exception.AddressFormatException;

import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {


    public static final BigInteger NEGATIVE_ONE = BigInteger.valueOf(-1);
    private static final MessageDigest digest;

    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    public static long longHash(@Nonnull final byte[] bytes) {

        return (bytes[31] & 0xFFl) | ((bytes[30] & 0xFFl) << 8)
                | ((bytes[29] & 0xFFl) << 16) | ((bytes[28] & 0xFFl) << 24)
                | ((bytes[27] & 0xFFl) << 32) | ((bytes[26] & 0xFFl) << 40)
                | ((bytes[25] & 0xFFl) << 48) | ((bytes[23] & 0xFFl) << 56);
    }

    /**
     * The string that prefixes all text messages signed using Bitcoin keys.
     */
    public static final String BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n";
    public static final byte[] BITCOIN_SIGNED_MESSAGE_HEADER_BYTES =
            BITCOIN_SIGNED_MESSAGE_HEADER.getBytes(Charsets.UTF_8);

    // TODO: Replace this nanocoins business with something better.

    /**
     * How many "nanocoins" there are in a Bitcoin.
     * <p/>
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion.
     */
    public static final BigInteger COIN = new BigInteger("100000000", 10);

    /**
     * How many "nanocoins" there are in 0.01 BitCoins.
     * <p/>
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion).
     */
    public static final long CENT = 1000000;
    private static BlockingQueue<Boolean> mockSleepQueue;

    /**
     * The regular {@link java.math.BigInteger#toByteArray()} method isn't quite what we often
     * need: it appends a
     * leading zero to indicate that the number is positive and may need padding.
     *
     * @param b        the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null) {
            return null;
        }
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    /**
     * Convert an amount expressed in the way humans are used to into nanocoins.<p>
     * <p/>
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
     * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
     *
     * @throws ArithmeticException if you try to specify fractional nanocoins,
     *                             or nanocoins out of range.
     */
    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >> 8));
        out[offset + 3] = (byte) (0xFF & (val));
    }

    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val));
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
    }

    public static void uint64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset] = (byte) (0xFF & (val));
        out[offset + 1] = (byte) (0xFF & (val >> 8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));
        out[offset + 4] = (byte) (0xFF & (val >> 32));
        out[offset + 5] = (byte) (0xFF & (val >> 40));
        out[offset + 6] = (byte) (0xFF & (val >> 48));
        out[offset + 7] = (byte) (0xFF & (val >> 56));
    }

    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
    }

    public static void int64ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int) (0xFF & (val)));
        stream.write((int) (0xFF & (val >> 8)));
        stream.write((int) (0xFF & (val >> 16)));
        stream.write((int) (0xFF & (val >> 24)));
        stream.write((int) (0xFF & (val >> 32)));
        stream.write((int) (0xFF & (val >> 40)));
        stream.write((int) (0xFF & (val >> 48)));
        stream.write((int) (0xFF & (val >> 56)));
    }

    public static void uint64ToByteStreamLE(BigInteger val, OutputStream stream) throws
            IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) {
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0;
                 i < 8 - bytes.length;
                 i++)
                stream.write(0);
        }
    }

    /**
     * See {@link Utils#doubleDigest(byte[], int, int)}.
     */
    public static byte[] doubleDigest(byte[] input) {
        return doubleDigest(input, 0, input.length);
    }

    /**
     * Calculates the SHA-256 hash of the given byte range, and then hashes the resulting hash
     * again. This is
     * standard procedure in Bitcoin. The resulting hash is in big endian form.
     */
    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    public static byte[] singleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            return digest.digest();
        }
    }

    /**
     * Calculates SHA256(SHA256(byte range 1 + byte range 2)).
     */
    public static byte[] doubleDigestTwoBuffers(byte[] input1, int offset1, int length1,
                                                byte[] input2, int offset2, int length2) {
        synchronized (digest) {
            digest.reset();
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    /**
     * Work around lack of unsigned types in Java.
     */
    public static boolean isLessThanUnsigned(long n1, long n2) {
        return UnsignedLongs.compare(n1, n2) < 0;
    }

    public static String hashToString(byte[] bytes) {
        return bytesToHexString(reverseBytes(bytes));
    }

    final protected static char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * Returns the given byte array hex encoded.
     */
    public static String bytesToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars).toUpperCase(Locale.US);
    }


    /**
     * Returns a copy of the given byte array in reverse order.
     */
    public static byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find
        // this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    /**
     * Returns a copy of the given byte array with the bytes of each double-word (4 bytes) reversed.
     *
     * @param bytes      length must be divisible by 4.
     * @param trimLength trim output to this length.  If positive, must be divisible by 4.
     */
    public static byte[] reverseDwordBytes(byte[] bytes, int trimLength) {
        checkArgument(bytes.length % 4 == 0);
        checkArgument(trimLength < 0 || trimLength % 4 == 0);

        byte[] rev = new byte[trimLength >= 0 && bytes.length > trimLength ? trimLength : bytes
                .length];

        for (int i = 0; i < rev.length; i += 4) {
            System.arraycopy(bytes, i, rev, i, 4);
            for (int j = 0; j < 4; j++) {
                rev[i + j] = bytes[i + 3 - j];
            }
        }
        return rev;
    }

    public static long readUint32(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL)) |
                ((bytes[offset++] & 0xFFL) << 8) |
                ((bytes[offset++] & 0xFFL) << 16) |
                ((bytes[offset] & 0xFFL) << 24);
    }

    public static long readInt64(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL)) |
                ((bytes[offset++] & 0xFFL) << 8) |
                ((bytes[offset++] & 0xFFL) << 16) |
                ((bytes[offset++] & 0xFFL) << 24) |
                ((bytes[offset++] & 0xFFL) << 32) |
                ((bytes[offset++] & 0xFFL) << 40) |
                ((bytes[offset++] & 0xFFL) << 48) |
                ((bytes[offset] & 0xFFL) << 56);
    }

    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFFL) << 24) |
                ((bytes[offset + 1] & 0xFFL) << 16) |
                ((bytes[offset + 2] & 0xFFL) << 8) |
                ((bytes[offset + 3] & 0xFFL));
    }

    public static int readUint16BE(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | bytes[offset + 1] & 0xff;
    }

    /**
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(input);
            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.doFinal(out, 0);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns the given value in nanocoins as a 0.12 type string. More digits after the decimal
     * place will be used
     * if necessary, but two will always be present.
     */
    public static String bitcoinValueToFriendlyString(BigInteger value) {
        // TODO: This API is crap. This method should go away when we encapsulate money values.
        boolean negative = value.compareTo(BigInteger.ZERO) < 0;
        if (negative) {
            value = value.negate();
        }
        BigDecimal bd = new BigDecimal(value, 8);
        String formatted = bd.toPlainString();   // Don't use scientific notation.
        int decimalPoint = formatted.indexOf(".");
        // Drop unnecessary zeros from the end.
        int toDelete = 0;
        for (int i = formatted.length() - 1; i > decimalPoint + 2; i--) {
            if (formatted.charAt(i) == '0') {
                toDelete++;
            } else {
                break;
            }
        }
        return (negative ? "-" : "") + formatted.substring(0, formatted.length() - toDelete);
    }

    /**
     * <p>
     * Returns the given value as a plain string denominated in BTC.
     * The result is unformatted with no trailing zeroes.
     * For instance, an input value of BigInteger.valueOf(150000) nanocoin gives an output string
     * of "0.0015" BTC
     * </p>
     *
     * @param value The value in nanocoins to convert to a string (denominated in BTC)
     * @throws IllegalArgumentException If the input value is null
     */
    public static String bitcoinValueToPlainString(long value) {
        BigDecimal valueInBTC = new BigDecimal(BigInteger.valueOf(value)).divide(new BigDecimal(Utils.COIN));
        return valueInBTC.toPlainString();
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     *
     * @param hasLength can be set to false if the given array is missing the 4 byte length field
     */
    public static BigInteger decodeMPI(byte[] mpi, boolean hasLength) {
        byte[] buf;
        if (hasLength) {
            int length = (int) readUint32BE(mpi, 0);
            buf = new byte[length];
            System.arraycopy(mpi, 4, buf, 0, length);
        } else {
            buf = mpi;
        }
        if (buf.length == 0) {
            return BigInteger.ZERO;
        }
        boolean isNegative = (buf[0] & 0x80) == 0x80;
        if (isNegative) {
            buf[0] &= 0x7f;
        }
        BigInteger result = new BigInteger(buf);
        return isNegative ? result.negate() : result;
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     *
     * @param includeLength indicates whether the 4 byte length field should be included
     */
    public static byte[] encodeMPI(BigInteger value, boolean includeLength) {
        if (value.equals(BigInteger.ZERO)) {
            if (!includeLength) {
                return new byte[]{};
            } else {
                return new byte[]{0x00, 0x00, 0x00, 0x00};
            }
        }
        boolean isNegative = value.compareTo(BigInteger.ZERO) < 0;
        if (isNegative) {
            value = value.negate();
        }
        byte[] array = value.toByteArray();
        int length = array.length;
        if ((array[0] & 0x80) == 0x80) {
            length++;
        }
        if (includeLength) {
            byte[] result = new byte[length + 4];
            System.arraycopy(array, 0, result, length - array.length + 3, array.length);
            uint32ToByteArrayBE(length, result, 0);
            if (isNegative) {
                result[4] |= 0x80;
            }
            return result;
        } else {
            byte[] result;
            if (length != array.length) {
                result = new byte[length];
                System.arraycopy(array, 0, result, 1, array.length);
            } else {
                result = array;
            }
            if (isNegative) {
                result[0] |= 0x80;
            }
            return result;
        }
    }

    // The representation of nBits uses another home-brew encoding, as a way to represent a large
    // hash value in only 32 bits.
    public static BigInteger decodeCompactBits(long compact) {
        int size = ((int) (compact >> 24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) {
            bytes[4] = (byte) ((compact >> 16) & 0xFF);
        }
        if (size >= 2) {
            bytes[5] = (byte) ((compact >> 8) & 0xFF);
        }
        if (size >= 3) {
            bytes[6] = (byte) ((compact) & 0xFF);
        }
        return decodeMPI(bytes, true);
    }

    /**
     * If non-null, overrides the return value of now().
     */
    public static volatile Date mockTime;

    /**
     * Advances (or rewinds) the mock clock by the given number of seconds.
     */
    public static Date rollMockClock(int seconds) {
        return rollMockClockMillis(seconds * 1000);
    }

    /**
     * Advances (or rewinds) the mock clock by the given number of milliseconds.
     */
    public static Date rollMockClockMillis(long millis) {
        if (mockTime == null) {
            mockTime = new Date();
        }
        mockTime = new Date(mockTime.getTime() + millis);
        return mockTime;
    }

    /**
     * Sets the mock clock to the given time (in seconds)
     */
    public static void setMockClock(long mockClock) {
        mockTime = new Date(mockClock * 1000);
    }

    /**
     * Returns the current time, or a mocked out equivalent.
     */
    public static Date now() {
        if (mockTime != null) {
            return mockTime;
        } else {
            return new Date();
        }
    }

    /**
     * Returns the current time in seconds since the epoch, or a mocked out equivalent.
     */
    public static long currentTimeMillis() {
        if (mockTime != null) {
            return mockTime.getTime();
        } else {
            return System.currentTimeMillis();
        }
    }

    public static byte[] copyOf(byte[] in, int length) {
        byte[] out = new byte[length];
        System.arraycopy(in, 0, out, 0, Math.min(length, in.length));
        return out;
    }

    /**
     * Creates a copy of bytes and appends b to the end of it
     */
    public static byte[] appendByte(byte[] bytes, byte b) {
        byte[] result = Arrays.copyOf(bytes, bytes.length + 1);
        result[result.length - 1] = b;
        return result;
    }

    /**
     * Attempts to parse the given string as arbitrary-length hex or base58 and then return the
     * results, or null if
     * neither parse was successful.
     */
    public static byte[] parseAsHexOrBase58(String data) {
        try {
            return Hex.decode(data);
        } catch (Exception e) {
            // Didn't decode as hex, try base58.
            try {
                return Base58.decodeChecked(data);
            } catch (AddressFormatException e1) {
                return null;
            }
        }
    }

    public static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    /**
     * <p>Given a textual message, returns a byte buffer formatted as follows:</p>
     * <p/>
     * <tt><p>[24] "Bitcoin Signed Message:\n" [message.length as a varint] message</p></tt>
     */
    public static byte[] formatMessageForSigning(String message) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES.length);
            bos.write(BITCOIN_SIGNED_MESSAGE_HEADER_BYTES);
            byte[] messageBytes = message.getBytes(Charsets.UTF_8);
            VarInt size = new VarInt(messageBytes.length);
            bos.write(size.encode());
            bos.write(messageBytes);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static byte[] getPreSignMessage(String message) {
        byte[] data = formatMessageForSigning(message);
        return Utils.doubleDigest(data);
    }

    // 00000001, 00000010, 00000100, 00001000, ...
    private static final int bitMask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    // Checks if the given bit is set in data
    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index >>> 3] & bitMask[7 & index]) != 0;
    }

    // Sets the given bit in data to one
    public static void setBitLE(byte[] data, int index) {
        data[index >>> 3] |= bitMask[7 & index];
    }

    /**
     * Sleep for a span of time, or mock sleep if enabled
     */
    public static void sleep(long millis) {
        if (mockSleepQueue == null) {
            sleepUninterruptibly(millis, TimeUnit.MILLISECONDS);
        } else {
            try {
                boolean isMultiPass = mockSleepQueue.take();
                rollMockClockMillis(millis);
                if (isMultiPass) {
                    mockSleepQueue.offer(true);
                }
            } catch (InterruptedException e) {
                // Ignored.
            }
        }
    }

    /**
     * Enable or disable mock sleep.  If enabled, set mock time to current time.
     */
    public static void setMockSleep(boolean isEnable) {
        if (isEnable) {
            mockSleepQueue = new ArrayBlockingQueue<Boolean>(1);
            mockTime = new Date(System.currentTimeMillis());
        } else {
            mockSleepQueue = null;
        }
    }

    /**
     * Let sleeping thread pass the synchronization point.
     */
    public static void passMockSleep() {
        mockSleepQueue.offer(false);
    }

    /**
     * Let the sleeping thread pass the synchronization point any number of times.
     */
    public static void finishMockSleep() {
        if (mockSleepQueue != null) {
            mockSleepQueue.offer(true);
        }
    }

    public static boolean isEmpty(String str) {
        return str == null || str.equals("");
    }

    public static boolean compareString(String str, String other) {
        if (str == null) {
            return other == null;
        } else {
            return other != null && str.equals(other);
        }

    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0;
             i < len;
             i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s
                    .charAt(i + 1), 16));
        }
        return data;
    }

    public static String toAddress(byte[] pubKeyHash) {
        checkArgument(pubKeyHash.length == 20, "Addresses are 160-bit hashes, " +
                "so you must provide 20 bytes");

        int version = PrimerjSettings.addressHeader;
        checkArgument(version < 256 && version >= 0);

        byte[] addressBytes = new byte[1 + pubKeyHash.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(pubKeyHash, 0, addressBytes, 1, pubKeyHash.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, pubKeyHash.length + 1);
        System.arraycopy(check, 0, addressBytes, pubKeyHash.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    public static String toP2SHAddress(byte[] pubKeyHash) {
        checkArgument(pubKeyHash.length == 20, "Addresses are 160-bit hashes, " +
                "so you must provide 20 bytes");

        int version = PrimerjSettings.p2shHeader;
        checkArgument(version < 256 && version >= 0);

        byte[] addressBytes = new byte[1 + pubKeyHash.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(pubKeyHash, 0, addressBytes, 1, pubKeyHash.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, pubKeyHash.length + 1);
        System.arraycopy(check, 0, addressBytes, pubKeyHash.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    public static String toAddress(byte[] pubKeyHash, Coin coin) {
        checkArgument(pubKeyHash.length == 20, "Addresses are 160-bit hashes, " +
                "so you must provide 20 bytes");

        int version = coin.getAddressHeader();
        checkArgument(version < 256 && version >= 0);

        byte[] addressBytes = new byte[1 + pubKeyHash.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(pubKeyHash, 0, addressBytes, 1, pubKeyHash.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, pubKeyHash.length + 1);
        System.arraycopy(check, 0, addressBytes, pubKeyHash.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    public static String toP2SHAddress(byte[] pubKeyHash, Coin coin) {
        checkArgument(pubKeyHash.length == 20, "Addresses are 160-bit hashes, " +
                "so you must provide 20 bytes");

        int version = coin.getP2shHeader();
        checkArgument(version < 256 && version >= 0);

        byte[] addressBytes = new byte[1 + pubKeyHash.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(pubKeyHash, 0, addressBytes, 1, pubKeyHash.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, pubKeyHash.length + 1);
        System.arraycopy(check, 0, addressBytes, pubKeyHash.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    public static String toSegwitAddress(byte[] pubKeyHash) {
        assert (pubKeyHash.length == 20);

        int version = PrimerjSettings.p2shHeader;;
        assert (version < 256 && version >= 0);

        byte[] scriptSig = new byte[pubKeyHash.length + 2];
        scriptSig[0] = 0x00;
        scriptSig[1] = (byte) pubKeyHash.length;
        System.arraycopy(pubKeyHash, 0, scriptSig, 2, pubKeyHash.length);
        byte[] addressBytes = Utils.sha256hash160(scriptSig);

        byte[] b = new byte[1 + addressBytes.length + 4];
        b[0] = (byte) version;
        System.arraycopy(addressBytes, 0, b, 1, addressBytes.length);
        byte[] check = doubleDigest(b, 0, addressBytes.length + 1);
        System.arraycopy(check, 0, b, addressBytes.length + 1, 4);
        return Base58.encode(b);

    }

    public static int getAddressHeader(String address) throws AddressFormatException {
        byte[] tmp = Base58.decodeChecked(address);
        return tmp[0] & 0xFF;
    }

    public static byte[] getAddressHash(String address) throws AddressFormatException {
        byte[] tmp = Base58.decodeChecked(address);
        byte[] bytes = new byte[tmp.length - 1];
        System.arraycopy(tmp, 1, bytes, 0, tmp.length - 1);
        return bytes;
    }

    //add by jjz (bither)
    private static final String WALLET_ROM_CACHE = "wallet";
    private static final String WALLET_WATCH_ONLY = "watch";
    private static final String WALLET_HOT = "hot";
    private static final String WALLET_COLD = "cold";
    private static final String WALLET_TRASH = "trash";

    //add by jjz (bither)
    public static File getWalletRomCache() {
        return AbstractApp.bitherjSetting.getPrivateDir(WALLET_ROM_CACHE);
    }

    //add by jjz (bither)
    public static File getWatchOnlyDir() {
        File file = getWalletRomCache();
        file = new File(file, WALLET_WATCH_ONLY);
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    //add by jjz (bither)
    public static File getPrivateDir() {
        File file = getWalletRomCache();
        String dirName = WALLET_HOT;
        if (AbstractApp.bitherjSetting.getAppMode() == PrimerjSettings.AppMode.COLD) {
            dirName = WALLET_COLD;
        }
        file = new File(file, dirName);
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    public static File getTrashDir() {
        File file = getWalletRomCache();
        String dirName = WALLET_TRASH;
        file = new File(file, dirName);
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    //add by jjz (bither)
    public static void writeFile(String data, File tar) throws IOException {
        writeFile(data.getBytes(), tar);
    }

    //add by jjz (bither)
    public static void writeFile(byte[] data, File tar) throws IOException {
        FileOutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(tar);
            outputStream.write(data);
            outputStream.flush();
            outputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }

    //add by jjz (bither)
    public static String readFile(File file) {
        if (!file.exists()) {
            return null;
        }
        ByteArrayOutputStream arrayOutputStream = null;
        try {
            FileInputStream is = new FileInputStream(file);
            byte[] bytes = new byte[1024];

            arrayOutputStream = new ByteArrayOutputStream();
            int count;
            while ((count = is.read(bytes)) != -1) {
                arrayOutputStream.write(bytes, 0, count);
            }
            is.close();
            arrayOutputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return new String(arrayOutputStream.toByteArray());

    }

    //add by jjz (bither)
    public static void removeFile(File file) {
        if (file.exists()) {
            file.delete();
        }
    }

    public static void moveFile(File oldFile, File newFile) {
        if (oldFile.exists()) {
            oldFile.renameTo(newFile);
        }
    }

    //add by jjz (bither)
    public static String format(String format, Object... args) {
        return String.format(Locale.US, format, args);
    }

    //add by jjz (bither)
    public static String shortenAddress(String address) {
        if (address != null && address.length() > 4) {
            return address.substring(0, 4) + " ...";
        } else {
            return address;
        }
    }

    //Added by scw (bither)
    public static long parseLongFromAddress(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length >= Longs.BYTES) {
            return Longs.fromByteArray(bytes);
        } else {
            return Ints.fromByteArray(bytes);
        }
    }

    public static String formatDoubleToMoneyString(double num) {
        java.text.DecimalFormat formate = new DecimalFormat("0.00");
        return formate.format(num);
    }

    //Added by scw (bither)
    public static InetAddress parseAddressFromLong(long value) throws UnknownHostException {
        byte[] bytes;
        if (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
            bytes = Ints.toByteArray((int) value);
        } else {
            bytes = Longs.toByteArray(value);
        }
        return InetAddress.getByAddress(bytes);
    }

    public static long currentTimeSeconds() {
        return currentTimeMillis() / 1000;
    }

    public static long getFeeBase() {
        return AbstractApp.bitherjSetting.getTransactionFeeMode().getMinFeeSatoshi();
    }

    public static boolean validPassword(CharSequence password) {
        String pattern = "[0-9a-zA-Z`~!@#$%^&*()_\\-+=|{}':;',\\[\\].\\\\\"<>/?]+";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(password);
        //TODO jjz allow symbols for password
        return m.matches();
    }

    public static boolean validBitcoinPrivateKey(String str) {
        try {
            DumpedPrivateKey dumpedPrivateKey = new DumpedPrivateKey(str);
            dumpedPrivateKey.clearPrivateKey();
            return true;
        } catch (AddressFormatException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean validBicoinAddress(String str) {
        try {

            return (PrimerjSettings.validAddressPrefixPubkey(getAddressHeader(str)) ||
            PrimerjSettings.validAddressPrefixScript(getAddressHeader(str)));

        } catch (final AddressFormatException x) {
            x.printStackTrace();
        }
        return false;
    }

    public static boolean validBicoinGoldAddress(String str) {
        try {
            int addressHeader = getAddressHeader(str);
            return (addressHeader == PrimerjSettings.btgP2shHeader
                    || addressHeader == PrimerjSettings.btgAddressHeader);
        } catch (final AddressFormatException x) {
            x.printStackTrace();
        }
        return false;
    }

    public static boolean validSplitBitCoinAddress(String address,SplitCoin coin) {
        try {
            int addressHeader = getAddressHeader(address);
            return (addressHeader == coin.getAddressHeader() || addressHeader == coin.getP2shHeader());
        }catch (AddressFormatException error) {
            error.printStackTrace();
        }
        return false;
    }

    public static Coin getCoinByAddressHeader(String address) {
        if(address != null && !address.isEmpty()) {
            try {
                int addressHeader = getAddressHeader(address);
                if (addressHeader == SplitCoin.BTG.getP2shHeader() || addressHeader == SplitCoin.BTG.getAddressHeader()) {
                    return Coin.BTG;
                } else if (addressHeader == SplitCoin.BTW.getP2shHeader() || addressHeader == SplitCoin.BTW.getAddressHeader()) {
                    return Coin.BTW;
                } else if (addressHeader == SplitCoin.BTF.getP2shHeader() || addressHeader == SplitCoin.BTF.getAddressHeader()) {
                    return Coin.BTF;
                } else if (addressHeader == SplitCoin.BTP.getP2shHeader() || addressHeader == SplitCoin.BTP.getAddressHeader()) {
                    return Coin.BTP;
                } else {
                    return Coin.BTC;
                }
            } catch (AddressFormatException error) {
                error.printStackTrace();
            }
        }

        return Coin.BTC;
    }

    public static boolean isNubmer(Object obj) {
        try {
            Double.parseDouble(obj.toString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isInteger(Object obj) {
        try {
            Integer.parseInt(obj.toString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isLong(Object obj) {
        try {
            Long.parseLong(obj.toString());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static char[] charsFromBytes(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0;
             i < bytes.length;
             i++) {
            chars[i] = (char) bytes[i];
        }
        return chars;
    }

    public static void wipeBytes(byte[] bytes) {
        if (bytes == null) {
            return;
        }
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0;
        }
        SecureRandom r = new SecureRandom();
        r.nextBytes(bytes);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = 0;
        }
    }

    public static String joinString(String[] strs, String spiltStr) {
        String result = "";
        for (int i = 0; i < strs.length; i++) {
            String str = strs[i];
            if (!Utils.isEmpty(str)) {
                if (i < strs.length - 1) {
                    result = result + str + spiltStr;
                } else {
                    result = result + str;
                }
            }
        }
        return result;
    }

    public static String joinString(List<String> strs, String spiltStr) {
        String result = "";
        for (int i = 0; i < strs.size(); i++) {
            String str = strs.get(i);
            if (!Utils.isEmpty(str)) {
                if (i < strs.size() - 1) {
                    result = result + str + spiltStr;
                } else {
                    result = result + str;
                }
            }
        }
        return result;
    }

    public static byte[] copyOfRange(final byte[] source, final int from,
                                     final int len) {
        final byte[] range = new byte[len];
        System.arraycopy(source, from, range, 0, len);

        return range;
    }

    public static String base64Encode(byte[] bytes) {
        return new String(org.spongycastle.util.encoders.Base64.encode(bytes), Charset.forName("UTF-8"));
    }

    public static List<byte[]> decodeServiceResult(String result) {
        byte[] servicePubs = Base64.decode(result, Base64.DEFAULT);
        int index = 0;
        List<byte[]> pubsList = new ArrayList<byte[]>();
        while (index < servicePubs.length - 1) {
            byte charLen = servicePubs[index];
            index++;
            pubsList.add(Utils.copyOfRange(servicePubs, index, charLen));
            index = index + charLen;
        }
        return pubsList;
    }

    public static String encodeBytesForService(List<byte[]> bytesList) {
        int len = 0;
        for (byte[] bytes : bytesList) {
            len = len + 1 + bytes.length;
        }
        int index = 0;
        byte[] result = new byte[len];
        for (byte[] bytes : bytesList) {
            result[index] = (byte) bytes.length;
            index += 1;
            System.arraycopy(bytes, 0, result, index, bytes.length);
            index += bytes.length;
        }
        return new String(org.spongycastle.util.encoders.Base64.encode(result), Charset.forName("UTF-8"));


    }

    public static boolean isIntersects(Set set1, Set set2) {
        Set result = new HashSet();
        result.addAll(set1);
        result.retainAll(set2);
        return !result.isEmpty();
    }


    // remeber to wipe #address
    public static SecureCharSequence formatHashFromCharSequence(@Nonnull final SecureCharSequence address, final int groupSize, final int lineSize) {
        int length = address.length();
        if (length % groupSize == 0) {
            length = length + length / groupSize - 1;
        } else {
            length = length + length / groupSize;
        }
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            if (i % (groupSize + 1) == groupSize) {
                if ((i + 1) % (lineSize + lineSize / groupSize) == 0) {
                    chars[i] = '\n';
                } else {
                    chars[i] = ' ';
                }
            } else {
                chars[i] = address.charAt(i - i / (groupSize + 1));
            }
        }
        return new SecureCharSequence(chars);
    }


}
