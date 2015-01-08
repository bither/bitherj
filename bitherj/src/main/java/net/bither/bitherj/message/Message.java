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

package net.bither.bitherj.message;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.UnsafeByteArrayOutputStream;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkState;

public abstract class Message {
    private static final Logger log = LoggerFactory.getLogger(Message.class);

    public static final int MAX_SIZE = 0x02000000;

    public static final int UNKNOWN_LENGTH = Integer.MIN_VALUE;

    // The offset is how many bytes into the provided byte array this message starts at.
    protected transient int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message.
    protected transient int cursor;

    public transient int length = UNKNOWN_LENGTH;

    // The raw message bytes themselves.
    protected transient byte[] bytes;

    protected transient int protocolVersion;

    protected transient byte[] checksum;

    // This will be saved by subclasses that implement Serializable.
//    public NetworkParameters params;

    /**
     * This exists for the Java serialization framework to use only.
     */
    protected Message() {

    }

//    protected Message() {
////        this.params = params;
//        parsed = true;
//        parseLazy = false;
//        parseRetain = false;
//    }

//    protected Message2(byte[] msg, int offset, int protocolVersion) throws ProtocolException {
//        this(msg, offset, protocolVersion, UNKNOWN_LENGTH);
//    }

    /**
     * //     * @param params NetworkParameters object.
     *
     * @param msg             Bitcoin protocol formatted byte array containing message content.
     * @param offset          The location of the first msg byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     *                        If true and the backing byte array is invalidated due to modification of a field then
     *                        the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length          The length of message if known.  Usually this is provided when deserializing of the wire
     *                        as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    protected Message(byte[] msg, int offset, int protocolVersion, int length) throws ProtocolException {
        this.protocolVersion = protocolVersion;
        this.bytes = msg;
        this.cursor = this.offset = offset;
        this.length = length;
        parse();

        if (this.length == UNKNOWN_LENGTH) {
            this.protocolVersion = protocolVersion;
            this.bytes = msg;
            this.cursor = this.offset = offset;
            this.length = length;
            parse();
            checkState(false, "Length field has not been set in constructor for %s after %s parse. " +
                            "Refer to Message.parseLite() for detail of required Length field contract.",
                    getClass().getSimpleName(), "full");
        }


        this.bytes = null;
    }

    protected Message(byte[] msg, int offset) throws ProtocolException {
        this(msg, offset, BitherjSettings.PROTOCOL_VERSION, UNKNOWN_LENGTH);
    }

    protected Message(byte[] msg, int offset, int length) throws ProtocolException {
        this(msg, offset, BitherjSettings.PROTOCOL_VERSION, length);
    }

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.
    // It's somewhat painful to work with in Java, so some of these objects support a second
    // serialization mechanism - the standard Java serialization system. This is used when things
    // are serialized to the wallet.
    protected abstract void parse() throws ProtocolException;

    protected void adjustLength(int newArraySize, int adjustment) {
        if (length == UNKNOWN_LENGTH)
            return;
        // Our own length is now unknown if we have an unknown length adjustment.
        if (adjustment == UNKNOWN_LENGTH) {
            length = UNKNOWN_LENGTH;
            return;
        }
        length += adjustment;
        // Check if we will need more bytes to encode the length prefix.
        if (newArraySize == 1)
            length++;  // The assumption here is we never call adjustLength with the same arraySize as before.
        else if (newArraySize != 0)
            length += VarInt.sizeOf(newArraySize) - VarInt.sizeOf(newArraySize - 1);
    }

    /**
     * Should only used by BitcoinSerializer for cached checksum
     *
     * @return the checksum
     */
    protected byte[] getChecksum() {
        return checksum;
    }

    /**
     * Should only used by BitcoinSerializer for caching checksum
     *
     * @param checksum the checksum to set
     */
    public void setChecksum(byte[] checksum) {
        if (checksum.length != 4)
            throw new IllegalArgumentException("Checksum length must be 4 bytes, actual length: " + checksum.length);
        this.checksum = checksum;
    }

    /**
     * Returns a copy of the array returned by {@link Message#unsafeBitcoinSerialize()}, which is safe to mutate.
     * If you need extra performance and can guarantee you won't write to the array, you can use the unsafe version.
     *
     * @return a freshly allocated serialized byte array
     */
    public byte[] bitcoinSerialize() {
        byte[] bytes = unsafeBitcoinSerialize();
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }

    /**
     * Serialize this message to a byte array that conforms to the bitcoin wire protocol.
     * <br/>
     * This method may return the original byte array used to construct this message if the
     * following conditions are met:
     * <ol>
     * <li>1) The message was parsed from a byte array with parseRetain = true</li>
     * <li>2) The message has not been modified</li>
     * <li>3) The array had an offset of 0 and no surplus bytes</li>
     * </ol>
     * <p/>
     * If condition 3 is not met then an copy of the relevant portion of the array will be returned.
     * Otherwise a full serialize will occur. For this reason you should only use this API if you can guarantee you
     * will treat the resulting array as read only.
     *
     * @return a byte array owned by this object, do NOT mutate it.
     */
    public byte[] unsafeBitcoinSerialize() {
        // 1st attempt to use a cached array.
        if (bytes != null) {
            if (offset == 0 && length == bytes.length) {
                // Cached byte array is the entire message with no extras so we can return as is and avoid an array
                // copy.
                return bytes;
            }

            byte[] buf = new byte[length];
            System.arraycopy(bytes, offset, buf, 0, length);
            return buf;
        }

        // No cached array available so serialize parts by stream.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length < 32 ? 32 : length + 32);
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        // Record length. If this Message wasn't parsed from a byte stream it won't have length field
        // set (except for static length message types).  Setting it makes future streaming more efficient
        // because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
        byte[] buf = stream.toByteArray();
        length = buf.length;
        return buf;
    }

    /**
     * Serialize this message to the provided OutputStream using the bitcoin wire format.
     *
     * @param stream
     * @throws java.io.IOException
     */
    final public void bitcoinSerialize(OutputStream stream) throws IOException {
        // 1st check for cached bytes.
        if (bytes != null && length != UNKNOWN_LENGTH) {
            stream.write(bytes, offset, length);
            return;
        }

        bitcoinSerializeToStream(stream);
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        log.error("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", getClass());
    }

    /**
     * This should be overridden to extract correct message size in the case of lazy parsing.  Until this method is
     * implemented in a subclass of ChildMessage lazy parsing may have no effect.
     * <p/>
     * This default implementation is a safe fall back that will ensure it returns a correct value by parsing the message.
     */
    public int getMessageSize() {
        if (length != UNKNOWN_LENGTH)
            return length;
        if (length == UNKNOWN_LENGTH)
            checkState(false, "Length field has not been set in %s after full parse.", getClass().getSimpleName());
        return length;
    }

    protected long readUint32() throws ProtocolException {
        try {
            long u = Utils.readUint32(bytes, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte[] readHash() throws ProtocolException {
        try {
            byte[] hash = new byte[32];
            System.arraycopy(bytes, cursor, hash, 0, 32);
            // We have to flip it around, as it's been read off the wire in little endian.
            // Not the most efficient way to do this but the clearest.
//            hash = Utils.reverseBytes(hash);
            cursor += 32;
            return hash;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readInt64() throws ProtocolException {
        try {
            long u = Utils.readInt64(bytes, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected BigInteger readUint64() throws ProtocolException {
        try {
            // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
            byte[] valbytes = new byte[8];
            System.arraycopy(bytes, cursor, valbytes, 0, 8);
            valbytes = Utils.reverseBytes(valbytes);
            cursor += valbytes.length;
            return new BigInteger(valbytes);
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readVarInt() throws ProtocolException {
        return readVarInt(0);
    }

    protected long readVarInt(int offset) throws ProtocolException {
        try {
            VarInt varint = new VarInt(bytes, cursor + offset);
            cursor += offset + varint.getOriginalSizeInBytes();
            return varint.value;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }


    protected byte[] readBytes(int length) throws ProtocolException {
        try {
            byte[] b = new byte[length];
            System.arraycopy(bytes, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte[] readByteArray() throws ProtocolException {
        long len = readVarInt();
        return readBytes((int) len);
    }

    protected String readStr() throws ProtocolException {
        try {
            VarInt varInt = new VarInt(bytes, cursor);
            if (varInt.value == 0) {
                cursor += 1;
                return "";
            }
            cursor += varInt.getOriginalSizeInBytes();
            byte[] characters = new byte[(int) varInt.value];
            System.arraycopy(bytes, cursor, characters, 0, characters.length);
            cursor += characters.length;
            try {
                return new String(characters, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);  // Cannot happen, UTF-8 is always supported.
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected boolean hasMoreBytes() {
        return cursor < bytes.length;
    }

}
