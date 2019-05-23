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

package net.bither.bitherj.message;

import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.utils.Utils;

import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static com.google.common.base.Preconditions.checkNotNull;
import static net.bither.bitherj.utils.Utils.uint32ToByteStreamLE;
import static net.bither.bitherj.utils.Utils.uint64ToByteStreamLE;

/**
 * A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin P2P network. It exists primarily for serialization purposes.
 */
public class PeerAddress extends ChildMessage {
    private static final long serialVersionUID = 7501293709324197411L;
    public static final int MESSAGE_SIZE = 30;

    private InetAddress addr;
    private int port;
    private BigInteger services;
    private long time;

    /**
     * Construct a peer address from a serialized payload.
     */
    public PeerAddress(byte[] payload, int offset, int protocolVersion, int length) throws ProtocolException {
        super(payload, offset, protocolVersion, length);
    }

    /**
     * Construct a peer address from a serialized payload.
     * //     * @param params NetworkParameters object.
     *
     * @param msg             Bitcoin protocol formatted byte array containing message content.
     * @param offset          The location of the first msg byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @throws ProtocolException
     */
    public PeerAddress(byte[] msg, int offset, int protocolVersion, Message parent, int length) throws ProtocolException {
        super(msg, offset, protocolVersion, parent, length);
        // Message length is calculated in parseLite which is guaranteed to be called before it is ever read.
        // Even though message length is static for a PeerAddress it is safer to leave it there 
        // as it will be set regardless of which constructor was used.
    }


    /**
     * Construct a peer address from a memorized or hardcoded address.
     */
    public PeerAddress(InetAddress addr, int port, int protocolVersion) {
        this.addr = checkNotNull(addr);
        this.port = port;
        this.protocolVersion = protocolVersion;
        this.services = BigInteger.ZERO;
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
    }

    /**
     * Constructs a peer address from the given IP address and port. Protocol version is the default.
     */
    public PeerAddress(InetAddress addr, int port) {
        this(addr, port, PrimerjSettings.PROTOCOL_VERSION);
    }

    /**
     * Constructs a peer address from the given IP address. Port and protocol version are default for the prodnet.
     */
    public PeerAddress(InetAddress addr) {
        this(addr, PrimerjSettings.port);
    }

    public PeerAddress(InetSocketAddress addr) {
        this(addr.getAddress(), addr.getPort());
    }

    public static PeerAddress localhost() {
        try {
            return new PeerAddress(InetAddress.getLocalHost(), PrimerjSettings.port);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Broken system.
        }
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (protocolVersion >= 31402) {
            //TODO this appears to be dynamic because the client only ever sends out it's own address
            //so assumes itself to be up.  For a fuller implementation this needs to be dynamic only if
            //the address refers to this client.
            int secs = (int) (Utils.currentTimeMillis() / 1000);
            Utils.uint32ToByteStreamLE(secs, stream);
        }
        Utils.uint64ToByteStreamLE(services, stream);  // nServices.
        // Java does not provide any utility to map an IPv4 address into IPv6 space, so we have to do it by hand.
        byte[] ipBytes = addr.getAddress();
        if (ipBytes.length == 4) {
            byte[] v6addr = new byte[16];
            System.arraycopy(ipBytes, 0, v6addr, 12, 4);
            v6addr[10] = (byte) 0xFF;
            v6addr[11] = (byte) 0xFF;
            ipBytes = v6addr;
        }
        stream.write(ipBytes);
        // And write out the port. Unlike the rest of the protocol, address and port is in big endian byte order.
        stream.write((byte) (0xFF & port >> 8));
        stream.write((byte) (0xFF & port));
    }

    protected void parseLite() {
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
    }

    @Override
    protected void parse() throws ProtocolException {
        // Format of a serialized address:
        //   uint32 timestamp
        //   uint64 services   (flags determining what the node can do)
        //   16 bytes ip address
        //   2 bytes port num
        if (protocolVersion > 31402)
            time = readUint32();
        else
            time = -1;
        services = readUint64();
        byte[] addrBytes = readBytes(16);
        try {
            addr = InetAddress.getByAddress(addrBytes);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
        port = ((0xFF & bytes[cursor++]) << 8) | (0xFF & bytes[cursor++]);
    }

    /* (non-Javadoc)
      * @see Message#getMessageSize()
      */
    @Override
    public int getMessageSize() {
        // The 4 byte difference is the uint32 timestamp that was introduced in version 31402 
        length = protocolVersion > 31402 ? MESSAGE_SIZE : MESSAGE_SIZE - 4;
        return length;
    }

    /**
     * @return the addr
     */
    public InetAddress getAddr() {
        return addr;
    }


    /**
     * @param addr the addr to set
     */
    public void setAddr(InetAddress addr) {
        this.addr = addr;
    }


    /**
     * @return the port
     */
    public int getPort() {
        return port;
    }


    /**
     * @param port the port to set
     */
    public void setPort(int port) {
        this.port = port;
    }


    /**
     * @return the services
     */
    public BigInteger getServices() {
        return services;
    }


    /**
     * @param services the services to set
     */
    public void setServices(BigInteger services) {
        this.services = services;
    }


    /**
     * @return the time
     */
    public long getTime() {
        return time;
    }


    /**
     * @param time the time to set
     */
    public void setTime(long time) {
        this.time = time;
    }


    @Override
    public String toString() {
        return "[" + addr.getHostAddress() + "]:" + port;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PeerAddress)) return false;
        PeerAddress other = (PeerAddress) o;
        return other.addr.equals(addr) &&
                other.port == port &&
                other.services.equals(services) &&
                other.time == time;
        //FIXME including services and time could cause same peer to be added multiple times in collections
    }

    @Override
    public int hashCode() {
        return addr.hashCode() ^ port ^ (int) time ^ services.hashCode();
    }

    public InetSocketAddress toSocketAddress() {
        return new InetSocketAddress(addr, port);
    }
}
