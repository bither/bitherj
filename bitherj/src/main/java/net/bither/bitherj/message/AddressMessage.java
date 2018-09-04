package net.bither.bitherj.message;

import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.VarInt;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents an "addr" message on the P2P network, which contains broadcast IP addresses of other peers. This is
 * one of the ways peers can find each other without using the DNS or IRC discovery mechansisms. However storing and
 * using addr messages is not presently implemented.
 */
public class AddressMessage extends Message {
    private static final long serialVersionUID = 8058283864924679460L;
    private static final long MAX_ADDRESSES = 1024;
    private List<PeerAddress> addresses;
    private transient long numAddresses = -1;

    /**
     * Contruct a new 'addr' message.
     * //     * @param params NetworkParameters object.
     *
     * @param offset The location of the first msg byte within the array.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws net.bither.bitherj.exception.ProtocolException
     */
    AddressMessage(byte[] payload, int offset, int length) throws ProtocolException {
        super(payload, offset, length);
    }

    /**
     * Contruct a new 'addr' message.
     * //     * @param params NetworkParameters object.
     *
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public AddressMessage(byte[] payload, int length) throws ProtocolException {
        super(payload, 0, length);
    }

//    AddressMessage(byte[] payload, int offset) throws ProtocolException {
//        super(payload, offset, UNKNOWN_LENGTH);
//    }

    AddressMessage(byte[] payload) throws ProtocolException {
        super(payload, 0, UNKNOWN_LENGTH);
    }

//    @Override
//    protected void parseLite() throws ProtocolException {
//    }

    @Override
    protected void parse() throws ProtocolException {
        numAddresses = readVarInt();
        // Guard against ultra large messages that will crash us.
        if (numAddresses > MAX_ADDRESSES)
            throw new ProtocolException("Address message too large.");
        addresses = new ArrayList<PeerAddress>((int) numAddresses);
        for (int i = 0; i < numAddresses; i++) {
            PeerAddress addr = new PeerAddress(bytes, cursor, protocolVersion, this, 30);
            addresses.add(addr);
            cursor += addr.getMessageSize();
        }
        length = cursor - offset;
    }

    /* (non-Javadoc)
      * @see Message#bitcoinSerializeToStream(java.io.OutputStream)
      */
    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (addresses == null)
            return;
        stream.write(new VarInt(addresses.size()).encode());
        for (PeerAddress addr : addresses) {
            addr.bitcoinSerialize(stream);
        }
    }

    public int getMessageSize() {
        if (length != UNKNOWN_LENGTH)
            return length;
        if (addresses != null) {
            length = new VarInt(addresses.size()).getSizeInBytes();
            // The 4 byte difference is the uint32 timestamp that was introduced in version 31402
            length += addresses.size() * (protocolVersion > 31402 ? PeerAddress.MESSAGE_SIZE : PeerAddress.MESSAGE_SIZE - 4);
        }
        return length;
    }

    /**
     * AddressMessage cannot cache checksum in non-retain mode due to dynamic time being used.
     */
    @Override
    public void setChecksum(byte[] checksum) {
//        if (parseRetain)
        super.setChecksum(checksum);
//        else
//            this.checksum = null;
    }

    /**
     * @return An unmodifiableList view of the backing List of addresses.  Addresses contained within the list may be safely modified.
     */
    public List<PeerAddress> getAddresses() {
        return Collections.unmodifiableList(addresses);
    }

    public void addAddress(PeerAddress address) {
        address.setParent(this);
        addresses.add(address);
        if (length == UNKNOWN_LENGTH)
            getMessageSize();
        else
            length += address.getMessageSize();
    }

    public void removeAddress(int index) {
        PeerAddress address = addresses.remove(index);
        address.setParent(null);
        if (length == UNKNOWN_LENGTH)
            getMessageSize();
        else
            length -= address.getMessageSize();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("addr: ");
        for (PeerAddress a : addresses) {
            builder.append(a.toString());
            builder.append(" ");
        }
        return builder.toString();
    }

}
