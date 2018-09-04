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

import net.bither.bitherj.core.Block;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.exception.ProtocolException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.List;

/**
 * <p>A block is a group of transactions, and is one of the fundamental data structures of the Bitcoin system.
 * It records a set of {@link}s together with some data that links it into a place in the global block
 * chain, and proves that a difficult calculation was done over its contents. See
 * <a href="http://www.bitcoin.org/bitcoin.pdf">the Bitcoin technical paper</a> for
 * more detail on blocks. <p/>
 * <p/>
 * To get a block, you can either build one from the raw bytes you can get from another implementation, or request one
 * specifically using {@link net.bither.bitherj.core.Peer#(net.bither.bitherj.utils.Sha256Hash)}, or grab one from a downloaded {@link net.bither.bitherj.core.BlockChain}.
 */
public class BlockMessage extends Message {
    private static final Logger log = LoggerFactory.getLogger(BlockMessage.class);
    private static final long serialVersionUID = 2738848929966035281L;

    /**
     * How many bytes are required to represent a block header WITHOUT the trailing 00 length byte.
     */
    public static final int HEADER_SIZE = 80;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as official client.

    /**
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
     */
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
    /**
     * A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on
     * the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very
     * expensive/slow to verify.
     */
    public static final int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

    /**
     * A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing.
     */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    protected Block block;

    public void setBlock(Block block) {
        this.block = block;
    }

    public Block getBlock() {
        return this.block;
    }

    // Fields defined as part of the protocol format.
//    private long version;
//    private byte[] prevBlockHash;
//    private byte[] merkleRoot;
//    private long time;
//    private long difficultyTarget; // "nBits"
//    private long nonce;

    /**
     * If null, it means this object holds only the headers.
     */
//    public List<Tx> transactions;

    /**
     * Stores the hash of the block. If null, getHash() will recalculate it.
     */
//    private transient byte[] hash;
//
//    private transient boolean headerParsed;
//    private transient boolean transactionsParsed;
//
//    private transient boolean headerBytesValid;
//    private transient boolean transactionBytesValid;

    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
//    private transient int optimalEncodingMessageSize;

    /**
     * Special case constructor, used for the genesis node, cloneAsHeader and unit tests.
     */
    public BlockMessage() {
        super();
        // Set up a few basic things. We are not complete after this though.
//        version = 1;
//        difficultyTarget = 0x1d07fff8L;
//        time = System.currentTimeMillis() / 1000;
//        prevBlockHash = new byte[32];
//
//        length = 80;
        block = new Block();
        block.setBlockVer(1);
        block.setBlockBits(0x1d07fff8L);
        block.setBlockTime((int) (System.currentTimeMillis() / 1000));
        block.setBlockPrev(new byte[32]);
        length = 80;
    }

    /**
     * Constructs a block object from the Bitcoin wire format.
     */
    public BlockMessage(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0, payloadBytes.length);
        block = new Block(payloadBytes);
    }

    /**
     * Contruct a block object from the Bitcoin wire format.
     * //     * @param params NetworkParameters object.
     *
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws net.bither.bitherj.exception.ProtocolException
     */
    public BlockMessage(byte[] payloadBytes, int length)
            throws ProtocolException {
        super(payloadBytes, 0, length);
        block = new Block(payloadBytes, length);
    }

    /**
     * Construct a block initialized with all the given fields.
     * //     * @param params Which network the block is for.
     *
     * @param version          This should usually be set to 1 or 2, depending on if the height is in the coinbase input.
     * @param prevBlockHash    Reference to previous block in the chain or {@link net.bither.bitherj.utils.Sha256Hash#ZERO_HASH} if genesis.
     * @param merkleRoot       The root of the merkle tree formed by the transactions.
     * @param time             UNIX time when the block was mined.
     * @param difficultyTarget Number which this block hashes lower than.
     * @param nonce            Arbitrary number to make the block hash lower than the target.
     * @param transactions     List of transactions including the coinbase.
     */
    public BlockMessage(long version, byte[] prevBlockHash, byte[] merkleRoot, long time,
                        long difficultyTarget, long nonce, List<Tx> transactions) {
        super();
        block = new Block();
        block.setBlockVer(version);
        block.setBlockBits(difficultyTarget);
        block.setBlockTime((int) time);
        block.setBlockPrev(prevBlockHash);
        block.setBlockRoot(merkleRoot);
        block.setBlockNonce(nonce);
        block.setTransactions(transactions);
    }

    protected void parse() throws ProtocolException {

    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws java.io.IOException
     */
    public byte[] bitcoinSerialize() {
        return block.bitcoinSerialize();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        block.bitcoinSerializeToStream(stream);
    }

    /**
     * The number that is one greater than the largest representable SHA-256
     * hash.
     */
    static private BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /**
     * Returns a copy of the block, but without any transactions.
     */
    public BlockMessage cloneAsHeader() {
        BlockMessage blockMessage = new BlockMessage();
        Block block = new Block();
        block.setBlockNo(this.block.getBlockNo());
        block.setBlockNonce(this.block.getBlockNonce());
        block.setBlockPrev(this.block.getBlockPrev().clone());
        block.setBlockRoot(this.block.getBlockRoot().clone());
        block.setBlockVer(this.block.getBlockVer());
        block.setBlockTime(this.block.getBlockTime());
        block.setBlockBits(this.block.getBlockBits());
        block.setTransactions(null);
        block.setBlockHash(this.block.getBlockHash().clone());
        blockMessage.setBlock(block);
        return blockMessage;
    }

    /**
     * Returns a multi-line string containing a description of the contents of
     * the block. Use for debugging purposes only.
     */
    @Override
    public String toString() {
        return block.toString();
    }
}
