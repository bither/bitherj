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

import com.google.common.base.Preconditions;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.exception.VerificationException;
import net.bither.bitherj.message.BlockMessage;
import net.bither.bitherj.message.Message;
import net.bither.bitherj.utils.UnsafeByteArrayOutputStream;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import static net.bither.bitherj.utils.Utils.doubleDigest;
import static net.bither.bitherj.utils.Utils.doubleDigestTwoBuffers;

public class Block extends Message {
    private static final Logger log = LoggerFactory.getLogger(Block.class);

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

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as official client.

    /**
     * How many bytes are required to represent a block header WITHOUT the trailing 00 length byte.
     */
    public static final int HEADER_SIZE = 80;

    private int blockNo;
    private byte[] blockHash;
    private byte[] blockRoot;
    private long blockVer;
    private long blockBits;
    private long blockNonce;
    private int blockTime;
    private byte[] blockPrev;
    private boolean isMain;

    private List<byte[]> txHashes;
    private List<Tx> transactions;

    public Block() {

    }

    public Block(byte[] blockHash, long version, byte[] prevBlock, byte[] merkleRoot, int timestamp
            , long target, long nonce, int blockNo, boolean isMain) {
        this.blockVer = version;
        this.blockPrev = prevBlock;
        this.blockRoot = merkleRoot;
        this.blockTime = timestamp;
        this.blockBits = target;
        this.blockNonce = nonce;
        this.blockNo = blockNo;
        this.blockHash = blockHash;
        this.isMain = isMain;
    }

    /**
     * Constructs a block object from the Bitcoin wire format.
     */
    public Block(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0, payloadBytes.length);
    }

    /**
     * Contruct a block object from the Bitcoin wire format.
     * //     * @param params NetworkParameters object.
     *
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws net.bither.bitherj.exception.ProtocolException
     */
    public Block(byte[] payloadBytes, int length)
            throws ProtocolException {
        super(payloadBytes, 0, length);
    }

    public Block(long version, String prevBlock, String merkleRoot, int timestamp
            , long target, long nonce, int height) {
        this.blockVer = version;
        this.blockPrev = Utils.reverseBytes(Utils.hexStringToByteArray(prevBlock));
        this.blockRoot = Utils.reverseBytes(Utils.hexStringToByteArray(merkleRoot));
        this.blockTime = timestamp;
        this.blockBits = target;
        this.blockNonce = nonce;
        this.blockNo = height;
        this.blockHash = calculateHash();

    }

    /**
     * Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on
     * the block explorer. If you call this on block 1 in the production chain
     * you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".
     */
    public String getHashAsString() {
        return Utils.hashToString(this.getBlockHash());
    }

    public int getBlockNo() {
        return blockNo;
    }

    public void setBlockNo(int blockNo) {
        this.blockNo = blockNo;
    }

    public byte[] getBlockHash() {
        if (blockHash == null)
            blockHash = calculateHash();
        return blockHash;
    }

    public void setBlockHash(byte[] blockHash) {
        this.blockHash = blockHash;
    }

    public byte[] getBlockRoot() {
        return blockRoot;
    }

    public void setBlockRoot(byte[] blockRoot) {
        this.blockRoot = blockRoot;
    }

    public long getBlockVer() {
        return blockVer;
    }

    public void setBlockVer(long blockVer) {
        this.blockVer = blockVer;
    }

    public long getBlockBits() {
        return blockBits;
    }

    public void setBlockBits(long blockBits) {
        this.blockBits = blockBits;
    }

    public long getBlockNonce() {
        return blockNonce;
    }

    public void setBlockNonce(long blockNonce) {
        this.blockNonce = blockNonce;
    }

    public int getBlockTime() {
        return blockTime;
    }

    public void setBlockTime(int blockTime) {
        this.blockTime = blockTime;
    }

    public byte[] getBlockPrev() {
        return blockPrev;
    }

    public void setBlockPrev(byte[] blockPrev) {
        this.blockPrev = blockPrev;
    }

    public boolean isMain() {
        return isMain;
    }

    public void setMain(boolean isMain) {
        this.isMain = isMain;
    }

    public List<byte[]> getTxHashes() {
        return this.txHashes;
    }

    public void setTxHashes(List<byte[]> txHashes) {
        this.txHashes = txHashes;
    }

    public List<Tx> getTransactions() {
        return this.transactions;
    }

    public void setTransactions(List<Tx> transactions) {
        this.transactions = transactions;
    }

    public byte[] calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(BlockMessage.HEADER_SIZE);
            writeHeader(bos);
            return doubleDigest(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }

    void writeHeader(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(this.blockVer, stream);
        stream.write(this.blockPrev);
        stream.write(this.blockRoot);
        Utils.uint32ToByteStreamLE(this.blockTime, stream);
        Utils.uint32ToByteStreamLE(this.blockBits, stream);
        Utils.uint32ToByteStreamLE(this.blockNonce, stream);
    }

    public void verifyDifficultyFromPreviousBlock(Block prev) {
        // checkState(lock.isHeldByCurrentThread());

        // Is this supposed to be a difficulty transition point?
        if ((prev.getBlockNo() + 1) % BitherjSettings.BLOCK_DIFFICULTY_INTERVAL != 0) {

            // TODO: Refactor this hack after 0.5 is released and we stop supporting deserialization compatibility.
            // This should be a method of the NetworkParameters, which should in turn be using singletons and a subclass
            // for each network type. Then each network can define its own difficulty transition rules.
//            if (Settings.params.getId().equals(NetworkParameters.ID_TESTNET) && nextBlock.getTime().after(testnetDiffDate)) {
//                checkTestnetDifficulty(storedPrev, prev, nextBlock);
//                return;
//            }

            // No ... so check the difficulty didn't actually change.
            if (this.getBlockBits() != prev.getBlockBits())
                throw new VerificationException("Unexpected change in difficulty at height " + prev.getBlockNo() +
                        ": " + Long.toHexString(this.getBlockBits()) + " vs " +
                        Long.toHexString(prev.getBlockBits()));
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
        long now = System.currentTimeMillis();
        Block cursor = get(prev.getBlockHash());
        for (int i = 0; i < BitherjSettings.BLOCK_DIFFICULTY_INTERVAL - 1; i++) {
            if (cursor == null) {
                // This should never happen. If it does, it means we are following an incorrect or busted chain.
                throw new VerificationException(
                        "Difficulty transition point but we did not find a way back to the genesis block.");
            }
            cursor = get(cursor.getBlockPrev());
        }
        long elapsed = System.currentTimeMillis() - now;
        if (elapsed > 50)
            log.info("Difficulty transition traversal took {}msec", elapsed);

        Block blockIntervalAgo = cursor;
        int timespan = (int) (prev.getBlockTime() - blockIntervalAgo.getBlockTime());
        // Limit the adjustment step.
        final int targetTimespan = BitherjSettings.TARGET_TIMESPAN;
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        BigInteger newDifficulty = Utils.decodeCompactBits(prev.getBlockBits());
        newDifficulty = newDifficulty.multiply(BigInteger.valueOf(timespan));
        newDifficulty = newDifficulty.divide(BigInteger.valueOf(targetTimespan));

        if (newDifficulty.compareTo(BitherjSettings.proofOfWorkLimit) > 0) {
            // log.info("Difficulty hit proof of work limit: {}", newDifficulty.toString(16));
            newDifficulty = BitherjSettings.proofOfWorkLimit;
        }

        int accuracyBytes = (int) (this.getBlockBits() >>> 24) - 3;
        BigInteger receivedDifficulty = this.getDifficultyTargetAsInteger();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newDifficulty = newDifficulty.and(mask);

        if (newDifficulty.compareTo(receivedDifficulty) != 0)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    receivedDifficulty.toString(16) + " vs " + newDifficulty.toString(16));
    }

    public void verifyDifficultyFromPreviousBlock(Block prev, int transitionTime) {
        // checkState(lock.isHeldByCurrentThread());

        // Is this supposed to be a difficulty transition point?
        if ((prev.getBlockNo() + 1) % BitherjSettings.BLOCK_DIFFICULTY_INTERVAL != 0) {

            // TODO: Refactor this hack after 0.5 is released and we stop supporting deserialization compatibility.
            // This should be a method of the NetworkParameters, which should in turn be using singletons and a subclass
            // for each network type. Then each network can define its own difficulty transition rules.
//            if (Settings.params.getId().equals(NetworkParameters.ID_TESTNET) && nextBlock.getTime().after(testnetDiffDate)) {
//                checkTestnetDifficulty(storedPrev, prev, nextBlock);
//                return;
//            }

            // No ... so check the difficulty didn't actually change.
            if (this.getBlockBits() != prev.getBlockBits())
                throw new VerificationException("Unexpected change in difficulty at height " + prev.getBlockNo() +
                        ": " + Long.toHexString(this.getBlockBits()) + " vs " +
                        Long.toHexString(prev.getBlockBits()));
            return;
        }

        // We need to find a block far back in the chain. It's OK that this is expensive because it only occurs every
        // two weeks after the initial block chain download.
//        long now = System.currentTimeMillis();
//        Block cursor = get(prev.getBlockHash());
//        for (int i = 0; i < BitherjSettings.BLOCK_DIFFICULTY_INTERVAL - 1; i++) {
//            if (cursor == null) {
//                // This should never happen. If it does, it means we are following an incorrect or busted chain.
//                throw new VerificationException(
//                        "Difficulty transition point but we did not find a way back to the genesis block.");
//            }
//            cursor = get(cursor.getBlockPrev());
//        }
//        long elapsed = System.currentTimeMillis() - now;
//        if (elapsed > 50)
//            log.info("Difficulty transition traversal took {}msec", elapsed);
//
//        Block blockIntervalAgo = cursor;
//        int timespan = (int) (prev.getBlockTime() - blockIntervalAgo.getBlockTime());
        int timespan = (int) (prev.getBlockTime() - transitionTime);
        // Limit the adjustment step.
        final int targetTimespan = BitherjSettings.TARGET_TIMESPAN;
        if (timespan < targetTimespan / 4)
            timespan = targetTimespan / 4;
        if (timespan > targetTimespan * 4)
            timespan = targetTimespan * 4;

        BigInteger newDifficulty = Utils.decodeCompactBits(prev.getBlockBits());
        newDifficulty = newDifficulty.multiply(BigInteger.valueOf(timespan));
        newDifficulty = newDifficulty.divide(BigInteger.valueOf(targetTimespan));

        if (newDifficulty.compareTo(BitherjSettings.proofOfWorkLimit) > 0) {
            // log.info("Difficulty hit proof of work limit: {}", newDifficulty.toString(16));
            newDifficulty = BitherjSettings.proofOfWorkLimit;
        }

        int accuracyBytes = (int) (this.getBlockBits() >>> 24) - 3;
        BigInteger receivedDifficulty = this.getDifficultyTargetAsInteger();

        // The calculated difficulty is to a higher precision than received, so reduce here.
        BigInteger mask = BigInteger.valueOf(0xFFFFFFL).shiftLeft(accuracyBytes * 8);
        newDifficulty = newDifficulty.and(mask);

        if (newDifficulty.compareTo(receivedDifficulty) != 0)
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " +
                    receivedDifficulty.toString(16) + " vs " + newDifficulty.toString(16));
    }

    @Nullable
    public Block get(byte[] hash) {
        return BlockChain.getInstance().getBlock(hash);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof Block) {
            Block block = (Block) o;
            return getBlockNo() == block.getBlockNo() &&
                    Arrays.equals(getBlockHash(), block.getBlockHash()) &&
                    getBlockVer() == block.getBlockVer() &&
                    getBlockBits() == block.getBlockBits() &&
                    getBlockNonce() == block.getBlockNonce() &&
                    getBlockTime() == block.getBlockTime() &&
                    isMain() == block.isMain();

        } else {
            return false;
        }
    }

    /**
     * Checks the block data to ensure it follows the rules laid out in the network parameters. Specifically,
     * throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
     * This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent
     * of the chain and without a transaction index.
     *
     * @throws net.bither.bitherj.exception.VerificationException
     */
    public void verifyHeader() throws VerificationException {
        // Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
        // network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
        //
        // Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
        // enough, it's probably been done by the network.
        checkProofOfWork(true);
        checkTimestamp();
    }

    /**
     * Checks the block contents
     *
     * @throws net.bither.bitherj.exception.VerificationException
     */
    public void verifyTransactions() throws VerificationException {
        // Now we need to check that the body of the block actually matches the headers. The network won't generate
        // an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
        // valid block from the network and simply replace the transactions in it with their own fictional
        // transactions that reference spent or non-existant inputs.
        if (transactions.isEmpty())
            throw new VerificationException("Block had no transactions");
        if (this.getOptimalEncodingMessageSize() > MAX_BLOCK_SIZE)
            throw new VerificationException("Block larger than MAX_BLOCK_SIZE");
        checkTransactions();
        checkMerkleRoot();
        checkSigOps();
        for (Tx transaction : transactions)
            transaction.verify();
    }

    /**
     * Verifies both the header and that the transactions hash to the merkle root.
     */
    public void verify() throws VerificationException {
        verifyHeader();
        verifyTransactions();
    }

    /**
     * Returns true if the hash of the block is OK (lower than difficulty target).
     */
    private boolean checkProofOfWork(boolean throwException) throws VerificationException {
        // This part is key - it is what proves the block was as difficult to make as it claims
        // to be. Note however that in the context of this function, the block can claim to be
        // as difficult as it wants to be .... if somebody was able to take control of our network
        // connection and fork us onto a different chain, they could send us valid blocks with
        // ridiculously easy difficulty and this function would accept them.
        //
        // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
        // field is of the right value. This requires us to have the preceeding blocks.
        BigInteger target = getDifficultyTargetAsInteger();

        BigInteger h = new BigInteger(1, Utils.reverseBytes(getBlockHash()));
        if (h.compareTo(target) > 0) {
            // Proof of work check failed!
            if (throwException)
                throw new VerificationException("Hash is higher than target: " + getHashAsString() + " vs "
                        + target.toString(16));
            else
                return false;
        }
        return true;
    }

    private void checkTimestamp() throws VerificationException {
        // Allow injection of a fake clock to allow unit testing.
        long currentTime = Utils.currentTimeMillis() / 1000;
        if (blockTime > currentTime + ALLOWED_TIME_DRIFT)
            throw new VerificationException("Block too far in future");
    }

    private void checkSigOps() throws VerificationException {
        // Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the
        // comments for MAX_BLOCK_SIGOPS.
        int sigOps = 0;
        for (Tx tx : transactions) {
            sigOps += tx.getSigOpCount();
        }
        if (sigOps > MAX_BLOCK_SIGOPS)
            throw new VerificationException("Block had too many Signature Operations");
    }

    private void checkMerkleRoot() throws VerificationException {
        byte[] calculatedRoot = calculateMerkleRoot();
        if (!Arrays.equals(calculatedRoot, blockRoot)) {
            log.error("Merkle tree did not verify");
            throw new VerificationException("Merkle hashes do not match: "
                    + Utils.bytesToHexString(calculatedRoot) + " vs "
                    + Utils.bytesToHexString(blockRoot));
        }
    }

    private byte[] calculateMerkleRoot() {
        List<byte[]> tree = buildMerkleTree();
        return tree.get(tree.size() - 1);
    }

    private List<byte[]> buildMerkleTree() {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        ArrayList<byte[]> tree = new ArrayList<byte[]>();
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Tx t : transactions) {
            tree.add(t.getTxHash());
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                byte[] leftBytes = tree.get(levelOffset + left);
                byte[] rightBytes = tree.get(levelOffset + right);
                tree.add(doubleDigestTwoBuffers(leftBytes, 0, 32, rightBytes, 0, 32));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }

    private void checkTransactions() throws VerificationException {
        // The first transaction in a block must always be a coinbase transaction.
        if (!transactions.get(0).isCoinBase())
            throw new VerificationException("First tx is not coinbase");
        // The rest must not be.
        for (int i = 1; i < transactions.size(); i++) {
            if (transactions.get(i).isCoinBase())
                throw new VerificationException("TX " + i + " is coinbase when it should not be.");
        }
    }

    /**
     * Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the
     * target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception
     * is thrown.
     */
    public BigInteger getDifficultyTargetAsInteger() throws VerificationException {
        BigInteger target = Utils.decodeCompactBits(blockBits);
        if (target.compareTo(BigInteger.ZERO) <= 0 || target.compareTo(BitherjSettings.proofOfWorkLimit) > 0)
            throw new VerificationException("Difficulty target is bad: " + target.toString());
        return target;
    }


    private transient boolean headerParsed;
    private transient boolean transactionsParsed;

    private transient boolean headerBytesValid;
    private transient boolean transactionBytesValid;


    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    private transient int optimalEncodingMessageSize;

    private void parseHeader() throws ProtocolException {
        if (headerParsed)
            return;

        cursor = offset;
        blockVer = readUint32();
        blockPrev = readHash();
        blockRoot = readHash();
        blockTime = (int) readUint32();
        blockBits = readUint32();
        blockNonce = readUint32();

        blockHash = Utils.doubleDigest(bytes, offset, cursor);

        headerParsed = true;
        headerBytesValid = false;
    }

    private void parseTransactions() throws ProtocolException {
        if (transactionsParsed)
            return;

        cursor = offset + HEADER_SIZE;
        optimalEncodingMessageSize = HEADER_SIZE;
        if (bytes.length == cursor) {
            // This message is just a header, it has no transactions.
            transactionsParsed = true;
            transactionBytesValid = false;
            return;
        }

        int numTransactions = (int) readVarInt();
        optimalEncodingMessageSize += VarInt.sizeOf(numTransactions);
        transactions = new ArrayList<Tx>(numTransactions);
        for (int i = 0; i < numTransactions; i++) {
            Tx tx = new Tx(bytes, cursor, UNKNOWN_LENGTH);
            // Label the transaction as coming from the P2P network, so code that cares where we first saw it knows.
            tx.setSource(Tx.SourceType.network.getValue());
            transactions.add(tx);
            cursor += tx.getMessageSize();
            optimalEncodingMessageSize += tx.getOptimalEncodingMessageSize();
        }
        // No need to set length here. If length was not provided then it should be set at the end of parseLight().
        // If this is a genuine lazy parse then length must have been provided to the constructor.
        transactionsParsed = true;
        transactionBytesValid = false;
    }

    protected void parse() throws ProtocolException {
        if (length == UNKNOWN_LENGTH) {
            Preconditions.checkState(false,
                    "Performing lite parse of block transaction as block was initialised from byte array " +
                            "without providing length.  This should never need to happen."
            );
            parseTransactions();
            length = cursor - offset;
        } else {
            transactionBytesValid = !transactionsParsed || false && length > HEADER_SIZE;
        }
        headerBytesValid = !headerParsed || false && length >= HEADER_SIZE;

        parseHeader();
        parseTransactions();
        length = cursor - offset;
    }

    public int getOptimalEncodingMessageSize() {
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        if (optimalEncodingMessageSize != 0)
            return optimalEncodingMessageSize;
        optimalEncodingMessageSize = getMessageSize();
        return optimalEncodingMessageSize;
    }

    private void writeTransactions(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null && transactionsParsed) {
            return;
        }

        // confirmed we must have transactions either cached or as objects.
        if (transactionBytesValid && bytes != null && bytes.length >= offset + length) {
            stream.write(bytes, offset + HEADER_SIZE, length - HEADER_SIZE);
            return;
        }
        if (transactions != null) {
            stream.write(new VarInt(transactions.size()).encode());
            for (Tx tx : transactions) {
                tx.bitcoinSerialize(stream);
            }
        }
    }

    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     * @throws java.io.IOException
     */
    public byte[] bitcoinSerialize() {
        // we have completely cached byte array.
        if (headerBytesValid && transactionBytesValid) {
            Preconditions.checkNotNull(bytes, "Bytes should never be null if headerBytesValid && transactionBytesValid");
            if (length == bytes.length) {
                return bytes;
            } else {
                // byte array is offset so copy out the correct range.
                byte[] buf = new byte[length];
                System.arraycopy(bytes, offset, buf, 0, length);
                return buf;
            }
        }

        // At least one of the two cacheable components is invalid
        // so fall back to stream write since we can't be sure of the length.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? HEADER_SIZE + guessTransactionsLength() : length);
        try {
            writeHeader(stream);
            writeTransactions(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        // We may only have enough data to write the header.
        writeTransactions(stream);
    }

    /**
     * Provides a reasonable guess at the byte length of the transactions part of the block.
     * The returned value will be accurate in 99% of cases and in those cases where not will probably slightly
     * oversize.
     * <p/>
     * This is used to preallocate the underlying byte array for a ByteArrayOutputStream.  If the size is under the
     * real value the only penalty is resizing of the underlying byte array.
     */
    private int guessTransactionsLength() {
        if (transactionBytesValid)
            return bytes.length - HEADER_SIZE;
        if (transactions == null)
            return 0;
        int len = VarInt.sizeOf(transactions.size());
        for (Tx tx : transactions) {
            // 255 is just a guess at an average tx length
            len += tx.length == UNKNOWN_LENGTH ? 255 : tx.length;
        }
        return len;
    }

    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        headerBytesValid = false;
        if (!transactionBytesValid)
            bytes = null;
        blockHash = null;
        checksum = null;
    }

    private void unCacheTransactions() {
        transactionBytesValid = false;
        if (!headerBytesValid)
            bytes = null;
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        blockRoot = null;
    }

    public Block cloneAsHeader() {
        Block block = new Block();
        block.setBlockNo(this.getBlockNo());
        block.setBlockNonce(this.getBlockNonce());
        block.setBlockPrev(this.getBlockPrev().clone());
        block.setBlockRoot(this.getBlockRoot().clone());
        block.setBlockVer(this.getBlockVer());
        block.setBlockTime(this.getBlockTime());
        block.setBlockBits(this.getBlockBits());
        block.setTransactions(null);
        block.setBlockHash(this.getBlockHash().clone());
        return block;
    }

}

























