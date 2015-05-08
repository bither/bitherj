/**
 * Copyright 2012 Matt Corallo
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
import net.bither.bitherj.exception.VerificationException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * <p>A FilteredBlock is used to relay a block with its transactions filtered using a {@link }. It consists
 * of the block header and a {@link } which contains the transactions which matched the filter.</p>
 */
public class FilteredBlockMessage extends Message {
    /**
     * The protocol version at which Bloom filtering started to be supported.
     */
    public static final int MIN_PROTOCOL_VERSION = 70000;
    //    private BlockMessage header;
    private Block block;

    // The PartialMerkleTree of transactions
    private PartialMerkleTree merkleTree;
    private List<byte[]> cachedTransactionHashes = null;

    // A set of transactions whose hashes are a subset of getTransactionHashes()
    // These were relayed as a part of the filteredblock getdata, ie likely weren't previously received as loose transactions
    private Map<byte[], Tx> associatedTransactions = new HashMap<byte[], Tx>();

    public FilteredBlockMessage(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0);
    }

    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (block.getTransactions() == null)
            block.bitcoinSerializeToStream(stream);
        else {
            Block emptyBlock = new Block(block.bitcoinSerialize());
            emptyBlock.setTransactions(null);
            emptyBlock.bitcoinSerializeToStream(stream);
        }
        merkleTree.bitcoinSerializeToStream(stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        byte[] headerBytes = new byte[BlockMessage.HEADER_SIZE];
        System.arraycopy(bytes, 0, headerBytes, 0, BlockMessage.HEADER_SIZE);
        block = new Block(headerBytes);
        merkleTree = new PartialMerkleTree(bytes, BlockMessage.HEADER_SIZE);
        length = BlockMessage.HEADER_SIZE + merkleTree.getMessageSize();
        block.setTxHashes(this.getTransactionHashes());
    }

    /**
     * Gets a list of leaf hashes which are contained in the partial merkle tree in this filtered block
     *
     * @throws ProtocolException If the partial merkle block is invalid or the merkle root of the partial merkle block doesnt match the block header
     */
    public List<byte[]> getTransactionHashes() throws VerificationException {
        if (cachedTransactionHashes != null)
            return Collections.unmodifiableList(cachedTransactionHashes);
        List<byte[]> hashesMatched = new LinkedList<byte[]>();
        byte[] by = merkleTree.getTxnHashAndMerkleRoot(hashesMatched);
        if (Arrays.equals(block.getBlockRoot(), by)) {
            cachedTransactionHashes = hashesMatched;
            return Collections.unmodifiableList(cachedTransactionHashes);
        } else
            throw new VerificationException("Merkle root of block header does not match merkle root of partial merkle tree.");
    }

    /**
     * Gets a copy of the block header
     */
    public Block getBlock() {
        return block;
    }

    /**
     * Provide this FilteredBlock with a transaction which is in its merkle tree
     *
     * @returns false if the tx is not relevant to this FilteredBlock
     */
    public boolean provideTransaction(Tx tx) throws VerificationException {
        byte[] hash = tx.getTxHash();
        if (getTransactionHashes().contains(hash)) {
            associatedTransactions.put(hash, tx);
            return true;
        } else
            return false;
    }

    /**
     * Gets the set of transactions which were provided using provideTransaction() which match in getTransactionHashes()
     */
    public Map<byte[], Tx> getAssociatedTransactions() {
        return Collections.unmodifiableMap(associatedTransactions);
    }

    /**
     * Number of transactions in this block, before it was filtered
     */
    public int getTransactionCount() {
        return merkleTree.transactionCount;
    }
}
