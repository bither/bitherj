/**
 * Copyright 2012 The Bitcoin Developers
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

import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.exception.VerificationException;
import net.bither.bitherj.utils.Utils;
import net.bither.bitherj.utils.VarInt;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>A data structure that contains proofs of block inclusion for one or more transactions, in an efficient manner.</p>
 * <p/>
 * <p>The encoding works as follows: we traverse the tree in depth-first order, storing a bit for each traversed node,
 * signifying whether the node is the parent of at least one matched leaf txid (or a matched txid itself). In case we
 * are at the leaf level, or this bit is 0, its merkle node hash is stored, and its children are not explored further.
 * Otherwise, no hash is stored, but we recurse into both (or the only) child branch. During decoding, the same
 * depth-first traversal is performed, consuming bits and hashes as they were written during encoding.</p>
 * <p/>
 * <p>The serialization is fixed and provides a hard guarantee about the encoded size,
 * <tt>SIZE <= 10 + ceil(32.25*N)</tt> where N represents the number of leaf nodes of the partial tree. N itself
 * is bounded by:</p>
 * <p/>
 * <p>
 * N <= total_transactions<br>
 * N <= 1 + matched_transactions*tree_height
 * </p>
 * <p/>
 * <p><pre>The serialization format:
 *  - uint32     total_transactions (4 bytes)
 *  - varint     number of hashes   (1-3 bytes)
 *  - uint256[]  hashes in depth-first order (<= 32*N bytes)
 *  - varint     number of bytes of flag bits (1-3 bytes)
 *  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)
 * The size constraints follow from this.</pre></p>
 */
public class PartialMerkleTree extends Message {
    // the total number of transactions in the block
    public int transactionCount;

    // node-is-parent-of-matched-txid bits
    byte[] matchedChildBits;

    // txids and internal hashes
    List<byte[]> hashes;

    public PartialMerkleTree(byte[] payloadBytes, int offset) throws ProtocolException {
        super(payloadBytes, offset);
    }

    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(transactionCount, stream);

        stream.write(new VarInt(hashes.size()).encode());
        for (byte[] hash : hashes)
            stream.write(hash);

        stream.write(new VarInt(matchedChildBits.length).encode());
        stream.write(matchedChildBits);
    }

    @Override
    protected void parse() throws ProtocolException {
        transactionCount = (int) readUint32();

        int nHashes = (int) readVarInt();
        hashes = new ArrayList<byte[]>(nHashes);
        for (int i = 0; i < nHashes; i++)
            hashes.add(readHash());

        int nFlagBytes = (int) readVarInt();
        matchedChildBits = readBytes(nFlagBytes);

        length = cursor - offset;
    }

//    @Override
//    protected void parseLite() {
//
//    }

    // helper function to efficiently calculate the number of nodes at given height in the merkle tree
    private int getTreeWidth(int height) {
        return (transactionCount + (1 << height) - 1) >> height;
    }

    private static class ValuesUsed {
        public int bitsUsed = 0, hashesUsed = 0;
    }

    // recursive function that traverses tree nodes, consuming the bits and hashes produced by TraverseAndBuild.
    // it returns the hash of the respective node.
    private byte[] recursiveExtractHashes(int height, int pos, ValuesUsed used, List<byte[]> matchedHashes) throws VerificationException {
        if (used.bitsUsed >= matchedChildBits.length * 8) {
            // overflowed the bits array - failure
            throw new VerificationException("CPartialMerkleTree overflowed its bits array");
        }
        boolean parentOfMatch = Utils.checkBitLE(matchedChildBits, used.bitsUsed++);
        if (height == 0 || !parentOfMatch) {
            // if at height 0, or nothing interesting below, use stored hash and do not descend
            if (used.hashesUsed >= hashes.size()) {
                // overflowed the hash array - failure
                throw new VerificationException("CPartialMerkleTree overflowed its hash array");
            }
            if (height == 0 && parentOfMatch) // in case of height 0, we have a matched txid
                matchedHashes.add(hashes.get(used.hashesUsed));
            return hashes.get(used.hashesUsed++);
        } else {
            // otherwise, descend into the subtrees to extract matched txids and hashes
            byte[] left = recursiveExtractHashes(height - 1, pos * 2, used, matchedHashes), right;
            if (pos * 2 + 1 < getTreeWidth(height - 1))
                right = recursiveExtractHashes(height - 1, pos * 2 + 1, used, matchedHashes);
            else
                right = left;
            // and combine them before returning
            return Utils.doubleDigestTwoBuffers(
                    left, 0, 32,
                    right, 0, 32);
        }
    }

    /**
     * Extracts tx hashes that are in this merkle tree
     * and returns the merkle root of this tree.
     * <p/>
     * The returned root should be checked against the
     * merkle root contained in the block header for security.
     *
     * @param matchedHashes A list which will contain the matched txn (will be cleared)
     *                      Required to be a LinkedHashSet in order to retain order or transactions in the block
     * @return the merkle root of this merkle tree
     * @throws ProtocolException if this partial merkle tree is invalid
     */
    public byte[] getTxnHashAndMerkleRoot(List<byte[]> matchedHashes) throws VerificationException {
        matchedHashes.clear();

        // An empty set will not work
        if (transactionCount == 0)
            throw new VerificationException("Got a CPartialMerkleTree with 0 transactions");
        // check for excessively high numbers of transactions
        if (transactionCount > BlockMessage.MAX_BLOCK_SIZE / 60) // 60 is the lower bound for the size of a serialized CTransaction
            throw new VerificationException("Got a CPartialMerkleTree with more transactions than is possible");
        // there can never be more hashes provided than one for every txid
        if (hashes.size() > transactionCount)
            throw new VerificationException("Got a CPartialMerkleTree with more hashes than transactions");
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if (matchedChildBits.length * 8 < hashes.size())
            throw new VerificationException("Got a CPartialMerkleTree with fewer matched bits than hashes");
        // calculate height of tree
        int height = 0;
        while (getTreeWidth(height) > 1)
            height++;
        // traverse the partial tree
        ValuesUsed used = new ValuesUsed();
        byte[] merkleRoot = recursiveExtractHashes(height, 0, used, matchedHashes);
        // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
        if ((used.bitsUsed + 7) / 8 != matchedChildBits.length ||
                // verify that all hashes were consumed
                used.hashesUsed != hashes.size())
            throw new VerificationException("Got a CPartialMerkleTree that didn't need all the data it provided");

        return merkleRoot;
    }
}
