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
import net.bither.bitherj.utils.InventoryItem;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>Represents the "inv" P2P network message. An inv contains a list of hashes of either blocks or transactions. It's
 * a bandwidth optimization - on receiving some data, a (fully validating) peer sends every connected peer an inv
 * containing the hash of what it saw. It'll only transmit the full thing if a peer asks for it with a
 * {@link GetDataMessage}.</p>
 */
public class InventoryMessage extends ListMessage {
    private static final long serialVersionUID = -7050246551646107066L;

    public InventoryMessage(byte[] bytes) throws ProtocolException {
        super(bytes);
    }

    /**
     * Deserializes an 'inv' message.
     * //     * @param params NetworkParameters object.
     *
     * @param msg    Bitcoin protocol formatted byte array containing message content.
     *               If true and the backing byte array is invalidated due to modification of a field then
     *               the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public InventoryMessage(byte[] msg, int length)
            throws ProtocolException {
        super(msg, length);
    }

    public InventoryMessage() {
        super();
    }

    public void addBlock(Block block) {
        addItem(new InventoryItem(InventoryItem.Type.Block, block.getBlockHash()));
    }

    public void addTransaction(Tx tx) {
        addItem(new InventoryItem(InventoryItem.Type.Transaction, tx.getTxHash()));
    }

    /**
     * Creates a new inv message for the given transactions.
     */
    public static InventoryMessage with(Tx... txns) {
        checkArgument(txns.length > 0);
        InventoryMessage result = new InventoryMessage();
        for (Tx tx : txns)
            result.addTransaction(tx);
        return result;
    }
}
