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

import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.InventoryItem;

/**
 * Represents the "getdata" P2P network message, which requests the contents of blocks or transactions given their
 * hashes.
 */
public class GetDataMessage extends ListMessage {
    private static final long serialVersionUID = 2754681589501709887L;

    public GetDataMessage(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes);
    }

    /**
     * Deserializes a 'getdata' message.
     * //     * @param params NetworkParameters object.
     *
     * @param msg    Bitcoin protocol formatted byte array containing message content.
     *               If true and the backing byte array is invalidated due to modification of a field then
     *               the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     *               as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws net.bither.bitherj.exception.ProtocolException
     */
    public GetDataMessage(byte[] msg, int length)
            throws ProtocolException {
        super(msg, length);
    }

    public GetDataMessage() {
        super();
    }

    public void addTransaction(byte[] hash) {
        addItem(new InventoryItem(InventoryItem.Type.Transaction, hash));
    }

    public void addBlock(byte[] hash) {
        addItem(new InventoryItem(InventoryItem.Type.Block, hash));
    }

    public void addFilteredBlock(byte[] hash) {
        addItem(new InventoryItem(InventoryItem.Type.FilteredBlock, hash));
    }
}
