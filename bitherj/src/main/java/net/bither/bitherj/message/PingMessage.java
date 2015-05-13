/**
 * Copyright 2011 Noa Resare
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
import net.bither.bitherj.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;

public class PingMessage extends Message {
    private long nonce;
    private boolean hasNonce;

    public PingMessage(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0);
    }

    /**
     * Create a Ping with a nonce value.
     * Only use this if the remote node has a protocol version > 60000
     */
    public PingMessage(long nonce) {
        this.nonce = nonce;
        this.hasNonce = true;
    }

    /**
     * Create a Ping without a nonce value.
     * Only use this if the remote node has a protocol version <= 60000
     */
    public PingMessage() {
        this.hasNonce = false;
    }

    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        if (hasNonce)
            Utils.int64ToByteStreamLE(nonce, stream);
    }

    @Override
    protected void parse() throws ProtocolException {
        try {
            nonce = readInt64();
            hasNonce = true;
        } catch (ProtocolException e) {
            hasNonce = false;
        }
        length = hasNonce ? 8 : 0;
    }

    public boolean hasNonce() {
        return hasNonce;
    }

    public long getNonce() {
        return nonce;
    }
}
