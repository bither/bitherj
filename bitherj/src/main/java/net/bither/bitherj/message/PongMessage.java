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

import net.bither.bitherj.exception.ProtocolException;
import net.bither.bitherj.utils.Utils;

import java.io.IOException;
import java.io.OutputStream;

public class PongMessage extends Message {
    /**
     * The smallest protocol version that supports the pong response (BIP 31). Anything beyond version 60000.
     */
    public static final int MIN_PROTOCOL_VERSION = 60001;

    private long nonce;

    public PongMessage(byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0);
    }

    /**
     * Create a Pong with a nonce value.
     * Only use this if the remote node has a protocol version > 60000
     */
    public PongMessage(long nonce) {
        this.nonce = nonce;
    }

    @Override
    protected void parse() throws ProtocolException {
        nonce = readInt64();
        length = 8;
    }

    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        Utils.int64ToByteStreamLE(nonce, stream);
    }

//    @Override
//    protected void parseLite() {
//    }

    public long getNonce() {
        return nonce;
    }
}
