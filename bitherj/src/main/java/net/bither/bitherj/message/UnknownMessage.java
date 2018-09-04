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
import net.bither.bitherj.utils.Utils;

public class UnknownMessage extends EmptyMessage {
    private static final long serialVersionUID = 3614705938207918775L;
    private String name;

    public UnknownMessage(String name, byte[] payloadBytes) throws ProtocolException {
        super(payloadBytes, 0);
        this.name = name;
    }

    public String toString() {
        return "Unknown message [" + name + "]: " + (bytes == null ? "" : Utils.bytesToHexString(bytes));
    }

}
