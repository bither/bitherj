/**
 * Copyright 2011 Steve Coughlan.
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

import javax.annotation.Nullable;

/**
 * Represents a Message type that can be contained within another Message.  ChildMessages that have a cached
 * backing byte array need to invalidate their parent's caches as well as their own if they are modified.
 *
 * @author git
 */
public abstract class ChildMessage extends Message {
    private static final long serialVersionUID = -7657113383624517931L;

    @Nullable
    private Message parent;

    protected ChildMessage() {
    }

//    public ChildMessage() {
//        super();
//    }

    public ChildMessage(byte[] msg, int offset, int protocolVersion) throws ProtocolException {
        super(msg, offset, protocolVersion);
    }

    public ChildMessage(byte[] msg, int offset, int protocolVersion, int length) throws ProtocolException {
        super(msg, offset, protocolVersion, length);
    }

    public ChildMessage(byte[] msg, int offset, int protocolVersion, Message parent, int length) throws ProtocolException {
        super(msg, offset, protocolVersion, length);
        this.parent = parent;
    }

    public ChildMessage(byte[] msg, int offset) throws ProtocolException {
        super(msg, offset);
    }

    public ChildMessage(byte[] msg, int offset, @Nullable Message parent, int length)
            throws ProtocolException {
        super(msg, offset, length);
        this.parent = parent;
    }

    public void setParent(@Nullable Message parent) {
        if (this.parent != null && this.parent != parent && parent != null) {
            // After old parent is unlinked it won't be able to receive notice if this ChildMessage
            // changes internally.  To be safe we invalidate the parent cache to ensure it rebuilds
            // manually on serialization.
//            this.parent.unCache();
        }
        this.parent = parent;
    }

    protected void adjustLength(int adjustment) {
        adjustLength(0, adjustment);
    }

    protected void adjustLength(int newArraySize, int adjustment) {
        super.adjustLength(newArraySize, adjustment);
        if (parent != null)
            parent.adjustLength(newArraySize, adjustment);
    }

}
