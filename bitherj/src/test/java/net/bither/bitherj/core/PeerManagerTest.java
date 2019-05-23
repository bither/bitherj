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

import org.junit.Test;

public class PeerManagerTest {

    @Test
    public void testNormal() throws InterruptedException {
        Block block = new Block(2, "00000000000000000ee9b585e0a707347d7c80f3a905f48fa32d448917335366", "4d60e37c7086096e85c11324d70112e61e74fc38a5c5153587a0271fd22b65c5", 1400928750
                , 409544770l, 4079278699l, 302400);
        BlockChain.getInstance().addSPVBlock(block);
        PeerManager.instance().start();

        while (true) {
            Thread.sleep(1000);
        }
    }
}
