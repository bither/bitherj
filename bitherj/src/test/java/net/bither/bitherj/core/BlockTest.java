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

import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class BlockTest {
    @Test
    public void testText() {
        assertEquals("", "");
        Block block = new Block(2, "00000000000000003711b624fbde8c77d4c7e25334cfa8bc176b7248ca67b24b", "d1ce608b0e83f5b0c134d27ea6952fc55bc68b5ccf0490bbb47ea1906a7075d0", 1407474112
                , 406305378, 2798738616L, 314496);
        String str = Utils.bytesToHexString(Utils.reverseBytes(block.getBlockHash()));
        assertEquals("000000000000000030e597a72386c512d830b08ecc70b254f46033fd06f2bf93", str);

        AbstractDb.blockProvider.addBlock(block);
        Block testBlock = AbstractDb.blockProvider.
                getBlock(Utils.reverseBytes(Utils.hexStringToByteArray(
                        "000000000000000030e597a72386c512d830b08ecc70b254f46033fd06f2bf93")));

        assertEquals(Utils.bytesToHexString(testBlock.getBlockHash()), Utils.bytesToHexString(block.getBlockHash()));
    }

    @Test
    public void testBlockConstructor() {
        Block block = new Block(1, "0000000000000000000000000000000000000000000000000000000000000000"
                , "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", 1231006505
                , 486604799, 2083236893, 0);
        byte[] expectBlockHash = Utils.reverseBytes(Utils.hexStringToByteArray("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        assertTrue(Arrays.equals(block.getBlockHash(), expectBlockHash));
        Block block1 = new Block(block.bitcoinSerialize());
        assertTrue(Arrays.equals(block1.getBlockHash(), expectBlockHash));
    }
}
