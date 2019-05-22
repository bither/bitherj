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

package net.bither.bitherj.db;


import net.bither.bitherj.core.Block;

import java.util.List;

public interface IBlockProvider {

    List<Block> getAllBlocks();

    List<Block> getBlocksFrom(int blockNo);

    List<Block> getLimitBlocks(int limit);

    int getBlockCount();

    Block getLastBlock();

    Block getLastOrphanBlock();

    Block getBlock(byte[] blockHash);

    Block getOrphanBlockByPrevHash(byte[] prevHash);

    Block getMainChainBlock(byte[] blockHash);

//    List<byte[]> exists(List<byte[]> blockHashes);

    void addBlocks(List<Block> blockItemList);

    void addBlock(Block item);

    void updateBlock(byte[] blockHash, boolean isMain);

    void removeBlock(byte[] blockHash);

    void cleanOldBlock();


}
