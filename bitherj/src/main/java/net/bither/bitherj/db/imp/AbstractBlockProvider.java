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

package net.bither.bitherj.db.imp;

import com.google.common.base.Function;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IBlockProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IDb;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractBlockProvider extends AbstractProvider implements IBlockProvider {

    public List<Block> getAllBlocks() {
        final List<Block> blockItems = new ArrayList<Block>();
        String sql = "select * from blocks order by block_no desc";

        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                blockItems.add(applyCursor(c));
                return null;
            }
        });
        return blockItems;
    }

    @Override
    public List<Block> getLimitBlocks(int limit) {
        final List<Block> blockItems = new ArrayList<Block>();
        String sql = "select * from blocks order by block_no desc limit ?";
        this.execQueryLoop(sql, new String[]{Integer.toString(limit)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                blockItems.add(applyCursor(c));
                return null;
            }
        });
        return blockItems;
    }

    public List<Block> getBlocksFrom(int blockNo) {
        final List<Block> blockItems = new ArrayList<Block>();
        String sql = "select * from blocks where block_no>? order by block_no desc";
        this.execQueryLoop(sql, new String[]{Integer.toString(blockNo)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                blockItems.add(applyCursor(c));
                return null;
            }
        });
        return blockItems;
    }

    public int getBlockCount() {
        String sql = "select count(*) cnt from blocks ";
        final int[] count = {0};
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    count[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return count[0];
    }

    public Block getLastBlock() {
        final Block[] item = {null};
        String sql = "select * from blocks where is_main=1 order by block_no desc limit 1";

        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                item[0] = applyCursor(c);
                return null;
            }
        });
        return item[0];
    }

    public Block getLastOrphanBlock() {
        final Block[] item = {null};
        String sql = "select * from blocks where is_main=0 order by block_no desc limit 1";
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                item[0] = applyCursor(c);
                return null;
            }
        });
        return item[0];
    }

    public Block getBlock(byte[] blockHash) {
        final Block[] item = {null};
        String sql = "select * from blocks where block_hash=?";
        this.execQueryOneRecord(sql, new String[]{Base58.encode(blockHash)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                item[0] = applyCursor(c);
                return null;
            }
        });
        return item[0];
    }

    public Block getOrphanBlockByPrevHash(byte[] prevHash) {
        final Block[] item = {null};
        String sql = "select * from blocks where block_prev=? and is_main=0";
        this.execQueryOneRecord(sql, new String[]{Base58.encode(prevHash)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                item[0] = applyCursor(c);
                return null;
            }
        });
        return item[0];
    }

    public Block getMainChainBlock(byte[] blockHash) {
        final Block[] item = {null};
        String sql = "select * from blocks where block_hash=? and is_main=1";
        this.execQueryOneRecord(sql, new String[]{Base58.encode(blockHash)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                item[0] = applyCursor(c);
                return null;
            }
        });
        return item[0];
    }

//    public List<byte[]> exists(List<byte[]> blockHashes) {
//        List<byte[]> exists = new ArrayList<byte[]>();
//        List<Block> blockItems = getAllBlocks();
//        for (Block blockItm : blockItems) {
//            for (byte[] bytes : exists) {
//                if (Arrays.equals(bytes, blockItm.getBlockHash())) {
//                    exists.add(bytes);
//                    break;
//                }
//            }
//        }
//        return exists;
//    }

    public void addBlocks(List<Block> blockItemList) {
        List<Block> addBlockList = new ArrayList<Block>();
        for (Block item : blockItemList) {
            if (!this.blockExists(item.getBlockHash())) {
                addBlockList.add(item);
            }
        }
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        String sql = "insert into blocks(block_no,block_hash,block_root,block_ver,block_bits,block_nonce,block_time,block_prev,is_main) values(?,?,?,?,?,?,?,?,?)";
        for (Block item : addBlockList) {
            this.execUpdate(writeDb, sql, new String[] {
                    Integer.toString(item.getBlockNo())
                    , Base58.encode(item.getBlockHash())
                    , Base58.encode(item.getBlockRoot())
                    , Long.toString(item.getBlockVer())
                    , Long.toString(item.getBlockBits())
                    , Long.toString(item.getBlockNonce())
                    , Long.toString(item.getBlockTime())
                    , Base58.encode(item.getBlockPrev())
                    , item.isMain() ? "1" : "0"
            });
        }
        writeDb.endTransaction();
    }

    public void addBlock(Block item) {
        boolean blockExists = blockExists(item.getBlockHash());
        if (!blockExists) {
            String sql = "insert into blocks(block_no,block_hash,block_root,block_ver,block_bits,block_nonce,block_time,block_prev,is_main) values(?,?,?,?,?,?,?,?,?)";
            this.execUpdate(sql, new String[] {
                    Integer.toString(item.getBlockNo())
                    , Base58.encode(item.getBlockHash())
                    , Base58.encode(item.getBlockRoot())
                    , Long.toString(item.getBlockVer())
                    , Long.toString(item.getBlockBits())
                    , Long.toString(item.getBlockNonce())
                    , Long.toString(item.getBlockTime())
                    , Base58.encode(item.getBlockPrev())
                    , item.isMain() ? "1" : "0"
            });
        }
    }

    public boolean blockExists(byte[] blockHash) {
        String sql = "select count(0) cnt from blocks where block_hash=?";
        final int[] cnt = {0};

        this.execQueryOneRecord(sql, new String[]{Base58.encode(blockHash)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                cnt[0] = c.getInt(0);
                return null;
            }
        });
        return cnt[0] > 0;
    }

    public void updateBlock(byte[] blockHash, boolean isMain) {
        String sql = "update blocks set is_main=? where block_hash=?";
        this.execUpdate(sql, new String[] {isMain ? "1" : "0", Base58.encode(blockHash)});
    }

    public void removeBlock(byte[] blockHash) {
        String sql = "delete from blocks where block_hash=?";
        this.execUpdate(sql, new String[]{Base58.encode(blockHash)});
    }

    public void cleanOldBlock() {
        String sql = "select count(0) cnt from blocks";
        final int[] cnt = {0};
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                cnt[0] = c.getInt(0);
                return null;
            }
        });
        if (cnt[0] > 5000) {
            sql = "select max(block_no) max_block_no from blocks where is_main=1";
            final int[] maxBlockNo = {0};
            this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    maxBlockNo[0] = c.getInt(0);
                    return null;
                }
            });

            int blockNo = (maxBlockNo[0] - BitherjSettings.BLOCK_DIFFICULTY_INTERVAL) - maxBlockNo[0] % BitherjSettings.BLOCK_DIFFICULTY_INTERVAL;
            sql = "delete from blocks where block_no<?";
            this.execUpdate(sql, new String[]{Integer.toString(blockNo)});
        }
    }

    private Block applyCursor(ICursor c) {
        byte[] blockHash = null;
        long version = 1;
        byte[] prevBlock = null;
        byte[] merkleRoot = null;
        int timestamp = 0;
        long target = 0;
        long nonce = 0;
        int blockNo = 0;
        boolean isMain = false;
        int idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_BITS);
        if (idColumn != -1) {
            target = c.getLong(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_HASH);
        if (idColumn != -1) {
            try {
                blockHash = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_NO);
        if (idColumn != -1) {
            blockNo = c.getInt(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_NONCE);
        if (idColumn != -1) {
            nonce = c.getLong(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_PREV);
        if (idColumn != -1) {
            try {
                prevBlock = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_ROOT);
        if (idColumn != -1) {
            try {
                merkleRoot = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_TIME);
        if (idColumn != -1) {
            timestamp = c.getInt(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.BLOCK_VER);
        if (idColumn != -1) {
            version = c.getLong(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.BlocksColumns.IS_MAIN);
        if (idColumn != -1) {
            isMain = c.getInt(idColumn) == 1;
        }
        return new Block(blockHash, version, prevBlock, merkleRoot, timestamp, target, nonce, blockNo, isMain);
    }
}
