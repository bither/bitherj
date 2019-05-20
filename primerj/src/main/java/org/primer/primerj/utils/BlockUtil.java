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

package org.primer.primerj.utils;


import org.primer.primerj.AbstractApp;
import org.primer.primerj.PrimerjSettings;
import org.primer.primerj.api.BlockChainDownloadSpvApi;
import org.primer.primerj.api.BlockChainDownloadSpvApiNew;
import org.primer.primerj.api.BlockChainDownloadSpvApiNewBlock;
import org.primer.primerj.api.BlockChainGetLatestBlockNew;
import org.primer.primerj.core.Block;
import org.primer.primerj.core.BlockChain;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BlockUtil {

    private static final Logger log = LoggerFactory.getLogger(BlockUtil.class);

    private static final String VER = "ver";
    private static final String PREV_BLOCK = "prev_block";
    private static final String MRKL_ROOT = "mrkl_root";
    private static final String TIME = "time";
    private static final String BITS = "bits";
    private static final String NONCE = "nonce";
    private static final String BLOCK_NO = "block_no";
    private static final String HEIGHT = "height";

    public  static Block getLatestBlockHeight(JSONObject jsonObject)
            throws Exception {
        int latestHeight = jsonObject.getInt("height");
        int height = 0;
        if (latestHeight % 2016 !=0){
            height = latestHeight - (latestHeight%2016);
        }else {
            height = latestHeight;
        }
        BlockChainDownloadSpvApi blockChainDownloadSpvApi = new BlockChainDownloadSpvApi(height);
        blockChainDownloadSpvApi.handleHttpGet();
        Block block = blockChainDownloadSpvApi.getResult();
        return block;
    }
    public  static Block getLatestBlockHeightNew(JSONObject jsonObject)
            throws Exception {
        JSONArray array = jsonObject.getJSONArray("blocks");
        JSONObject object = (JSONObject) array.get(0);
        int latestHeight = object.getInt("height");
        int height = 0;
        if (latestHeight % 2016 !=0){
            height = latestHeight - (latestHeight%2016);
        }else {
            height = latestHeight;
        }
        BlockChainDownloadSpvApiNew blockChainDownloadSpvApi = new BlockChainDownloadSpvApiNew(height);
        blockChainDownloadSpvApi.handleHttpGet();
        Block block = blockChainDownloadSpvApi.getResult();
        return block;
    }
    public  static Block getLatestBlockHash(String hash)
            throws Exception {

        BlockChainDownloadSpvApiNewBlock blockChainDownloadSpvApi = new BlockChainDownloadSpvApiNewBlock(hash);
        blockChainDownloadSpvApi.handleHttpGet();
        Block block = blockChainDownloadSpvApi.getResult();
        return block;
    }
    public static Block formatStoreBlockFromBlockChainInfoNew(JSONObject jsonObject)
            throws JSONException{
        long ver = jsonObject.getLong("version");
        int height = jsonObject.getInt("height");
        String prevBlock = jsonObject.getString("previousblockhash");
        String mrklRoot = jsonObject.getString("merkleroot");
        int time = jsonObject.getInt(TIME);
        long difficultyTarget = Integer.parseInt(jsonObject.getString(BITS),16);
        long nonce = jsonObject.getLong(NONCE);

        return BlockUtil.getStoredBlock(ver, prevBlock, mrklRoot, time,
                difficultyTarget, nonce, height);

    }
    public static Block formatStoreBlockFromBlockChainInfo(JSONObject jsonObject)
        throws JSONException{
        long ver = jsonObject.getLong(VER);
        int height = jsonObject.getInt(HEIGHT);
        String prevBlock = jsonObject.getString(PREV_BLOCK);
        String mrklRoot = jsonObject.getString(MRKL_ROOT);
        int time = jsonObject.getInt(TIME);
        long difficultyTarget = jsonObject.getLong(BITS);
        long nonce = jsonObject.getLong(NONCE);

        return BlockUtil.getStoredBlock(ver, prevBlock, mrklRoot, time,
                difficultyTarget, nonce, height);

    }

    public static Block formatStoredBlock(JSONObject jsonObject)
            throws JSONException {
        long ver = jsonObject.getLong(VER);
        int height = jsonObject.getInt(BLOCK_NO);
        String prevBlock = jsonObject.getString(PREV_BLOCK);
        String mrklRoot = jsonObject.getString(MRKL_ROOT);
        int time = jsonObject.getInt(TIME);
        long difficultyTarget = jsonObject.getLong(BITS);
        long nonce = jsonObject.getLong(NONCE);

        return BlockUtil.getStoredBlock(ver, prevBlock, mrklRoot, time,
                difficultyTarget, nonce, height);
    }

    public static Block formatStoredBlock(JSONObject jsonObject, int hegih)
            throws JSONException {
        long ver = jsonObject.getLong(VER);
        String prevBlock = jsonObject.getString(PREV_BLOCK);
        String mrklRoot = jsonObject.getString(MRKL_ROOT);
        int time = jsonObject.getInt(TIME);
        long difficultyTarget = jsonObject.getLong(BITS);
        long nonce = jsonObject.getLong(NONCE);

        return BlockUtil.getStoredBlock(ver, prevBlock, mrklRoot, time,
                difficultyTarget, nonce, hegih);

    }

    public static Block getStoredBlock(long ver, String prevBlock,
                                       String mrklRoot, int time, long difficultyTarget, long nonce,
                                       int hegiht) {
        Block b = new Block(ver,
                prevBlock, mrklRoot, time,
                difficultyTarget, nonce, hegiht);
        return b;
    }

    public synchronized static Block dowloadSpvBlock() throws Exception {
        if (AbstractApp.bitherjSetting.getDownloadSpvFinish()) {
            return null;
        }
        Block block = null;
//        try {
//            DownloadSpvApi downloadSpvApi = new DownloadSpvApi();
//            downloadSpvApi.handleHttpGet();
//            block = downloadSpvApi.getResult();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        try {
            if (block == null) {
//                BlockChainGetLatestBlockApi blockChainGetLatestBlockApi = new BlockChainGetLatestBlockApi();
                BlockChainGetLatestBlockNew blockChainGetLatestBlockApi = new BlockChainGetLatestBlockNew();
                blockChainGetLatestBlockApi.handleHttpGet();
                block = blockChainGetLatestBlockApi.getResult();
                log.info("Block: " + block + " ");
                log.info("Block: interval is " + String.valueOf(PrimerjSettings.INTERVAL));
            }
        } catch (Exception e) {
            e.printStackTrace();
            AbstractApp.notificationService.sendBroadcastGetSpvBlockComplete(false);
            throw e;
        }
        if (block.getBlockNo() % PrimerjSettings.INTERVAL == 0) {
            BlockChain.getInstance().addSPVBlock(block);
            AbstractApp.bitherjSetting.setDownloadSpvFinish(true);
            AbstractApp.notificationService.sendBroadcastGetSpvBlockComplete(true);
        } else {
            AbstractApp.notificationService.sendBroadcastGetSpvBlockComplete(false);
            return null;
        }
        return block;
    }


}
