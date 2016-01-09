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

package net.bither.bitherj.utils;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.api.BitherMytransactionsApi;
import net.bither.bitherj.api.BlockChainMytransactionsApi;
import net.bither.bitherj.core.*;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.ScriptException;
import net.bither.bitherj.qrcode.QRCodeUtil;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TransactionsUtil {

    private static final Logger log = LoggerFactory.getLogger(TransactionsUtil.class);
    private static final String TX = "tx";
    private static final String BLOCK_COUNT = "block_count";
    private static final String TX_CNT = "tx_cnt";
    // TODO: blockChain.info
    private static final String BLOCK_CHAIN_HEIGHT = "height";
    private static final String BLOCK_CHAIN_TX = "n_tx";
    private static final String BLOCK_CHAIN_TXS = "txs";
    private static final String BLOCK_CHAIN_BLOCK_HEIGHT = "block_height";
    private static final String BLOCK_CHAIN_TX_INDEX = "tx_index";
    private static final String BLOCK_CHAIN_CNT = "n_tx";


    private static List<UnSignTransaction> unsignTxs = new ArrayList<UnSignTransaction>();

    /**
     *  TODO: get data from blockChain.info
     */
    private  static List<Tx> getTransactionsFromBlockChain(
            JSONObject jsonObject, int storeBlockHeight) throws Exception {
        List<Tx> transactions = new ArrayList<Tx>();
        List<Block> blocks = AbstractDb.blockProvider.getAllBlocks();
        Map<Integer, Integer> blockMapList = new HashMap<Integer, Integer>();
        int minBlockNo = blocks.get(blocks.size() - 1).getBlockNo();
        for (Block block : blocks) {
            blockMapList.put(block.getBlockNo(), block.getBlockTime());
            if (minBlockNo > block.getBlockNo()) {
                minBlockNo = block.getBlockNo();
            }
        }

        if (!jsonObject.isNull(BLOCK_CHAIN_TX)) {
            JSONArray txsArray = jsonObject.getJSONArray(BLOCK_CHAIN_TXS);
            for (int i = 0; i < txsArray.length(); i++) {
                JSONObject txJSON = txsArray.getJSONObject(i);
                if (!txJSON.has(BLOCK_CHAIN_BLOCK_HEIGHT)) {
                    continue;
                }
                int height = txJSON.getInt(BLOCK_CHAIN_BLOCK_HEIGHT);
                if (height > storeBlockHeight && storeBlockHeight > 0) {
                    continue;
                }
                Integer timeKey = height;
                if (height <= minBlockNo) {
                    timeKey = minBlockNo;
                }
                // TODO: get single tx hex format data
                int txIndex = txJSON.getInt(BLOCK_CHAIN_TX_INDEX);

                String txHex = getTxHexByIndex(txIndex);

                byte[] decodeTxHex = Hex.decode(txHex);
                // byte[] txBytes = Base64.encode(decodeTxHex, Base64.DEFAULT);

                Tx tx = new Tx(decodeTxHex);
                tx.setBlockNo(height);

                if (blockMapList.containsKey(timeKey)) {
                    tx.setTxTime(blockMapList.get(timeKey));
                }
                transactions.add(tx);
            }
        }
        return transactions;

    }

    private static String getTxHexByIndex(int txIndex) throws Exception {
        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi(txIndex);
        blockChainMytransactionsApi.handleHttpGet();
        String rel = blockChainMytransactionsApi.getResult();
        return rel;
    }
    /**
     *  end
     */


    private static List<Tx> getTransactionsFromBither(
            JSONObject jsonObject, int storeBlockHeight) throws JSONException {
        List<Tx> transactions = new ArrayList<Tx>();
        List<Block> blocks = AbstractDb.blockProvider.getAllBlocks();
        Map<Integer, Integer> blockMapList = new HashMap<Integer, Integer>();
        int minBlockNo = blocks.get(blocks.size() - 1).getBlockNo();
        for (Block block : blocks) {
            blockMapList.put(block.getBlockNo(), block.getBlockTime());
            if (minBlockNo > block.getBlockNo()) {
                minBlockNo = block.getBlockNo();
            }
        }
        if (!jsonObject.isNull(TX)) {
            JSONArray txsArray = jsonObject.getJSONArray(TX);
            for (int i = 0; i < txsArray.length(); i++) {
                JSONArray txArray = txsArray.getJSONArray(i);
                if (txArray.length() < 2) {
                    continue;
                }
                int height = txArray.getInt(0);
                if (height > storeBlockHeight && storeBlockHeight > 0) {
                    continue;
                }
                String txString = txArray.getString(1);
                byte[] txBytes = Base64.decode(txString, Base64.DEFAULT);
                Tx tx = new Tx(txBytes);
                tx.setBlockNo(height);
                Integer timeKey = height;
                if (height <= minBlockNo) {
                    timeKey = minBlockNo;
                }
                if (blockMapList.containsKey(timeKey)) {
                    tx.setTxTime(blockMapList.get(timeKey));
                }
                transactions.add(tx);
            }
        }
        return transactions;

    }

    public static List<In> getInSignatureFromBither(String str) {
        List<In> result = new ArrayList<In>();
        if (str.length() > 0) {
            String[] txs = str.split(";");
            for (String tx : txs) {
                String[] ins = tx.split(":");
                byte[] txHash = Utils.reverseBytes(Base64.decode(ins[0], Base64.URL_SAFE));
                for (int i = 1; i < ins.length; i++) {
                    String[] array = ins[i].split(",");
                    int inSn = Integer.decode(array[0]);
                    byte[] inSignature = Base64.decode(array[1], Base64.URL_SAFE);
                    In in = new In();
                    in.setTxHash(txHash);
                    in.setInSn(inSn);
                    in.setInSignature(inSignature);
                    result.add(in);
                }
            }
        }
        return result;
    }

    public static class ComparatorTx implements Comparator<Tx> {

        @Override
        public int compare(Tx lhs, Tx rhs) {
            if (lhs.getBlockNo() != rhs.getBlockNo()) {
                return Integer.valueOf(lhs.getBlockNo()).compareTo(Integer.valueOf(rhs.getBlockNo()));
            } else {
                return Integer.valueOf(lhs.getTxTime()).compareTo(Integer.valueOf(rhs.getTxTime()));
            }

        }

    }

    // TODO display unSignTx

    public static UnSignTransaction getUnsignTxFromCache(String address) {
        synchronized (unsignTxs) {
            for (UnSignTransaction unSignTransaction : unsignTxs) {
                if (Utils.compareString(address,
                        unSignTransaction.getAddress())) {
                    return unSignTransaction;
                }
            }
            return null;
        }

    }

    public static void removeSignTx(UnSignTransaction unSignTransaction) {
        synchronized (unsignTxs) {
            if (unsignTxs.contains(unSignTransaction)) {
                unsignTxs.remove(unSignTransaction);
            }
        }
    }

    public static void addUnSignTxToCache(UnSignTransaction unSignTransaction) {
        synchronized (unsignTxs) {
            if (unsignTxs.contains(unSignTransaction)) {
                unsignTxs.remove(unSignTransaction);
            }
            unsignTxs.add(unSignTransaction);
        }
    }

    public static boolean signTransaction(Tx tx, String qrCodeContent)
            throws ScriptException {
        String[] stringArray = QRCodeUtil.splitString(qrCodeContent);
        List<byte[]> hashList = new ArrayList<byte[]>();
        for (String str : stringArray) {
            if (!Utils.isEmpty(str)) {
                hashList.add(Utils.hexStringToByteArray(str));
            }
        }
        tx.signWithSignatures(hashList);
        return tx.verifySignatures();
    }


    public static void getMyTxFromBither() throws Exception {
        if (AbstractApp.bitherjSetting.getAppMode() != BitherjSettings.AppMode.HOT) {
            return;
        }
        // TODO: web type
        int flag = AbstractApp.bitherjSetting.getApiConfig().value();
        getTxForAddress(flag);
        if (AddressManager.getInstance().getHDAccountHot() != null) {
            getTxForHDAccount(AddressManager.getInstance().getHDAccountHot().getHdSeedId(), flag);
        }
        if(AddressManager.getInstance().hasHDAccountMonitored()){
            getTxForHDAccountMoitored(AddressManager.getInstance().getHDAccountMonitored().getHdSeedId(), flag);

        }
        if (AddressManager.getInstance().hasDesktopHDMKeychain()) {
            DesktopHDMKeychain desktopHDMKeychain = AddressManager.getInstance().getDesktopHDMKeychains().get(0);
            getTxForDesktopHDM(desktopHDMKeychain, flag);

        }

    }
    private static void getTxForHDAccountMoitored(int hdSeedId, final int webType) throws Exception {
        for (AbstractHD.PathType pathType : AbstractHD.PathType.values()) {
            HDAccount.HDAccountAddress hdAccountAddress;
//            boolean hasTx = true;
            int unusedAddressCnt = 0; //HDAccount.MaxUnusedNewAddressCount
            int maxUnusedAddressCount = HDAccount.MaxUnusedNewAddressCount;
            int addressIndex = 0;
            while (unusedAddressCnt <= maxUnusedAddressCount) {
                Block storedBlock = BlockChain.getInstance().getLastBlock();
                int storeBlockHeight = storedBlock.getBlockNo();
                hdAccountAddress = AbstractDb.hdAccountAddressProvider.addressForPath(hdSeedId,
                        pathType, addressIndex);
                if (hdAccountAddress == null) {
//                    hasTx = false;
                    unusedAddressCnt += 1;
                    log.warn("hd monitor address is null path {} ,index {}", pathType, addressIndex);
                    continue;
                }
                if (hdAccountAddress.isSyncedComplete()) {
                    log.info("hd monitor address is synced path {} ,index {}, {}", pathType,
                            addressIndex, hdAccountAddress.getAddress());
                    addressIndex++;
                    continue;
                }

                int apiBlockCount = 0;
                int txSum = 0;
                boolean needGetTxs = true;
                int page = 1;

                List<Tx> transactions;

                log.info("hd monitor address will sync path {} ,index {}, {}", pathType, addressIndex, hdAccountAddress.getAddress());
                while (needGetTxs) {
                    // TODO: get data from bither.net else from blockchain.info
                    if (webType == 0) {
                        BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                                hdAccountAddress.getAddress(), page);
                        bitherMytransactionsApi.handleHttpGet();
                        String txResult = bitherMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);

                        if (!jsonObject.isNull(BLOCK_COUNT)) {
                            apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                        }
                        int txCnt = jsonObject.getInt(TX_CNT);
                        // TODO: HDAccount
                        transactions = TransactionsUtil.getTransactionsFromBither(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        AddressManager.getInstance().getHDAccountMonitored().initTxs(transactions);

                        txSum = txSum + transactions.size();
                        needGetTxs = transactions.size() > 0;
                        page++;

                    }else {
                        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi(hdAccountAddress.getAddress());
                        blockChainMytransactionsApi.handleHttpGet();
                        String txResult = blockChainMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);
                        // TODO: get the latest block number from blockChain.info
                        JSONObject jsonObjectBlockChain = getLatestBlockNumberFromBlockchain();
                        if (!jsonObjectBlockChain.isNull(BLOCK_CHAIN_HEIGHT)) {
                            apiBlockCount = jsonObjectBlockChain.getInt(BLOCK_CHAIN_HEIGHT);
                        }
                        int txCnt = jsonObject.getInt(BLOCK_CHAIN_CNT);
                        // TODO: get transactions from blockChain.info
                        transactions = TransactionsUtil.getTransactionsFromBlockChain(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        AddressManager.getInstance().getHDAccountMonitored().initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = false;

                    }
                }
                /*
                while (needGetTxs) {
                    BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                            hdAccountAddress.getAddress(), page, flag);
                    bitherMytransactionsApi.handleHttpGet();
                    String txResult = bitherMytransactionsApi.getResult();
                    JSONObject jsonObject = new JSONObject(txResult);
                    if (!jsonObject.isNull(BLOCK_COUNT)) {
                        apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                    }
                    int txCnt = jsonObject.getInt(TX_CNT);
                    List<Tx> transactions = TransactionsUtil.getTransactionsFromBither(
                            jsonObject, storeBlockHeight);
                    transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);
                    Collections.sort(transactions, new ComparatorTx());
                    AddressManager.getInstance().getHDAccountMonitored().initTxs(transactions);
                    txSum = txSum + transactions.size();
                    needGetTxs = transactions.size() > 0;
                    page++;
                }
                */
                if (apiBlockCount < storeBlockHeight && storeBlockHeight - apiBlockCount < 100) {
                    BlockChain.getInstance().rollbackBlock(apiBlockCount);
                }

                log.info("hd monitor address did sync {} tx, path {} ,index {}, {}", txSum, pathType, addressIndex, hdAccountAddress.getAddress());
                hdAccountAddress.setSyncedComplete(true);
                AddressManager.getInstance().getHDAccountMonitored().updateSyncComplete(hdAccountAddress);

                if (txSum > 0) {
                    if (pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                        AddressManager.getInstance().getHDAccountMonitored().updateIssuedExternalIndex(addressIndex);
                    } else {
                        AddressManager.getInstance().getHDAccountMonitored().updateIssuedInternalIndex(addressIndex);
                    }
                    AddressManager.getInstance().getHDAccountMonitored().supplyEnoughKeys(false);
//                    hasTx = true;
                    unusedAddressCnt = 0;
                } else {
//                    hasTx = false;
                    unusedAddressCnt += 1;
                }
                addressIndex++;
            }
            AbstractDb.hdAccountAddressProvider.updateSyncedForIndex(hdSeedId, pathType, addressIndex - 1);
        }
    }

    private static void getTxForHDAccount(int hdSeedId, final int webType) throws Exception {
        for (AbstractHD.PathType pathType : AbstractHD.PathType.values()) {
            HDAccount.HDAccountAddress hdAccountAddress;
//            boolean hasTx = true;
            int unusedAddressCnt = 0; //HDAccount.MaxUnusedNewAddressCount
            int maxUnusedAddressCount = HDAccount.MaxUnusedNewAddressCount;
            int addressIndex = 0;
            while (unusedAddressCnt <= maxUnusedAddressCount) {
                Block storedBlock = BlockChain.getInstance().getLastBlock();
                int storeBlockHeight = storedBlock.getBlockNo();
                hdAccountAddress = AbstractDb.hdAccountAddressProvider.addressForPath(hdSeedId,
                        pathType, addressIndex);
                if (hdAccountAddress == null) {
//                    hasTx = false;
                    unusedAddressCnt += 1;
                    log.warn("hd address is null path {} ,index {}", pathType, addressIndex);
                    continue;
                }
                if (hdAccountAddress.isSyncedComplete()) {
                    log.info("hd address is synced path {} ,index {}, {}", pathType,
                            addressIndex, hdAccountAddress.getAddress());
                    addressIndex++;
                    continue;
                }
                int apiBlockCount = 0;
                int txSum = 0;
                boolean needGetTxs = true;
                int page = 1;
                // TODO
                List<Tx> transactions;


                log.info("hd address will sync path {} ,index {}, {}", pathType, addressIndex, hdAccountAddress.getAddress());
                while (needGetTxs) {
                    // TODO: get data from bither.net else from blockchain.info
                    if (webType == 0) {
                        BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                                hdAccountAddress.getAddress(), page);
                        bitherMytransactionsApi.handleHttpGet();
                        String txResult = bitherMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);

                        if (!jsonObject.isNull(BLOCK_COUNT)) {
                            apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                        }
                        int txCnt = jsonObject.getInt(TX_CNT);
                        transactions = TransactionsUtil.getTransactionsFromBither(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        AddressManager.getInstance().getHDAccountHot().initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = transactions.size() > 0;
                        page++;

                    }else {
                        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi(hdAccountAddress.getAddress());
                        blockChainMytransactionsApi.handleHttpGet();
                        String txResult = blockChainMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);
                        // TODO: get the latest block number from blockChain.info
                        JSONObject jsonObjectBlockChain = getLatestBlockNumberFromBlockchain();
                        if (!jsonObjectBlockChain.isNull(BLOCK_CHAIN_HEIGHT)) {
                            apiBlockCount = jsonObjectBlockChain.getInt(BLOCK_CHAIN_HEIGHT);
                        }
                        int txCnt = jsonObject.getInt(BLOCK_CHAIN_CNT);
                        // TODO: get transactions from blockChain.info
                        transactions = TransactionsUtil.getTransactionsFromBlockChain(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        AddressManager.getInstance().getHDAccountHot().initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = false;

                    }
                }
                /*
                while (needGetTxs) {
                    BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                            hdAccountAddress.getAddress(), page, flag);
                    bitherMytransactionsApi.handleHttpGet();
                    String txResult = bitherMytransactionsApi.getResult();
                    JSONObject jsonObject = new JSONObject(txResult);
                    if (!jsonObject.isNull(BLOCK_COUNT)) {
                        apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                    }
                    int txCnt = jsonObject.getInt(TX_CNT);
                    List<Tx> transactions = TransactionsUtil.getTransactionsFromBither(
                            jsonObject, storeBlockHeight);
                    transactions = AddressManager.getInstance().compressTxsForHDAccount(transactions);
                    Collections.sort(transactions, new ComparatorTx());
                    AddressManager.getInstance().getHDAccountHot().initTxs(transactions);
                    txSum = txSum + transactions.size();
                    needGetTxs = transactions.size() > 0;
                    page++;
                }
                */
                if (apiBlockCount < storeBlockHeight && storeBlockHeight - apiBlockCount < 100) {
                    BlockChain.getInstance().rollbackBlock(apiBlockCount);
                }

                log.info("hd address did sync {} tx, path {} ,index {}, {}", txSum, pathType, addressIndex, hdAccountAddress.getAddress());
                hdAccountAddress.setSyncedComplete(true);
                AddressManager.getInstance().getHDAccountHot().updateSyncComplete(hdAccountAddress);

                if (txSum > 0) {
                    if (pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                        AddressManager.getInstance().getHDAccountHot().updateIssuedExternalIndex(addressIndex);
                    } else {
                        AddressManager.getInstance().getHDAccountHot().updateIssuedInternalIndex(addressIndex);
                    }
                    AddressManager.getInstance().getHDAccountHot().supplyEnoughKeys(false);
//                    hasTx = true;
                    unusedAddressCnt = 0;
                } else {
//                    hasTx = false;
                    unusedAddressCnt += 1;
                }
                addressIndex++;
            }
            AbstractDb.hdAccountAddressProvider.updateSyncedForIndex(hdSeedId, pathType, addressIndex - 1);
        }
    }

    private static void getTxForDesktopHDM(DesktopHDMKeychain desktopHDMKeychain, final int webType) throws Exception {
        for (AbstractHD.PathType pathType : AbstractHD.PathType.values()) {
            DesktopHDMAddress desktopHDMAddress;
            boolean hasTx = true;
            int addressIndex = 0;
            while (hasTx) {
                Block storedBlock = BlockChain.getInstance().getLastBlock();
                int storeBlockHeight = storedBlock.getBlockNo();
                desktopHDMAddress = AbstractDb.desktopTxProvider.addressForPath(desktopHDMKeychain,
                        pathType, addressIndex);
                if (desktopHDMAddress == null) {
                    hasTx = false;
                    log.warn("AccountAddress", "address is null path {} ,index {}", pathType, addressIndex);
                    continue;
                }
                if (desktopHDMAddress.isSyncComplete()) {
                    addressIndex++;
                    continue;
                }
                int apiBlockCount = 0;
                int txSum = 0;
                boolean needGetTxs = true;
                int page = 1;
                // TODO
                List<Tx> transactions;

                while (needGetTxs) {
                    // TODO: get data from bither.net else from blockchain.info
                    if (webType == 0) {
                        BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                                desktopHDMAddress.getAddress(), page);
                        bitherMytransactionsApi.handleHttpGet();
                        String txResult = bitherMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);

                        if (!jsonObject.isNull(BLOCK_COUNT)) {
                            apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                        }
                        int txCnt = jsonObject.getInt(TX_CNT);
                        transactions = TransactionsUtil.getTransactionsFromBither(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForDesktopHDM(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        desktopHDMKeychain.initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = transactions.size() > 0;
                        page++;

                    }else {
                        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi(desktopHDMAddress.getAddress());
                        blockChainMytransactionsApi.handleHttpGet();
                        String txResult = blockChainMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);
                        // TODO: get the latest block number from blockChain.info
                        JSONObject jsonObjectBlockChain = getLatestBlockNumberFromBlockchain();
                        if (!jsonObjectBlockChain.isNull(BLOCK_CHAIN_HEIGHT)) {
                            apiBlockCount = jsonObjectBlockChain.getInt(BLOCK_CHAIN_HEIGHT);
                        }
                        int txCnt = jsonObject.getInt(BLOCK_CHAIN_CNT);
                        // TODO: get transactions from blockChain.info
                        transactions = TransactionsUtil.getTransactionsFromBlockChain(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForDesktopHDM(transactions);

                        Collections.sort(transactions, new ComparatorTx());
                        // address.initTxs(transactions);
                        desktopHDMKeychain.initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = false;

                    }
                }
                /*
                while (needGetTxs) {
                    BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                            desktopHDMAddress.getAddress(), page, flag);
                    bitherMytransactionsApi.handleHttpGet();
                    String txResult = bitherMytransactionsApi.getResult();
                    JSONObject jsonObject = new JSONObject(txResult);
                    if (!jsonObject.isNull(BLOCK_COUNT)) {
                        apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                    }
                    int txCnt = jsonObject.getInt(TX_CNT);
                    List<Tx> transactions = TransactionsUtil.getTransactionsFromBither(
                            jsonObject, storeBlockHeight);
                    transactions = AddressManager.getInstance().compressTxsForDesktopHDM(transactions);
                    Collections.sort(transactions, new ComparatorTx());
                    desktopHDMKeychain.initTxs(transactions);
                    txSum = txSum + transactions.size();
                    needGetTxs = transactions.size() > 0;
                    page++;
                }
                */
                if (apiBlockCount < storeBlockHeight && storeBlockHeight - apiBlockCount < 100) {
                    BlockChain.getInstance().rollbackBlock(apiBlockCount);
                }

                desktopHDMAddress.setSyncComplete(true);
                desktopHDMKeychain.updateSyncComplete(desktopHDMAddress);

                if (txSum > 0) {
                    if (pathType == AbstractHD.PathType.EXTERNAL_ROOT_PATH) {
                        desktopHDMKeychain.updateIssuedExternalIndex(addressIndex);
                    } else {
                        desktopHDMKeychain.updateIssuedInternalIndex(addressIndex);
                    }
                    desktopHDMKeychain.supplyEnoughKeys(false);
                    hasTx = true;
                } else {
                    hasTx = false;
                    AbstractDb.desktopTxProvider.updateSyncdForIndex(pathType, addressIndex);
                }
            }
            addressIndex++;
        }


    }

    private static void getTxForAddress(final int webType) throws Exception {
        for (Address address : AddressManager.getInstance().getAllAddresses()) {
            Block storedBlock = BlockChain.getInstance().getLastBlock();
            int storeBlockHeight = storedBlock.getBlockNo();
            if (!address.isSyncComplete()) {
                int apiBlockCount = 0;
                int txSum = 0;
                boolean needGetTxs = true;
                int page = 1;
                // TODO
                List<Tx> transactions = new ArrayList<Tx>();

                while (needGetTxs) {

                    // TODO: get data from bither.net else from blockchain.info
                    if (webType == 0) {
                        BitherMytransactionsApi bitherMytransactionsApi = new BitherMytransactionsApi(
                                address.getAddress(), page);
                        bitherMytransactionsApi.handleHttpGet();
                        String txResult = bitherMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);

                        if (!jsonObject.isNull(BLOCK_COUNT)) {
                            apiBlockCount = jsonObject.getInt(BLOCK_COUNT);
                        }
                        int txCnt = jsonObject.getInt(TX_CNT);
                        transactions = TransactionsUtil.getTransactionsFromBither(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForApi(transactions, address);

                        Collections.sort(transactions, new ComparatorTx());
                        address.initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = transactions.size() > 0;
                        page++;

                    }else {
                        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi(address.getAddress());
                        blockChainMytransactionsApi.handleHttpGet();
                        String txResult = blockChainMytransactionsApi.getResult();
                        JSONObject jsonObject = new JSONObject(txResult);
                        // TODO: get the latest block number from blockChain.info
                        JSONObject jsonObjectBlockChain = getLatestBlockNumberFromBlockchain();
                        if (!jsonObjectBlockChain.isNull(BLOCK_CHAIN_HEIGHT)) {
                            apiBlockCount = jsonObjectBlockChain.getInt(BLOCK_CHAIN_HEIGHT);
                        }
                        int txCnt = jsonObject.getInt(BLOCK_CHAIN_CNT);
                        // TODO: get transactions from blockChain.info
                        transactions = TransactionsUtil.getTransactionsFromBlockChain(jsonObject, storeBlockHeight);
                        transactions = AddressManager.getInstance().compressTxsForApi(transactions, address);

                        Collections.sort(transactions, new ComparatorTx());
                        address.initTxs(transactions);
                        txSum = txSum + transactions.size();
                        needGetTxs = false;

                    }
                    /*
                    Collections.sort(transactions, new ComparatorTx());
                    address.initTxs(transactions);
                    txSum = txSum + transactions.size();
                    needGetTxs = transactions.size() > 0;
                    page++;
                    */
                }

                if (apiBlockCount < storeBlockHeight && storeBlockHeight - apiBlockCount < 100) {
                    BlockChain.getInstance().rollbackBlock(apiBlockCount);
                }
                address.setSyncComplete(true);
                if (address instanceof HDMAddress) {
                    HDMAddress hdmAddress = (HDMAddress) address;
                    hdmAddress.
                            updateSyncComplete();
                } else {
                    address.updateSyncComplete();
                }
            }
        }

    }

    // TODO: get the latest block info of JSON format from blockChain.info
    private static JSONObject getLatestBlockNumberFromBlockchain() throws Exception {
        BlockChainMytransactionsApi blockChainMytransactionsApi = new BlockChainMytransactionsApi();
        blockChainMytransactionsApi.handleHttpGet();
        String txResultBlockChain = blockChainMytransactionsApi.getResult();
        return new JSONObject(txResultBlockChain);

    }

}
