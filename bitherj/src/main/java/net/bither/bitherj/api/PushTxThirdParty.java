/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpsPostResponse;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Created by songchenwen on 16/6/12.
 */
public class PushTxThirdParty {
    private static final int ThreadCount = 5;

    private static PushTxThirdParty instance;
    private static Object singletonLock = new Object();
    private final ExecutorService executor = Executors.newFixedThreadPool(ThreadCount);

    private static final Logger log = LoggerFactory.getLogger(PushTxThirdParty.class);

    private PushTxThirdParty() {
    }

    public static PushTxThirdParty getInstance() {
        synchronized (singletonLock) {
            if (instance == null) {
                instance = new PushTxThirdParty();
            }
        }
        return instance;
    }

    public void pushTx(Tx tx) {
        String raw = Utils.bytesToHexString(tx.bitcoinSerialize());
        pushToBlockChainInfo(raw);
        pushToBtcCom(raw);
        pushToChainQuery(raw);
        pushToBlockr(raw);
        pushToBlockExplorer(raw);
    }

    private void pushToBlockChainInfo(String rawTx) {
        pushTo("https://blockchain.info/pushtx", "tx", rawTx, "blockchain.info");
    }

    private void pushToBtcCom(String rawTx) {
        pushTo("https://btc.com/api/v1/tx/publish", "hex", rawTx, "BTC.com");
    }

    private void pushToChainQuery(String rawTx) {
        pushTo("https://chainquery.com/bitcoin-api/sendrawtransaction", "transaction", rawTx,
                "ChainQuery.com");
    }

    private void pushToBlockr(String rawTx) {
        pushTo("https://blockr.io/api/v1/tx/push", "hex", rawTx, "blockr.io");
    }

    private void pushToBlockExplorer(String rawTx) {
        pushTo("https://blockexplorer.com/api/tx/send", "rawtx", rawTx, "BlockExplorer");
    }

    private void pushTo(final String url, final String key, final String rawTx, final String tag) {
        executor.execute(new Runnable() {
            public void run() {
                log.info("begin push tx to {}", tag);
                try {
                    new PushApi(url, key, rawTx).handleHttpPost();
                    log.info("push tx to {} success", tag);
                } catch (Exception e) {
                    log.info("push tx to {} failed {}", tag, e.getMessage());
                    e.printStackTrace();
                }
            }
        });
    }

    private static class PushApi extends HttpsPostResponse<String> {
        private String rawTx;
        private String key;

        PushApi(String url, String key, String rawTx) {
            this.key = key;
            this.rawTx = rawTx;
            setUrl(url);
        }

        @Override
        public Map<String, String> getParams() throws Exception {
            Map<String, String> params = new HashMap<String, String>();
            params.put(key, rawTx);
            return params;
        }

        @Override
        public void setResult(String response) throws Exception {
            result = response;
        }
    }
}
