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

package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherBCUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;
import net.bither.bitherj.utils.Utils;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.HttpHostConnectException;
import org.json.JSONArray;
import org.json.JSONObject;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class DownloadSpvApi extends HttpGetResponse<Block> {

    public static Block getOneSpvBlock() throws Exception {
        return getOneSpvBlock(BitherBCUrl.getInstance().getDns(), 1);
    }

    private DownloadSpvApi() {
        String url = Utils.format(BitherUrl.BITHER_GET_ONE_SPVBLOCK_API, BitherBCUrl.getInstance().getDns());
        setUrl(url);
    }

    private static Block getOneSpvBlock(String firstBcDns, int requestCount) throws Exception {
        Block block = null;
        try {
            DownloadSpvApi downloadSpvApi = new DownloadSpvApi();
            downloadSpvApi.handleHttpGet();
            block = downloadSpvApi.getResult();
            return block;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex instanceof ConnectTimeoutException || ex instanceof HttpHostConnectException) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return getOneSpvBlock(firstBcDns, requestCount);
                }
                throw ex;
            } else {
                if (requestCount > TIMEOUT_REREQUEST_CNT) {
                    throw ex;
                }
                try {
                    Thread.sleep(TIMEOUT_REREQUEST_DELAY * requestCount);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                return getOneSpvBlock(firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        this.result = BlockUtil.formatStoredBlock(jsonObject);
    }
}
