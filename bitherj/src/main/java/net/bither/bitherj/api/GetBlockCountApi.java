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
import net.bither.bitherj.utils.Utils;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class GetBlockCountApi extends HttpGetResponse<Long> {

    public static long getBlockCount() throws Exception {
        return getBlockCount(BitherBCUrl.getInstance().getDns(), 1);
    }

    private GetBlockCountApi() {
        String url = Utils.format(BitherUrl.BITHER_Q_GETBLOCK_COUNT_URL, BitherBCUrl.getInstance().getDns());
        setUrl(url);
    }

    private static long getBlockCount(String firstBcDns, int requestCount) throws Exception {
        try {
            GetBlockCountApi getBlockCountApi = new GetBlockCountApi();
            getBlockCountApi.handleHttpGet();
            long count = getBlockCountApi.getResult();
            return count;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (BitherBCUrl.isChangeDns(ex)) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return getBlockCount(firstBcDns, requestCount);
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
                return getBlockCount(firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = Long.valueOf(response);

    }

}
