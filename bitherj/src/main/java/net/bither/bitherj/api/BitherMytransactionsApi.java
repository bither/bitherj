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

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;


public class BitherMytransactionsApi extends HttpGetResponse<String> {
    public static final int bitherWebType = 0;
    public static final int blockChainWebType = 1;

    public BitherMytransactionsApi(String address) {
        this(address, 1);
    }

    public BitherMytransactionsApi(String address, int page) {
        String url = Utils.format(BitherUrl.BITHER_Q_MYTRANSACTIONS,
                address);
        if (page > 1) {
            url = url + "/" + page;
        }
        setUrl(url);
    }

    /**
     * Improve this method
     * Get data from 1. bither.net
     *               2. blockchain.info
     */
    public BitherMytransactionsApi(String address, int page, int flag) {
        switch (flag) {
            case bitherWebType:{
                String url = Utils.format(BitherUrl.BITHER_Q_MYTRANSACTIONS, address);
                if (page > 0) {
                    url = url + "/p/" + page;
                }
                setUrl(url);
                break;
            }
            case blockChainWebType: {
                String url = Utils.format(BitherUrl.BITHER_BC_GET_BY_ADDRESS, address);
                setUrl(url);
                break;
            }
            default: {
                break;
            }
        }
    }

    public BitherMytransactionsApi() {
        setUrl(BitherUrl.BITHER_BC_LATEST_BLOCK);
    }

    public BitherMytransactionsApi(int txIndex) {
        // String url = Utils.format(BitherUrl.BITHER_BC_TX_INDEX, txIndex);
        String url = String.format(BitherUrl.BITHER_BC_TX_INDEX, txIndex);
        setUrl(url);
    }

    /**
     *  end
     */

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
