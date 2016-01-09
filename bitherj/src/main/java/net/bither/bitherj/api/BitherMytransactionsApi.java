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
        if (page > 0) {
            url = url + "/p/" + page;
        }
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
