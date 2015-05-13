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
import net.bither.bitherj.api.http.HttpSetting;
import net.bither.bitherj.api.http.HttpsPostResponse;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.utils.Base64;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CreateHDMAddressApi extends HttpsPostResponse<List<byte[]>> {
    private byte[] password;
    private String pubHot;
    private String pubCold;
    private int start;
    private int end;


    private static final Logger log = LoggerFactory.getLogger(CreateHDMAddressApi.class);

    public CreateHDMAddressApi(String address
            , List<HDMAddress.Pubs> pubsList, byte[] password) {
        this.password = password;
        String url = Utils.format(BitherUrl.BITHER_HDM_CREATE_ADDRESS, address);
        setUrl(url);
        pubHot = "";
        pubCold = "";
        start = Integer.MAX_VALUE;
        end = Integer.MIN_VALUE;
        int hotLen = 0;
        int coldLen = 0;
        for (HDMAddress.Pubs pubs : pubsList) {
            hotLen += 1 + pubs.hot.length;
            coldLen += 1 + pubs.cold.length;
        }
        byte[] hot = new byte[hotLen];
        byte[] cold = new byte[coldLen];
        int hotIndex = 0;
        int coldIndex = 0;
        for (HDMAddress.Pubs pubs : pubsList) {
            hot[hotIndex] = (byte) pubs.hot.length;
            cold[coldIndex] = (byte) pubs.cold.length;
            hotIndex += 1;
            coldIndex += 1;

            System.arraycopy(pubs.hot, 0, hot, hotIndex, pubs.hot.length);
            System.arraycopy(pubs.cold, 0, cold, coldIndex, pubs.cold.length);
            hotIndex += pubs.hot.length;
            coldIndex += pubs.cold.length;

            if (start > pubs.index) {
                start = pubs.index;
            }
            if (end < pubs.index) {
                end = pubs.index;
            }
        }
        pubHot = pubHot + Base64.encodeToString(hot, Base64.DEFAULT);
        pubCold = pubCold + Base64.encodeToString(cold, Base64.DEFAULT);


    }

    @Override
    public Map<String, String> getParams() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put(HttpSetting.PASSWORD, Utils.base64Encode(this.password));
        params.put(HttpSetting.PUB_HOT, this.pubHot);
        params.put(HttpSetting.PUB_COLD, this.pubCold);
        params.put(HttpSetting.START, Integer.toString(this.start));
        params.put(HttpSetting.END, Integer.toString(this.end));
        return params;
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = Utils.decodeServiceResult(response);
    }
}
