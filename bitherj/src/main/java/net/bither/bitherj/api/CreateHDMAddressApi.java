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
import net.bither.bitherj.api.http.HttpPostResponse;
import net.bither.bitherj.api.http.HttpSetting;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.utils.Base64;
import net.bither.bitherj.utils.Utils;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class CreateHDMAddressApi extends HttpPostResponse<List<byte[]>> {
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
        setIsHttps(true);

    }

    @Override
    public HttpEntity getHttpEntity() throws Exception {
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair(HttpSetting.PASSWORD, Utils.base64Encode(this.password)));
        params.add(new BasicNameValuePair(HttpSetting.PUB_HOT, this.pubHot));
        params.add(new BasicNameValuePair(HttpSetting.PUB_COLD, this.pubCold));
        params.add(new BasicNameValuePair(HttpSetting.START, Integer.toString(this.start)));
        params.add(new BasicNameValuePair(HttpSetting.END, Integer.toString(this.end)));

        return new UrlEncodedFormEntity(params, HTTP.UTF_8);
    }

    @Override
    public void setResult(String response) throws Exception {
        log.info("CreateHDMAddressApi:" + response);
        this.result = Utils.decodeServiceResult(response);
    }
}
