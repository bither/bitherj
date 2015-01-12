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

import java.util.ArrayList;
import java.util.List;

public class CreateHDMAddressApi extends HttpPostResponse<List<byte[]>> {
    private byte[] password;
    private String pubHot;
    private String pubCold;
    private int start;
    private int end;

    public CreateHDMAddressApi(String address, List<HDMAddress.Pubs> pubsList, byte[] password) {
        this.password = password;
        String url = Utils.format(BitherUrl.BITHER_HDM_CREATE_ADDRESS, address);
        setUrl(url);
        pubHot = "";
        pubCold = "";
        start = Integer.MAX_VALUE;
        end = Integer.MIN_VALUE;
        for (HDMAddress.Pubs pubs : pubsList) {
            byte[] cold = new byte[pubs.cold.length + 1];
            cold[0] = (byte) (pubs.cold.length & 255);
            System.arraycopy(pubs.cold, 0, cold, 1, pubs.cold.length);
            pubCold = pubCold + Base64.encodeToString(cold, Base64.URL_SAFE);

            byte[] hot = new byte[pubs.hot.length + 1];
            hot[0] = (byte) (pubs.hot.length & 255);
            System.arraycopy(pubs.hot, 0, hot, 1, pubs.hot.length);
            pubHot = pubHot + Base64.encodeToString(pubs.hot, Base64.URL_SAFE);
            if (start > pubs.index) {
                start = pubs.index;
            }
            if (end < pubs.index) {
                end = pubs.index;
            }
        }
    }

    @Override
    public HttpEntity getHttpEntity() throws Exception {
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair(HttpSetting.PASSWORD, Base64.encodeToString(this.password, Base64.URL_SAFE)));
        params.add(new BasicNameValuePair(HttpSetting.PUB_HOT, this.pubHot));
        params.add(new BasicNameValuePair(HttpSetting.PUB_COLD, this.pubCold));
        params.add(new BasicNameValuePair(HttpSetting.START, Integer.toString(this.start)));
        params.add(new BasicNameValuePair(HttpSetting.END, Integer.toString(this.end)));
        return new UrlEncodedFormEntity(params, HTTP.UTF_8);
    }

    @Override
    public void setResult(String response) throws Exception {
        byte[] servicePubs = Base64.decode(response, Base64.URL_SAFE);
        int index = 0;
        List<byte[]> pubsList = new ArrayList<byte[]>();
        while (index < servicePubs.length) {
            byte charLen = servicePubs[index];
            pubsList.add(Utils.copyOfRange(servicePubs, index + 1, charLen));
            index = index + charLen;
        }
        this.result = pubsList;
    }
}
