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
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignatureHDMApi extends HttpsPostResponse<List<byte[]>> {
    private byte[] password;
    private List<byte[]> unSigns;
    private static final Logger log = LoggerFactory.getLogger(SignatureHDMApi.class);

    public SignatureHDMApi(String address, int index, byte[] password, List<byte[]> unSigns) {
        String url = Utils.format(BitherUrl.BITHER_HDM_SIGNATURE, address, index);
        setUrl(url);
        this.password = password;
        this.unSigns = unSigns;

    }

    @Override
    public Map<String, String> getParams() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put(HttpSetting.PASSWORD, Utils.base64Encode(password));
        params.put(HttpSetting.UNSIGN, Utils.encodeBytesForService(unSigns));
        return params;
    }


    @Override
    public void setResult(String response) throws Exception {
        log.info("SignatureHDMApi:" + response);
        this.result = Utils.decodeServiceResult(response);
    }
}