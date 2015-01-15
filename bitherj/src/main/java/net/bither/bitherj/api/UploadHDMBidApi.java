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

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class UploadHDMBidApi extends HttpsPostResponse<Boolean> {

    private byte[] signature;
    private byte[] password;
    private String hotAddress;

    public UploadHDMBidApi(String address, String hotAddress, byte[] signature, byte[] password) {
        String url = Utils.format(BitherUrl.BITHER_HDM_PASSWORD, address);
        setUrl(url);
        this.signature = signature;
        this.password = password;
        this.hotAddress = hotAddress;

    }

    @Override
    public Map<String, String> getParams() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put(HttpSetting.PASSWORD, Utils.base64Encode(this.password));
        params.put(HttpSetting.SIGNATURE, Utils.base64Encode(this.signature));
        params.put(HttpSetting.HOT_ADDRESS, this.hotAddress);
        return params;
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = false;
        JSONObject json = new JSONObject(response);
        if (!json.isNull(HttpSetting.RESULT)) {
            this.result = Utils.compareString(json.getString(HttpSetting.RESULT)
                    , HttpSetting.STATUS_OK);
        }

    }
}
