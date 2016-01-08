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
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;
import net.bither.bitherj.utils.Utils;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.json.JSONArray;
import org.json.JSONObject;

public class DownloadSpvApi extends HttpGetResponse<Block> {

    public DownloadSpvApi() {
        setUrl(BitherUrl.BITHER_GET_ONE_SPVBLOCK_API);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        this.result = BlockUtil.formatStoredBlock(jsonObject);
    }
}
