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

package org.primer.primerj.api;

import org.primer.primerj.PrimerjSettings;
import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpGetResponse;
import org.primer.primerj.utils.Utils;

public class GetExchangeDepthApi extends HttpGetResponse<String> {


    public GetExchangeDepthApi(PrimerjSettings.MarketType marketType) {

        String url = Utils.format(PrimerUrl.BITHER_DEPTH_URL,
                PrimerjSettings.getMarketValue(marketType));
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
