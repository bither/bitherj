package org.primer.primerj.api;

import org.primer.primerj.api.http.HttpGetResponse;

/**
 * Created by Hzz on 2016/10/27.
 */

public class GetAdApi extends HttpGetResponse<String> {

    public GetAdApi() {
        String url = "https://github.com/bitpiedotcom/bitpiedotcom.github.com/raw/master/bither/bither_ad.json";
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
