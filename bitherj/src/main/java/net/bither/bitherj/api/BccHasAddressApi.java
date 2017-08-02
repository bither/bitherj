package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

/**
 * Created by ltq on 2017/7/27.
 */

public class BccHasAddressApi extends HttpGetResponse<String>{

    public BccHasAddressApi(String address) {
        String url = Utils.format("https://bitpie.getcai.com/api/v1/bcc/has/address/%s",address);
        setUrl(url);
    }

    public void setResult(String response) throws Exception {
        this.result = response;
    }
}
