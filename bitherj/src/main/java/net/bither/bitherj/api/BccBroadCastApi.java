package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpsPostResponse;
import net.bither.bitherj.utils.Utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by ltq on 2017/7/27.
 */

public class BccBroadCastApi extends HttpsPostResponse<String> {

    String rawTx;

    public BccBroadCastApi(String rawTx) {
        String url = Utils.format("https://bitpie.getcai.com/api/v1/bcc/broadcast");
        setUrl(url);
        this.rawTx = rawTx;
    }

    public void setResult(String response) throws Exception {
        this.result = response;
    }

    @Override
    public Map<String, String> getParams() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("raw_tx", rawTx);
        return params;
    }
}
