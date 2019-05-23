package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

/**
 * Created by ltq on 2017/9/18.
 */

public class UnspentOutputsApi extends HttpGetResponse<String> {

        public UnspentOutputsApi(String address) {
            String url = Utils.format("http://blockdozer.com/insight-api/addr/%s/utxo",address);
            setUrl(url);
        }

        public void setResult(String response) throws Exception {
            this.result = response;
        }
}
