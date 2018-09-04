package org.primer.primerj.api;

import org.primer.primerj.api.http.HttpGetResponse;
import org.primer.primerj.utils.Utils;

/**
 * Created by denmark on 2018/1/4.
 */

public class GetBcdBlockHashApi extends HttpGetResponse<String> {

    public GetBcdBlockHashApi() {
        String url = Utils.format("https://bitpie.getcai.com/api/v1/bcd/current/block/hash");
        setUrl(url);
    }

    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
