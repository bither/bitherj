package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherBCUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.HttpHostConnectException;
import org.json.JSONObject;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherQueryAddressApi extends HttpGetResponse<String> {

    public static JSONObject queryAddress(String addressesStr) throws Exception {
        return queryAddress(addressesStr, BitherBCUrl.getInstance().getDns(), 1);
    }

    private BitherQueryAddressApi(String addresses) {
        String url = Utils.format(BitherUrl.BITHER_Q_ADDRESSES, BitherBCUrl.getInstance().getDns(), addresses);
        setUrl(url);
    }

    private static JSONObject queryAddress(String addressesStr, String firstBcDns, int requestCount) throws Exception {
        try {
            BitherQueryAddressApi bitherQueryAddressApi = new BitherQueryAddressApi(addressesStr);
            bitherQueryAddressApi.handleHttpGet();
            String unspentResult = bitherQueryAddressApi.getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex instanceof ConnectTimeoutException || ex instanceof HttpHostConnectException) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return queryAddress(addressesStr, firstBcDns, requestCount);
                }
                throw ex;
            } else {
                if (requestCount > TIMEOUT_REREQUEST_CNT) {
                    throw ex;
                }
                try {
                    Thread.sleep(TIMEOUT_REREQUEST_DELAY * requestCount);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                return queryAddress(addressesStr, firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}

