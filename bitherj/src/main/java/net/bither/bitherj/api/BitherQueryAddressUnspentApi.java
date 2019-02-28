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

public class BitherQueryAddressUnspentApi extends HttpGetResponse<String> {

    public static JSONObject queryAddressUnspent(String address, int page) throws Exception {
        return queryAddress(address, page, BitherBCUrl.getInstance().getDns(),1);
    }

    private BitherQueryAddressUnspentApi(String address, int page) {
        String url = Utils.format(BitherUrl.BITHER_Q_ADDRESS_UNSPENT, BitherBCUrl.getInstance().getDns(), address);
        url = url + "?page=" + page;
        setUrl(url);
    }

    private static JSONObject queryAddress(String address, int page, String firstBcDns, int requestCount) throws Exception {
        try {
            BitherQueryAddressUnspentApi bitherQueryAddressUnspentApi = new BitherQueryAddressUnspentApi(address, page);
            bitherQueryAddressUnspentApi.handleHttpGet();
            String unspentResult = bitherQueryAddressUnspentApi.getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex instanceof ConnectTimeoutException || ex instanceof HttpHostConnectException) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return queryAddress(address, page, firstBcDns, requestCount);
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
                return queryAddress(address, page, firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}

