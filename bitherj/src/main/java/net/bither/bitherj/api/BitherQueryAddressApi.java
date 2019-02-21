package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import java.net.SocketTimeoutException;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherQueryAddressApi extends HttpGetResponse<String> {

    public BitherQueryAddressApi(String addresses) {
        String url = Utils.format(BitherUrl.BITHER_Q_ADDRESSES,
                addresses);
        setUrl(url);
    }

    public static JSONObject queryAddress(String addressesStr) throws Exception {
        return queryAddress(addressesStr, 1);
    }

    private static JSONObject queryAddress(String addressesStr, int requestCount) throws Exception {
        try {
            BitherQueryAddressApi bitherQueryAddressApi = new BitherQueryAddressApi(addressesStr);
            bitherQueryAddressApi.handleHttpGet();
            String unspentResult = bitherQueryAddressApi.getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            return jsonObject;
        } catch (SocketTimeoutException ex) {
            ex.printStackTrace();
            if (requestCount > TIMEOUT_REREQUEST_CNT) {
                throw ex;
            }
            try {
                Thread.sleep(TIMEOUT_REREQUEST_DELAY * requestCount);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            return queryAddress(addressesStr, requestCount + 1);
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}

