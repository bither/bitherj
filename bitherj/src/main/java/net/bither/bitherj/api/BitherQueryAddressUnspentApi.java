package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import java.net.SocketTimeoutException;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherQueryAddressUnspentApi extends HttpGetResponse<String> {

    public BitherQueryAddressUnspentApi(String address, int page) {
        String url = Utils.format(BitherUrl.BITHER_Q_ADDRESS_UNSPENT,
                address);
        url = url + "?page=" + page;
        setUrl(url);
    }

    public static JSONObject queryAddressUnspent(String address, int page) throws Exception {
        return queryAddress(address, page, 1);
    }

    private static JSONObject queryAddress(String address, int page, int requestCount) throws Exception {
        try {
            BitherQueryAddressUnspentApi bitherQueryAddressUnspentApi = new BitherQueryAddressUnspentApi(address, page);
            bitherQueryAddressUnspentApi.handleHttpGet();
            String unspentResult = bitherQueryAddressUnspentApi.getResult();
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
            return queryAddress(address, page,requestCount + 1);
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}

