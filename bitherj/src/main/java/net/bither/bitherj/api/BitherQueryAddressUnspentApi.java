package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherAndBtcComUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BTC_COM_URL;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherQueryAddressUnspentApi extends HttpGetResponse<String> {

    public static JSONObject queryAddressUnspent(String address, int page) throws Exception {
        return queryAddress(BitherAndBtcComUrl.getInstance().getDns(), address, page, 1);
    }

    private BitherQueryAddressUnspentApi(String address, int page) {
        String dns = BitherAndBtcComUrl.getInstance().getDns();
        String url = Utils.format(dns.equals(BTC_COM_URL) ? BitherUrl.BTC_COM_Q_ADDRESS_UNSPENT : BitherUrl.BITHER_Q_ADDRESS_UNSPENT, dns, address);
        url = url + "?page=" + page;
        setUrl(url);
    }

    private static JSONObject queryAddress(String firstBcDns, String address, int page, int requestCount) throws Exception {
        try {
            BitherQueryAddressUnspentApi bitherQueryAddressUnspentApi = new BitherQueryAddressUnspentApi(address, page);
            bitherQueryAddressUnspentApi.handleHttpGet();
            String unspentResult = bitherQueryAddressUnspentApi.getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (requestCount > TIMEOUT_REREQUEST_CNT) {
                String nextBcDns = BitherAndBtcComUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return queryAddress(firstBcDns, address, page, 1);
                }
                throw ex;
            }
            try {
                Thread.sleep(TIMEOUT_REREQUEST_DELAY);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            return queryAddress(firstBcDns, address, page, requestCount + 1);
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}

