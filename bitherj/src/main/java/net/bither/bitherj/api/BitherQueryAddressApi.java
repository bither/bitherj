package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherAndBtcComUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BTC_COM_URL;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherQueryAddressApi extends HttpGetResponse<String> {

    public static JSONObject queryAddress(String addressesStr) throws Exception {
        return queryAddress(addressesStr, BitherAndBtcComUrl.getInstance().getDns(), 1);
    }

    private BitherQueryAddressApi(String addresses) {
        String dns = BitherAndBtcComUrl.getInstance().getDns();
        String url = Utils.format(dns.equals(BTC_COM_URL) ? BitherUrl.BTC_COM_Q_ADDRESSES : BitherUrl.BITHER_Q_ADDRESSES, dns, addresses);
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
            if (BitherAndBtcComUrl.isChangeDns(ex)) {
                String nextBcDns = BitherAndBtcComUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return queryAddress(addressesStr, firstBcDns, 1);
                }
                throw ex;
            } else {
                if (requestCount > TIMEOUT_REREQUEST_CNT) {
                    throw ex;
                }
                try {
                    Thread.sleep(TIMEOUT_REREQUEST_DELAY);
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

