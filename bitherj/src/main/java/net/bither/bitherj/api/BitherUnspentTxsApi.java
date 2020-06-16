package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherAndBtcComUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BTC_COM_URL;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherUnspentTxsApi extends HttpGetResponse<String> {

    public static JSONObject getUnspentTxs(String txHashs) throws Exception {
        return getUnspentTxs(BitherAndBtcComUrl.getInstance().getDns(), txHashs, 1);
    }

    private BitherUnspentTxsApi(String txHashs) {
        String dns = BitherAndBtcComUrl.getInstance().getDns();
        String url = Utils.format(dns.equals(BTC_COM_URL) ? BitherUrl.BTC_COM_Q_ADDRESS_UNSPENT_TXS : BitherUrl.BITHER_Q_ADDRESS_UNSPENT_TXS, dns, txHashs);
        url = url + "?verbose=3";
        setUrl(url);
    }

    private static JSONObject getUnspentTxs(String firstBcDns, String txHashs, int requestCount) throws Exception {
        try {
            BitherUnspentTxsApi bitherUnspentTxsApi = new BitherUnspentTxsApi(txHashs);
            bitherUnspentTxsApi.handleHttpGet();
            String txsResult = bitherUnspentTxsApi.getResult();
            JSONObject jsonObject = new JSONObject(txsResult);
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (BitherAndBtcComUrl.isChangeDns(ex)) {
                String nextBcDns = BitherAndBtcComUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return getUnspentTxs(firstBcDns, txHashs, 1);
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
                return getUnspentTxs(firstBcDns, txHashs, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}