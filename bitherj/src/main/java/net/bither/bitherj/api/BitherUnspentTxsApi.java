package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherBCUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherUnspentTxsApi extends HttpGetResponse<String> {

    public static JSONObject getUnspentTxs(String txHashs) throws Exception {
        return getUnspentTxs(txHashs, BitherBCUrl.getInstance().getDns(), 1);
    }

    private BitherUnspentTxsApi(String txHashs) {
        String url = Utils.format(BitherUrl.BITHER_Q_ADDRESS_UNSPENT_TXS, BitherBCUrl.getInstance().getDns(), txHashs);
        url = url + "?verbose=3";
        setUrl(url);
    }

    private static JSONObject getUnspentTxs(String txHashs, String firstBcDns, int requestCount) throws Exception {
        try {
            BitherUnspentTxsApi bitherUnspentTxsApi = new BitherUnspentTxsApi(txHashs);
            bitherUnspentTxsApi.handleHttpGet();
            String txsResult = bitherUnspentTxsApi.getResult();
            JSONObject jsonObject = new JSONObject(txsResult);
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (BitherBCUrl.isChangeDns(ex)) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return getUnspentTxs(txHashs, firstBcDns, requestCount);
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
                return getUnspentTxs(txHashs, firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}