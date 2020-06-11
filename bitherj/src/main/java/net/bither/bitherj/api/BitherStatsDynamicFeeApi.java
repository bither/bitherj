package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherBCUrl;
import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;

public class BitherStatsDynamicFeeApi extends HttpGetResponse<String> {

    public static Long queryStatsDynamicFee() throws Exception {
        return queryStatsDynamicFee(BitherBCUrl.getInstance().getDns(),1);
    }

    private BitherStatsDynamicFeeApi() {
        String url = Utils.format(BitherUrl.BITHER_Q_STATS_DYNAMIC_FEE, BitherBCUrl.getInstance().getDns());
        setUrl(url);
    }

    private static Long queryStatsDynamicFee(String firstBcDns, int requestCount) throws Exception {
        try {
            BitherStatsDynamicFeeApi bitherStatsDynamicFeeApi = new BitherStatsDynamicFeeApi();
            bitherStatsDynamicFeeApi.handleHttpGet();
            String txResult = bitherStatsDynamicFeeApi.getResult();
            JSONObject jsonObject = new JSONObject(txResult);
            if (jsonObject != null && jsonObject.has("fee_base")) {
                return jsonObject.getLong("fee_base");

            }
            return null;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (BitherBCUrl.isChangeDns(ex)) {
                String nextBcDns = BitherBCUrl.getNextBcDns(firstBcDns);
                if (!Utils.isEmpty(nextBcDns)) {
                    return queryStatsDynamicFee(firstBcDns, requestCount);
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
                return queryStatsDynamicFee(firstBcDns, requestCount + 1);
            }
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
