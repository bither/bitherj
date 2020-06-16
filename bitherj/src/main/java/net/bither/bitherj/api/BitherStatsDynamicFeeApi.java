package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC;

public class BitherStatsDynamicFeeApi extends HttpGetResponse<String> {

    private BitherStatsDynamicFeeApi() {
        String url = Utils.format(BitherUrl.BITHER_Q_STATS_DYNAMIC_FEE, BITHER_BC);
        setUrl(url);
    }

    public static Long queryStatsDynamicFee() throws Exception {
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
            throw ex;
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
