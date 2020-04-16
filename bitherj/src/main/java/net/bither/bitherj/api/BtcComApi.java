package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

public abstract class BtcComApi<T> extends HttpsGetResponse<T> {

    @Override
    public void setResult(String response) throws Exception {
        if (Utils.isEmpty(response)) {
            throw new Exception("response is null");
        }
        JSONObject jsonObject = new JSONObject(response);
        if (jsonObject.getInt("err_no") != 0) {
            String errMsg = null;
            if (jsonObject.has("err_msg")) {
                errMsg = jsonObject.getString("err_msg");
            }
            if (Utils.isEmpty(errMsg)) {
                errMsg = "btc com response error";
            }
            throw new Exception(errMsg);
        }
        if (!jsonObject.has("data")) {
            throw new Exception("btc com response error");
        }
        JSONObject data = jsonObject.getJSONObject("data");
        if (data == null) {
            throw new Exception("btc com response error");
        }
        setResult(data);
    }

    public abstract void setResult(JSONObject response) throws Exception;

}
