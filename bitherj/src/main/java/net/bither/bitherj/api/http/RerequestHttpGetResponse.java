package net.bither.bitherj.api.http;

import org.json.JSONObject;

import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_CNT;
import static net.bither.bitherj.api.http.HttpSetting.TIMEOUT_REREQUEST_DELAY;


public abstract class RerequestHttpGetResponse extends HttpGetResponse<String> {

    protected int requestCount = 1;

    protected abstract JSONObject query() throws Exception;

    protected JSONObject reRequest(Exception ex) throws Exception {
        if (requestCount > TIMEOUT_REREQUEST_CNT) {
            throw ex;
        }
        try {
            Thread.sleep(TIMEOUT_REREQUEST_DELAY);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        requestCount = requestCount + 1;
        return query();
    }

    protected boolean blockchairDataIsError(JSONObject jsonObject) throws Exception {
        if (jsonObject == null || !jsonObject.has("context")) {
            return true;
        }
        JSONObject contextJson = jsonObject.getJSONObject("context");
        if (contextJson == null || !contextJson.has("code")) {
            return true;
        }
        int code = contextJson.getInt("code");
        switch (code) {
            case 200:
                return false;
            case 402:
            case 429:
            case 435:
            case 436:
            case 437:
            case 430:
            case 434:
            case 503:
                throw new Exception("error");
            default:
                return true;
        }
    }

    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }

}
