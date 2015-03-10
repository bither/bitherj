package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpSetting;
import net.bither.bitherj.api.http.HttpsPostResponse;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RecoveryHDMApi extends HttpsPostResponse<List<HDMAddress.Pubs>> {
    private byte[] signature;
    private byte[] password;

    public RecoveryHDMApi(String address, byte[] signature, byte[] password) {
        String url = Utils.format(BitherUrl.BITHER_REVOCERY_HDM, address);
        setUrl(url);
        this.signature = signature;
        this.password = password;


    }

    @Override
    public Map<String, String> getParams() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put(HttpSetting.PASSWORD, Utils.base64Encode(this.password));
        params.put(HttpSetting.SIGNATURE, Utils.base64Encode(this.signature));
        return params;
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject json = new JSONObject(response);
        this.result = new ArrayList<HDMAddress.Pubs>();
        List<byte[]> pubHots = new ArrayList<byte[]>();
        List<byte[]> pubColds = new ArrayList<byte[]>();
        List<byte[]> pubService = new ArrayList<byte[]>();
        if (!json.isNull(HttpSetting.PUB_HOT)) {
            String pubHotString = json.getString(HttpSetting.PUB_HOT);
            pubHots = Utils.decodeServiceResult(pubHotString);
        }
        if (!json.isNull(HttpSetting.PUB_COLD)) {
            String pubColdString = json.getString(HttpSetting.PUB_COLD);
            pubColds = Utils.decodeServiceResult(pubColdString);
        }
        if (!json.isNull(HttpSetting.PUB_SERVER)) {
            String pubServiceString = json.getString(HttpSetting.PUB_SERVER);
            pubService = Utils.decodeServiceResult(pubServiceString);
        }

        for (int i = 0; i < pubHots.size(); i++) {
            HDMAddress.Pubs pubs = new HDMAddress.Pubs(pubHots.get(i), pubColds.get(i), pubService.get(i), i);
            this.result.add(pubs);
        }

    }
}
