package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

import org.json.JSONArray;
import org.json.JSONObject;

public class MempoolSpaceDownloadSpvApi extends HttpsGetResponse<Block> {

    public MempoolSpaceDownloadSpvApi(int height) {
        setUrl(String.format(BitherUrl.MEMPOOL_SPACE_GET_SPVBLOCK_API, height));
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONArray jsonArray = new JSONArray(response);
        JSONObject jsonObject1 = (JSONObject) jsonArray.get(0);
        this.result = BlockUtil.formatStoreBlockFromMempoolSpaceInfo(jsonObject1);
    }

}