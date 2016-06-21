package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;
import net.bither.bitherj.utils.Utils;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONString;


public class BlockChainDownloadSpvApi extends HttpsGetResponse<Block> {
    public BlockChainDownloadSpvApi (int height){
        String url = Utils.format(BitherUrl.BLOCKCHAIN_INFO_GET_SPVBLOCK_API, height);
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        JSONArray jsonArray = jsonObject.getJSONArray("blocks");
        JSONObject jsonObject1 = (JSONObject) jsonArray.get(0);
        this.result = BlockUtil.formatStoreBlockFromBlockChainInfo(jsonObject1);
    }
}
