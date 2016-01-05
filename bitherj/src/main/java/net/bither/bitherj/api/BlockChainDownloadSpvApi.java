package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;
import net.bither.bitherj.utils.Utils;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONString;


public class BlockChainDownloadSpvApi extends HttpGetResponse<Block> {
    public BlockChainDownloadSpvApi (long height){
        String url = Utils.format(BitherUrl.BLOCKCHAIN_INFO_GET_SPVBLOCK_API, height);
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        System.out.print(jsonObject);
        JSONArray jsonArray = jsonObject.getJSONArray("blocks");
        System.out.print(jsonArray);
        JSONObject jsonObject1 = jsonArray.getJSONObject(0);
        System.out.print(jsonObject1);
        this.result = BlockUtil.formatStoredBlock(jsonObject1);
    }
}
