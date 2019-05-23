package net.bither.bitherj.api;

import net.bither.bitherj.api.http.PrimerUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

import org.json.JSONObject;

public class BlockChainGetLatestBlockApi extends HttpsGetResponse<Block> {
    public BlockChainGetLatestBlockApi(){
        setUrl(PrimerUrl.BLOCKCHAIN_INFO_GET_LASTST_BLOCK);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        this.result = BlockUtil.getLatestBlockHeight(jsonObject);
    }
}
