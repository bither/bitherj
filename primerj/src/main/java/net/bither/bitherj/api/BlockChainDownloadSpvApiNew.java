package net.bither.bitherj.api;

import net.bither.bitherj.api.http.PrimerUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

import org.json.JSONObject;

public class BlockChainDownloadSpvApiNew extends HttpsGetResponse<Block> {
    public BlockChainDownloadSpvApiNew(int height){
        String url = PrimerUrl.BLOCKCHAIN_INFO_SPVBLOCK_HASH+ height;
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        String blockHash = jsonObject.getString("blockHash");
        this.result = BlockUtil.getLatestBlockHash(blockHash);
    }
}
