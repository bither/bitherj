package net.bither.bitherj.api;

import net.bither.bitherj.api.http.PrimerUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

import org.json.JSONObject;

public class BlockChainDownloadSpvApiNewBlock extends HttpsGetResponse<Block> {
    public BlockChainDownloadSpvApiNewBlock(String hash){
        String url = PrimerUrl.BLOCKCHAIN_INFO_SPVBLOCK_NEW+ hash;
        setUrl(url);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
        this.result = BlockUtil.formatStoreBlockFromBlockChainInfoNew(jsonObject);
    }
}
