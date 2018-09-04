package org.primer.primerj.api;

import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpsGetResponse;
import org.primer.primerj.core.Block;
import org.primer.primerj.utils.BlockUtil;

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
