package org.primer.primerj.api;

import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpsGetResponse;
import org.primer.primerj.core.Block;
import org.primer.primerj.utils.BlockUtil;

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
