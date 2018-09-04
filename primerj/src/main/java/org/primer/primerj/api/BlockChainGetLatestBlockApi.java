package org.primer.primerj.api;

import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpsGetResponse;
import org.primer.primerj.core.Block;
import org.primer.primerj.utils.BlockUtil;

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
