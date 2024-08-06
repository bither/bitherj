package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

public class MempoolSpaceGetLatestBlockApi extends HttpsGetResponse<Block> {
    public MempoolSpaceGetLatestBlockApi(){
        setUrl(BitherUrl.MEMPOOL_SPACE_GET_LASTST_BLOCK);
    }

    @Override
    public void setResult(String response) throws Exception {
        int latestHeight = Integer.parseInt(response);
        this.result = BlockUtil.getLatestBlockHeightFromMempoolSpace(latestHeight);
    }
}