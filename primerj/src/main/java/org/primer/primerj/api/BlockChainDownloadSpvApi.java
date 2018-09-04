package org.primer.primerj.api;

import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpsGetResponse;
import org.primer.primerj.core.Block;
import org.primer.primerj.utils.BlockUtil;
import org.primer.primerj.utils.Utils;

import org.json.JSONArray;
import org.json.JSONObject;
public class BlockChainDownloadSpvApi extends HttpsGetResponse<Block> {
    public BlockChainDownloadSpvApi (int height){
        String url = Utils.format(PrimerUrl.BLOCKCHAIN_INFO_GET_SPVBLOCK_API, height);
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
