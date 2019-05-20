package org.primer.primerj.api;

import org.primer.primerj.api.http.PrimerUrl;
import org.primer.primerj.api.http.HttpsGetResponse;
import org.primer.primerj.core.Block;
import org.primer.primerj.utils.BlockUtil;
import org.primer.primerj.utils.Utils;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BlockChainGetLatestBlockNew extends HttpsGetResponse<Block> {
    public BlockChainGetLatestBlockNew(){
        setUrl(PrimerUrl.GET_BY_SYNCBLOCK);
    }

    @Override
    public void setResult(String response) throws Exception {
        JSONObject jsonObject = new JSONObject(response);
//        this.result = BlockUtil.getLatestBlockHeightNew(jsonObject);
        JSONObject result = jsonObject.getJSONObject("result");
        this.result = formatStoreBlockFromBlockChainInfo(result);
    }

    public static Block formatStoreBlockFromBlockChainInfo(JSONObject jsonObject)
            throws JSONException {
        long ver = jsonObject.getLong("version");
        int height = jsonObject.getInt("height");
        String prevBlock = jsonObject.getString("previousblockhash");
        String mrklRoot = jsonObject.getString("merkleroot");
        String hashCode = jsonObject.getString("hash");
        int time = jsonObject.getInt("time");
        String bits = jsonObject.getString("bits");
        long difficultyTarget = 389437975;//Long.parseLong(bits);
        long nonce = jsonObject.getLong("nonce");

        Block b = BlockUtil.getStoredBlock(ver, prevBlock, mrklRoot, time, difficultyTarget, nonce, height);
        b.setBlockHash(Utils.reverseBytes(Utils.hexStringToByteArray(hashCode)));

        return b;
    }

}
