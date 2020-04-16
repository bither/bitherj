package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;

import org.json.JSONObject;

public class BtcComGetLatestBlockApi extends BtcComApi<Block> {

    public BtcComGetLatestBlockApi(){
        setUrl(BitherUrl.BTC_COM_GET_LASTST_BLOCK);
    }

    @Override
    public void setResult(JSONObject response) throws Exception {
        if (!response.has("height")) {
            throw new Exception("btc com response error");
        }
        this.result = BlockUtil.getLatestBlockHeight(response);
    }

}
