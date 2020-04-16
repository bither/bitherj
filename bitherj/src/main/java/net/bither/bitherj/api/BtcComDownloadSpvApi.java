package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.core.Block;
import net.bither.bitherj.utils.BlockUtil;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

public class BtcComDownloadSpvApi extends BtcComApi<Block> {

    public BtcComDownloadSpvApi(int height) {
        String url = Utils.format(BitherUrl.BTC_COM_GET_SPVBLOCK_API, height);
        setUrl(url);
    }

    @Override
    public void setResult(JSONObject response) throws Exception {
        this.result = BlockUtil.formatStoreBlockFromBtcCom(response);
    }
}
