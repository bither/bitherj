package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.BlockchairUrl;
import net.bither.bitherj.api.http.RerequestHttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

public class BlockchairUnspentTxsBlockHashsApi extends RerequestHttpGetResponse {

    public static JSONObject getUnspentTxs(String blockIds) throws Exception {
        BlockchairUnspentTxsBlockHashsApi blockchairUnspentTxsBlockHashsApi = new BlockchairUnspentTxsBlockHashsApi(blockIds);
        return blockchairUnspentTxsBlockHashsApi.query(BlockchairUrl.getInstance().getDns());
    }

    @Override
    protected JSONObject query(String firstDns) throws Exception {
        try {
            handleHttpGet();
            String unspentResult = getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            if (blockchairDataIsError(jsonObject)) {
                return reRequest(firstDns, new Exception("data error"));
            }
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            return reRequest(firstDns, ex);
        }
    }

    private BlockchairUnspentTxsBlockHashsApi(String blockIds) {
        String url = Utils.format(BitherUrl.BLOCKCHAIR_COM_Q_ADDRESS_UNSPENT_TXS_BLOCK_HASHS, BlockchairUrl.getInstance().getDns(), blockIds);
        setUrl(url);
    }

}

