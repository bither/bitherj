package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.RerequestHttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

public class BlockchairUnspentTxsBlockHashsApi extends RerequestHttpGetResponse {

    public static JSONObject getUnspentTxs(String blockIds) throws Exception {
        BlockchairUnspentTxsBlockHashsApi blockchairUnspentTxsBlockHashsApi = new BlockchairUnspentTxsBlockHashsApi(blockIds);
        return blockchairUnspentTxsBlockHashsApi.query();
    }

    @Override
    protected JSONObject query() throws Exception {
        try {
            handleHttpGet();
            String unspentResult = getResult();
            JSONObject jsonObject = new JSONObject(unspentResult);
            if (blockchairDataIsError(jsonObject)) {
                return reRequest(new Exception("data error"));
            }
            return jsonObject;
        } catch (Exception ex) {
            ex.printStackTrace();
            return reRequest(ex);
        }
    }

    private BlockchairUnspentTxsBlockHashsApi(String blockIds) {
        String url = Utils.format(BitherUrl.BLOCKCHAIR_COM_Q_ADDRESS_UNSPENT_TXS_BLOCK_HASHS, blockIds);
        setUrl(url);
    }

}

