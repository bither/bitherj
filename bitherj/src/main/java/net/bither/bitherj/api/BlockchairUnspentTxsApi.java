package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.BlockchairUrl;
import net.bither.bitherj.api.http.RerequestHttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONObject;

public class BlockchairUnspentTxsApi extends RerequestHttpGetResponse {

    public static JSONObject getUnspentTxs(String txHashs) throws Exception {
        BlockchairUnspentTxsApi blockchairUnspentTxsApi = new BlockchairUnspentTxsApi(txHashs);
        return blockchairUnspentTxsApi.query(BlockchairUrl.getInstance().getDns());
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
            if (!jsonObject.has("data")) {
                return reRequest(firstDns, new Exception("data error"));
            }
            JSONObject dataJson = jsonObject.getJSONObject("data");
            if (dataJson == null) {
                return reRequest(firstDns, new Exception("data error"));
            }
            return dataJson;
        } catch (Exception ex) {
            ex.printStackTrace();
            return reRequest(firstDns, ex);
        }
    }

    private BlockchairUnspentTxsApi(String txHashs) {
        String url = Utils.format(BitherUrl.BLOCKCHAIR_COM_ADDRESS_UNSPENT_TXS, BlockchairUrl.getInstance().getDns(), txHashs);
        setUrl(url);
    }

}

