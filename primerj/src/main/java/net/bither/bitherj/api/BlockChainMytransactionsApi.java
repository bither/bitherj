package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpsGetResponse;

import net.bither.bitherj.api.http.PrimerUrl;
import net.bither.bitherj.api.http.HttpsGetResponse;
import net.bither.bitherj.utils.Utils;

/**
 * Created by zhangbo on 16/1/9.
 */
public class BlockChainMytransactionsApi extends HttpsGetResponse<String> {

    public static final int length=100;
    @Override
    public void setResult(String response) throws Exception {
        this.result = response;
    }
    public BlockChainMytransactionsApi(String address,int offset) {
        String url = Utils.format(PrimerUrl.GET_BY_ADDRESS, address);
        StringBuilder stringBuilder=new StringBuilder(url);
        stringBuilder.append("?offset=");
        stringBuilder.append(offset);
        stringBuilder.append("&length=");
        stringBuilder.append(length);
        setUrl(stringBuilder.toString());
    }

    public BlockChainMytransactionsApi(String address) {
        String url = Utils.format(PrimerUrl.GET_BY_ADDRESS, address);
        setUrl(url);
    }

    public BlockChainMytransactionsApi() {
        setUrl(PrimerUrl.BITHER_BC_LATEST_BLOCK);
    }

    public BlockChainMytransactionsApi(int txIndex) {
        String url = String.format(PrimerUrl.BITHER_BC_TX_INDEX, txIndex);
        setUrl(url);
    }

}
