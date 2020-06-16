package net.bither.bitherj.api;

import net.bither.bitherj.api.http.BitherUrl;
import net.bither.bitherj.api.http.Http404Exception;
import net.bither.bitherj.api.http.RerequestHttpGetResponse;
import net.bither.bitherj.utils.Utils;

import org.json.JSONArray;
import org.json.JSONObject;

public class BlockchairQueryAddressUnspentApi extends RerequestHttpGetResponse {

    private String addresses;
    private String[] addressList;
    private int offset = 0;
    private JSONObject result = new JSONObject();

    public final static String LAST_TX_ADDRESS = "last_tx_address";
    public final static String UTXO = "unspent_tx_out";
    public final static String HAS_TX_ADDRESSES = "has_tx_addresses";
    public final static String HAS_UTXO_ADDRESSES = "has_utxo_addresses";

    public static JSONObject queryAddressUnspent(String addresses) throws Exception {
        BlockchairQueryAddressUnspentApi blockchairQueryAddressUnspentApi = new BlockchairQueryAddressUnspentApi();
        blockchairQueryAddressUnspentApi.addresses = addresses;
        blockchairQueryAddressUnspentApi.addressList = addresses.split(",");
        blockchairQueryAddressUnspentApi.result.put(LAST_TX_ADDRESS, "");
        blockchairQueryAddressUnspentApi.result.put(HAS_TX_ADDRESSES, "");
        blockchairQueryAddressUnspentApi.result.put(HAS_UTXO_ADDRESSES, "");
        blockchairQueryAddressUnspentApi.setUrl(addresses, 0);
        return blockchairQueryAddressUnspentApi.query();
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
            String lastTxAddress = addressList[addressList.length - 1];
            if (!jsonObject.has("data")) {
                return result;
            }
            JSONObject dataJson = jsonObject.getJSONObject("data");
            if (dataJson == null || dataJson.length() == 0) {
                return result;
            }
            if (offset == 0) {
                if (!dataJson.has("addresses")) {
                    return result;
                }
                JSONObject addressesJson = dataJson.getJSONObject("addresses");
                if (addressesJson == null || addressesJson.length() == 0) {
                    return result;
                }
                String hasTxAddresses = "";
                for (int i = 0; i < addressList.length - 1; i++) {
                    String address = addressList[i];
                    if (!addressesJson.has(address)) {
                        continue;
                    }
                    JSONObject addressJson = addressesJson.getJSONObject(address);
                    if (addressesJson == null) {
                        continue;
                    }
                    if (addressJson.has("received") && addressJson.getLong("received") > 0) {
                        if (Utils.isEmpty(hasTxAddresses)) {
                            hasTxAddresses = address;
                        } else if (!hasTxAddresses.contains(address)) {
                            hasTxAddresses = hasTxAddresses + "," + address;
                        }
                        lastTxAddress = address;
                    }
                }
                result.put(LAST_TX_ADDRESS, lastTxAddress);
                result.put(HAS_TX_ADDRESSES, hasTxAddresses);
            }
            int unspentOutputCount = 0;
            if (!dataJson.has("set")) {
                return result;
            }
            JSONObject setJson = dataJson.getJSONObject("set");
            if (setJson != null) {
                unspentOutputCount = setJson.getInt("unspent_output_count");
            }
            if (unspentOutputCount == 0) {
                return result;
            }
            if (!dataJson.has("utxo")) {
                return result;
            }
            JSONArray utxoArray = dataJson.getJSONArray("utxo");
            if (utxoArray == null || utxoArray.length() == 0) {
                return result;
            }
            JSONArray lastUtxo = result.has(UTXO) ? result.getJSONArray(UTXO) : new JSONArray();
            String hasUtxoAddresses = result.getString(HAS_UTXO_ADDRESSES);
            for (int i = 0; i < utxoArray.length(); i++) {
                JSONObject utxoJson = utxoArray.getJSONObject(i);
                if (!utxoJson.has("transaction_hash") || !utxoJson.has("address") || !utxoJson.has("block_id") || utxoJson.getInt("block_id") == -1) {
                    continue;
                }
                String address = utxoJson.getString("address");
                if (Utils.isEmpty(hasUtxoAddresses)) {
                    hasUtxoAddresses = address;
                } else if (!hasUtxoAddresses.contains(address)) {
                    hasUtxoAddresses = hasUtxoAddresses + "," + address;
                }
                lastUtxo.put(utxoJson);
            }
            result.put(HAS_UTXO_ADDRESSES, hasUtxoAddresses);
            result.put(UTXO, lastUtxo);
            long currentUnspentOutputCount = offset == 0 ? utxoArray.length() : offset * 100 + utxoArray.length();
            if (currentUnspentOutputCount < unspentOutputCount) {
                setUrl(addresses, offset + 1);
                return query();
            }
            return result;
        } catch (Exception ex) {
            ex.printStackTrace();
            if (ex instanceof Http404Exception) {
                return result;
            } else {
                return reRequest(ex);
            }
        }
    }

    private void setUrl(String addresses, int offset) {
        this.offset = offset;
        String url = Utils.format(BitherUrl.BLOCKCHAIR_COM_Q_ADDRESSES_UNSPENT, addresses);
        if (offset > 0) {
            url = url + "&offset=" + offset;
        }
        setUrl(url);
    }

}

