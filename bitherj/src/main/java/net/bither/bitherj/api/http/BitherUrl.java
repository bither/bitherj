/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.api.http;


import net.bither.bitherj.utils.Utils;


public class BitherUrl {
    public static final class BITHER_DNS {
        private static final String FORMAT_HTTP = "http://%s/";
        private static final String FORMAT_HTTPS = "https://%s/";
        public static final String BITHER_BITCOIN_DOMAIN = "b.getcai.com";
        public static final String BITHER_USER_DOMAIN = "bu.getcai.com";
        public static final String BITHER_STATS_DOMAIN = "bs.getcai.com";
        public static final String BITHER_BC_DOMAIN = "bc.bither.net";
        public static final String BITHER_HDM_DOMAIN = "hdm.bither.net";
        public static final String BLOCK_CHAIN_INFO = "blockChain.info";


        public static final String BITHER_BITCOIN = Utils.format(FORMAT_HTTP, BITHER_BITCOIN_DOMAIN);
        public static final String BITHER_USER = Utils.format(FORMAT_HTTP, BITHER_USER_DOMAIN);
        public static final String BITHER_STATS = Utils.format(FORMAT_HTTP, BITHER_STATS_DOMAIN);

        public static final String BITHER_BC = Utils.format(FORMAT_HTTP, BITHER_BC_DOMAIN);
        public static final String BITHER_HDM = Utils.format(FORMAT_HTTPS, BITHER_HDM_DOMAIN);
        public static final String BITHER_URL = Utils.format(FORMAT_HTTP, "bither.net");
        public static final String BLOCK_CHAIN = Utils.format(FORMAT_HTTPS,BLOCK_CHAIN_INFO);

        // BlockChain.info
        public static final String BITHER_BLOCKCHAIN_DOMAIN = "blockchain.info";
        public static final String BITHER_BLOCKCHAIN = Utils.format(FORMAT_HTTPS, BITHER_BLOCKCHAIN_DOMAIN);

        // chain.btc.com
        public static final String BITHER_CHAINBTC_DOMAIN = "chain.btc.com";
        public static final String BITHER_CHAINBTC_URL = Utils.format(FORMAT_HTTPS, BITHER_DNS.BITHER_CHAINBTC_DOMAIN);


    }

    // bither blockChain
    public static final String BITHER_BC_GET_BY_ADDRESS = BITHER_DNS.BITHER_BLOCKCHAIN + "rawaddr/%s";
    public static final String BITHER_BC_LATEST_BLOCK = BITHER_DNS.BITHER_BLOCKCHAIN + "latestblock";
    public static final String BITHER_BC_TX_INDEX = BITHER_DNS.BITHER_BLOCKCHAIN + "rawtx/%d?format=hex";

    // bither chainBtc
    public static final String BITHER_CHAINBTC_GET_BY_ADDRESS = BITHER_DNS.BITHER_CHAINBTC_URL + "api/v1/address/%s";
    public static final String BITHER_CHAINBTC_LATEST_BLOCK = BITHER_DNS.BITHER_CHAINBTC_URL + "api/v1/latestblock";
    public static final String BITHER_CHAINBTC_TX_INDEX = BITHER_DNS.BITHER_CHAINBTC_URL + "rawtx/";


    // bither user
    public static final String BITHER_GET_COOKIE_URL = BITHER_DNS.BITHER_USER + "api/v1/cookie";
    public static final String BITHER_UPLOAD_AVATAR = BITHER_DNS.BITHER_USER + "api/v1/avatar";
    public static final String BITHER_DOWNLOAD_AVATAR = BITHER_DNS.BITHER_USER + "api/v1/avatar";
    public static final String BITHER_ERROR_API = BITHER_DNS.BITHER_USER + "api/v1/error";
    public static final String BITHER_IN_SIGNATURES_API = BITHER_DNS.BITHER_USER + "api/v1/address/%s/insignature/%d";

    // bither bitcoin
    public static final String BITHER_Q_GETBLOCK_COUNT_URL = BITHER_DNS.BITHER_BC + "api/v2/block/count";
    public static final String BITHER_GET_ONE_SPVBLOCK_API = BITHER_DNS.BITHER_BC + "api/v2/block/spv/one";
    public static final String BITHER_Q_MYTRANSACTIONS = BITHER_DNS.BITHER_BC + "api/v2/address/%s/transaction";

    // hdm api
    public static final String BITHER_HDM_PASSWORD = BITHER_DNS.BITHER_HDM + "api/v1/%s/hdm/password";
    public static final String BITHER_REVOCERY_HDM = BITHER_DNS.BITHER_HDM + "api/v1/%s/hdm/recovery";
    public static final String BITHER_HDM_CREATE_ADDRESS = BITHER_DNS.BITHER_HDM + "api/v1/%s/hdm/address/create";
    public static final String BITHER_HDM_SIGNATURE = BITHER_DNS.BITHER_HDM + "api/v1/%s/hdm/address/%d/signature";

    //bither stats
    public static final String BITHER_EXCHANGE_TICKER = BITHER_DNS.BITHER_STATS
            + "api/v1/exchange/ticker";
    public static final String BITHER_KLINE_URL = BITHER_DNS.BITHER_STATS
            + "api/v1/exchange/%d/kline/%d";
    public static final String BITHER_DEPTH_URL = BITHER_DNS.BITHER_STATS
            + "api/v1/exchange/%d/depth";
    public static final String BITHER_TREND_URL = BITHER_DNS.BITHER_STATS
            + "api/v1/exchange/%d/trend";

    //other
    public static final String BLOCKCHAIN_INFO_ADDRESS_URL = "http://blockchain.info/address/";
    public static final String BLOCKMETA_ADDRESS_URL = "http://www.blockmeta.com/address/";

    //blockChain.info Api
    public static final String BLOCKCHAIN_INFO_GET_LASTST_BLOCK = BITHER_DNS.BLOCK_CHAIN+"latestblock";
    public static final String BLOCKCHAIN_INFO_GET_SPVBLOCK_API = BITHER_DNS.BLOCK_CHAIN+"block-height/%d?format=json";
}
