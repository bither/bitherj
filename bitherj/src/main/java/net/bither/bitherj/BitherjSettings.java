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

package net.bither.bitherj;

import net.bither.bitherj.utils.Utils;

import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

public class BitherjSettings {

    public static final boolean LOG_DEBUG = true;
    public static final boolean DEV_DEBUG = true;

    public static final int BITHER_DESKTOP_NETWORK_SOCKET = 8329;
    public static final int BITHER_ENTERPRISE_NETWORK_SOCKET = 8328;
    public static final int BITHER_DAEMON_NETWORK_SOCKET = 8327;

    public static final int PROTOCOL_VERSION = 70001;
    public static final int MIN_PROTO_VERSION = 70001;

    public static final int MAX_TX_SIZE = 100000;
    public static final int COMPRESS_OUT_NUM = 5;
    public static final int TX_PAGE_SIZE = 20;

    public static final String DONATE_ADDRESS = "1BitherUnNvB2NsfxMnbS35kS3DTPr7PW5";

    /**
     * The alert signing key originally owned by Satoshi, and now passed on to Gavin along with a few others.
     */
    public static final byte[] SATOSHI_KEY = Hex.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");


    /**
     * The string returned by getId() for the main, production network where people trade things.
     */
    public static final String ID_MAINNET = "org.bitcoin.production";


    public static final BigInteger proofOfWorkLimit = Utils.decodeCompactBits(0x1d00ffffL);
    public static final int port = 8333;
    public static final long packetMagic = 0xf9beb4d9L;
    public static final int addressHeader = 0;
    public static final int p2shHeader = 5;
    public static final int dumpedPrivateKeyHeader = 128;
    public static final int TARGET_TIMESPAN = 14 * 24 * 60 * 60;  // 2 weeks per difficulty cycle, on average.
    public static final int TARGET_SPACING = 10 * 60;  // 10 minutes per block.
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;
    public static final int BTCFORKBLOCKNO = 478559;

    public static final long TX_UNCONFIRMED = Long.MAX_VALUE;

    public static final int PROTOCOL_TIMEOUT = 30000;

    public static final String id = ID_MAINNET;

    /**
     * The depth of blocks required for a coinbase transaction to be spendable.
     */
    public static final int spendableCoinbaseDepth = 100;
    public static final String[] dnsSeeds = new String[]{
            "seed.bitcoin.sipa.be",        // Pieter Wuille
            "dnsseed.bluematt.me",         // Matt Corallo
            "seed.bitcoinstats.com",       // Chris Decker
            "bitseed.xf2.org",
            "seed.bitcoinstats.com",
            "seed.bitnodes.io"
    };

    public static final long MAX_MONEY = 21000000l * 100000000l;

    public static final byte[] GENESIS_BLOCK_HASH = Utils.reverseBytes(Hex.decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
    public static final int BLOCK_DIFFICULTY_INTERVAL = 2016;
    public static final int BITCOIN_REFERENCE_BLOCK_HEIGHT = 250000;
    public static final int MaxPeerConnections = 6;
    public static final int MaxPeerBackgroundConnections = 2;

    public static enum AppMode {
        COLD, HOT
    }

    public static enum ApiConfig {
        BLOCKCHAIN_INFO(1), BITHER_NET(0);

        private int value;
        ApiConfig(int value){
            this.value = value;
        }

        public int value(){
            return value;
        }
    }

    public static final String PRIVATE_KEY_FILE_NAME = "%s/%s.key";
    public static final String WATCH_ONLY_FILE_NAME = "%s/%s.pub";

    public static final boolean ensureMinRequiredFee = true;

    public enum TransactionFeeMode {
        Normal(10000), High(20000), Higher(50000), TenX(100000);

        private int satoshi;

        TransactionFeeMode(int satoshi) {
            this.satoshi = satoshi;
        }

        public int getMinFeeSatoshi() {
            return satoshi;
        }
    }

    public enum MarketType {
        BITSTAMP, BTCE, BTCCHINA, OKCOIN, HUOBI, CHBTC, BTCTRADE, BITFINEX,
        COINBASE, MARKET796;


    }

    public static MarketType getMarketType(int value) {
        switch (value) {
            case 2:
                return MarketType.BTCE;
            case 3:
                return MarketType.HUOBI;
            case 4:
                return MarketType.OKCOIN;
            case 5:
                return MarketType.BTCCHINA;
            case 6:
                return MarketType.CHBTC;
            case 7:
                return MarketType.BITFINEX;
            case 8:
                return MarketType.MARKET796;
            case 9:
                return MarketType.COINBASE;
            case 10:
                return MarketType.BTCTRADE;
        }
        return MarketType.BITSTAMP;
    }

    public static int getMarketValue(MarketType marketType) {
        switch (marketType) {
            case BTCE:
                return 2;
            case HUOBI:
                return 3;
            case OKCOIN:
                return 4;
            case BTCCHINA:
                return 5;
            case CHBTC:
                return 6;
            case BITFINEX:
                return 7;
            case MARKET796:
                return 8;
            case COINBASE:
                return 9;
            case BTCTRADE:
                return 10;


        }
        return 1;
    }

    public enum KlineTimeType {
        ONE_MINUTE(1), FIVE_MINUTES(5), ONE_HOUR(60), ONE_DAY(1440);
        private int mVal;

        private KlineTimeType(int val) {
            this.mVal = val;
        }

        public int getValue() {
            return this.mVal;
        }
    }


}
