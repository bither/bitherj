package net.bither.bitherj.core;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.TransactionSignature;

/**
 * Created by Hzz on 2017/11/16.
 */

public enum Coin {
    BTC, BCC, BTG,SBTC;

    public SplitCoin getSplitCoin() {
        switch (this) {
            case BCC:
                return SplitCoin.BCC;
            case BTG:
                return SplitCoin.BTG;
            case SBTC:
                return SplitCoin.SBTC;
        }
        return SplitCoin.BCC;
    }

    public long getForkBlockHeight() {
        return this.getSplitCoin().getForkBlockHeight();
    }

    public TransactionSignature.SigHash getSigHash() {
        switch (this) {
            case BTC:
                return TransactionSignature.SigHash.ALL;
            case BCC:
            case BTG:
                return TransactionSignature.SigHash.BCCFORK;
            case SBTC:
                return TransactionSignature.SigHash.SBTCFORK;
        }
        return TransactionSignature.SigHash.ALL;
    }

    static public Coin getCoin(int sigHashValue) {
        for (Coin coin: Coin.values()) {
            if (coin.getSigHash().value == sigHashValue) {
                return coin;
            }
        }
        return BTC;
    }

    public int getP2shHeader() {
        switch (this) {
            case BTG:
                return BitherjSettings.btgP2shHeader;
            default:
                return BitherjSettings.p2shHeader;
        }
    }

    public int getAddressHeader() {
        switch (this) {
            case BTG:
                return BitherjSettings.btgAddressHeader;
            default:
                return BitherjSettings.addressHeader;
        }
    }
}
