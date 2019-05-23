package net.bither.bitherj.core;

import net.bither.bitherj.PrimerjSettings;

import net.bither.bitherj.PrimerjSettings;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.utils.Utils;

/**
 * Created by Hzz on 2017/11/16.
 */

public enum Coin {
    BTC, BCC, BTG,SBTC,BTW, BCD, BTF, BTP, BTN,XPM;

    public SplitCoin getSplitCoin() {
        switch (this) {
            case BCC:
                return SplitCoin.BCC;
            case BTG:
                return SplitCoin.BTG;
            case SBTC:
                return SplitCoin.SBTC;
            case BTW:
                return SplitCoin.BTW;
            case BCD:
                return SplitCoin.BCD;
            case BTF:
                return SplitCoin.BTF;
            case BTP:
                return SplitCoin.BTP;
            case BTN:
                return SplitCoin.BTN;
        }
        return SplitCoin.BCC;
    }

    public long getForkBlockHeight() {
        return this.getSplitCoin().getForkBlockHeight();
    }

    public TransactionSignature.SigHash getSigHash() {
        switch (this) {
            case BTF:
                return  TransactionSignature.SigHash.BTFFORK;
            case BTP:
                return  TransactionSignature.SigHash.BTPFORK;
            case BTN:
                return  TransactionSignature.SigHash.BTNFORK;
            case BCD:
            case BTC:
                return TransactionSignature.SigHash.ALL;
            case BCC:
                return TransactionSignature.SigHash.BCCFORK;
            case BTG:
                return TransactionSignature.SigHash.BTGFORK;
            case BTW:
                return TransactionSignature.SigHash.BTWFORK;
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
            case BTP:
                return PrimerjSettings.btpP2shHeader;
            case BTF:
                return PrimerjSettings.btfP2shHeader;
            case BTG:
                return PrimerjSettings.btgP2shHeader;
            case BTW:
                return PrimerjSettings.btwP2shHeader;
            default:
                return PrimerjSettings.p2shHeader;
        }
    }

    public int getAddressHeader() {
        switch (this) {
            case BTP:
                return PrimerjSettings.btpAddressHeader;
            case BTF:
                return PrimerjSettings.btfAddressHeader;
            case BTG:
                return PrimerjSettings.btgAddressHeader;
            case BTW:
                return PrimerjSettings.btwAddressHeader;
            default:
                return PrimerjSettings.addressHeader;
        }
    }

    public long getSplitNormalFee() {
        if(this == BTC) {
            return Utils.getFeeBase();
        }
        return getSplitCoin().getSplitNormalFee();
    }
}
