package net.bither.bitherj.core;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.TransactionSignature;

/**
 * Created by Hzz on 2017/11/16.
 */

public enum SplitCoin {
    BCC, BTG, SBTC;

    public String getName() {
        switch (this) {
            case BCC:
                return "BCH";
            case BTG:
                return "BTG";
            case SBTC:
                return "SBTC";
        }
        return "BCH";
    }

    public String getUrlCode() {
        switch (this) {
            case BCC:
                return "bcc";
            case BTG:
                return "btg";
            case SBTC:
                return "sbtc";
        }
        return "bcc";
    }

    public long getForkBlockHeight() {
        switch (this) {
            case BCC:
                return 478559;
            case BTG:
                return 491407;
            case SBTC:
                return 498888;
        }
        return 478559;
    }

    public String getReplaceSignHash() {
        switch (this) {
            case BCC:
                return "41";
            case BTG:
                return "41";
            case SBTC:
                return "41";
        }
        return "41";
    }

    public Coin getCoin() {
        switch (this) {
            case BCC:
                return Coin.BCC;
            case BTG:
                return Coin.BTG;
            case SBTC:
                return Coin.SBTC;
        }
        return Coin.BCC;
    }

    public TransactionSignature.SigHash getSigHash() {
        switch (this) {
            case SBTC:
                return TransactionSignature.SigHash.SBTCFORK;
            default:
                return TransactionSignature.SigHash.BCCFORK;
        }
    }

    public int getP2shHeader() {
        switch (this) {
            case BCC:
                return BitherjSettings.p2shHeader;
            case BTG:
                return BitherjSettings.btgP2shHeader;
        }
        return BitherjSettings.p2shHeader;
    }

    public int getAddressHeader() {
        switch (this) {
            case BCC:
                return BitherjSettings.addressHeader;
            case BTG:
                return BitherjSettings.btgAddressHeader;
        }
        return BitherjSettings.addressHeader;
    }

    public String getIsGatKey() {
        switch (this) {
            case BCC:
                return "";
            default:
                return this.getName();
        }
    }
}

