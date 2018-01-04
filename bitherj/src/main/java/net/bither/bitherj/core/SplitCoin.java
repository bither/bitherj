package net.bither.bitherj.core;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.utils.UnitUtil;
import net.bither.bitherj.utils.Utils;

/**
 * Created by Hzz on 2017/11/16.
 */

public enum SplitCoin {
    BCC, BTG, SBTC, BTW, BCD;

    public String getName() {
        switch (this) {
            case BCC:
                return "BCH";
            case BTG:
                return "BTG";
            case SBTC:
                return "SBTC";
            case BTW:
                return "BTW";
            case BCD:
                return "BCD";
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
            case BTW:
                return "btw";
            case BCD:
                return "bcd";
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
            case BTW:
                return 499777;
            case BCD:
                return 495866;

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
            case BTW:
                return "41";
            case BCD:
                return "1";
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
            case BTW:
                return Coin.BTW;
            case BCD:
                return Coin.BCD;
        }
        return Coin.BCC;
    }

    public TransactionSignature.SigHash getSigHash() {
        switch (this) {
            case SBTC:
                return TransactionSignature.SigHash.SBTCFORK;
            case BTW:
                return TransactionSignature.SigHash.BTWFORK;
            case BTG:
                return TransactionSignature.SigHash.BTGFORK;
            case BCD:
                return TransactionSignature.SigHash.ALL;
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
            case BTW:
                return BitherjSettings.btwP2shHeader;
        }
        return BitherjSettings.p2shHeader;
    }

    public int getAddressHeader() {
        switch (this) {
            case BCC:
                return BitherjSettings.addressHeader;
            case BTG:
                return BitherjSettings.btgAddressHeader;
            case BTW:
                return BitherjSettings.btwAddressHeader;
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

    public UnitUtil.BitcoinUnit getBitcoinUnit() {
        switch (this) {
            case BTW:
                return UnitUtil.BitcoinUnit.BTW;
            case BCD:
                return UnitUtil.BitcoinUnit.BCD;
            default:
                return UnitUtil.BitcoinUnit.BTC;
        }
    }

    public long getSplitNormalFee() {
        switch (this) {
            case BTW:
                return 1000;
            default:
                return Utils.getFeeBase();
        }
    }
}

