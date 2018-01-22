package net.bither.bitherj.core;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.utils.UnitUtil;

/**
 * Created by Hzz on 2017/11/16.
 */

public enum SplitCoin {
    BCC, BTG, SBTC, BTW, BCD, BTF, BTP, BTN;

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
            case BTF:
                return "BTF";
            case BTP:
                return "BTP";
            case BTN:
                return "BTN";
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
            case BTF:
                return "btf";
            case BTP:
                return "btp";
            case BTN:
                return "btn";
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
            case BTF:
                return 500000;
            case BTP:
                return 499345;
            case BTN:
                return 501000;

        }
        return 478559;
    }

    public String getReplaceSignHash() {
        switch (this) {
            case BCC:
            case BTN:
            case BTP:
            case BTF:
            case BTG:
            case SBTC:
            case BTW:
                return "41";
            case BCD:
                return "01";
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
            case BTF:
                return Coin.BTF;
            case BTP:
                return Coin.BTP;
            case BTN:
                return Coin.BTN;
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
            case BTF:
                return TransactionSignature.SigHash.BTFFORK;
            case BTP:
                return TransactionSignature.SigHash.BTPFORK;
            case BTN:
                return TransactionSignature.SigHash.BTNFORK;
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
            case BTF:
                return BitherjSettings.btfP2shHeader;
            case BTP:
                return BitherjSettings.btpP2shHeader;
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
            case BTF:
                return BitherjSettings.btfAddressHeader;
            case BTP:
                return BitherjSettings.btpAddressHeader;
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
            case BTP:
                return UnitUtil.BitcoinUnit.BCD;
            default:
                return UnitUtil.BitcoinUnit.BTC;
        }
    }

    public long getSplitNormalFee() {
        switch (this) {
            case BTW:
                return 1000;
            case BCD:
            case BTP:
                return 10000;
            default:
                return 100000;
        }
    }

    public boolean sigHashTypeAsBtgSame() {
        switch (this) {
            case BTN:
            case BTP:
            case BTF:
            case BTW:
            case BTG:
                return true;
        }
        return false;
    }
}

