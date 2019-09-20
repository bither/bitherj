package net.bither.bitherj.core;

import net.bither.bitherj.utils.Utils;

import java.math.BigInteger;

public enum BitpieColdCoin {

    BTC("BTC", 0x80, "00", "05", 0, 8, null),
    USDTOMNI("OMNI-BTC-USDT", 0x80, "00", "05", 200, 8, BitpieColdCoin.BTC);

    public String code;
    private int wif;
    private String address;
    private String payToScript;
    private int pathNumber;
    private int unitDecimal;
    private BitpieColdCoin parentCoin;


    BitpieColdCoin(String code, int wif, String address, String payToScript, int pathNumber, int unitDecimal, BitpieColdCoin parentCoin) {
        this.code = code;
        this.wif = wif;
        this.address = address;
        this.payToScript = payToScript;
        this.pathNumber = pathNumber;
        this.unitDecimal = unitDecimal;
        this.parentCoin = parentCoin;
    }

    public static BitpieColdCoin fromValue(String value) {
        if (Utils.isEmpty(value)) {
            return null;
        }
        for (BitpieColdCoin t : BitpieColdCoin.values()) {
            if (t.code.equals(value.toUpperCase())) {
                return t;
            }
        }
        return null;
    }

    public int getWif() {
        return wif;
    }

    public String getAddress() {
        return address;
    }

    public String getPayToScript() {
        return payToScript;
    }

    public int getPathNumber() {
        return pathNumber;
    }

    public int getUnitDecimal() {
        return unitDecimal;
    }

    public BitpieColdCoin getParentCoin() {
        return parentCoin;
    }
}
