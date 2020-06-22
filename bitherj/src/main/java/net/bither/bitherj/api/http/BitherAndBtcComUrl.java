package net.bither.bitherj.api.http;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC2;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC3;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BTC_COM_URL;

public class BitherAndBtcComUrl {

    private static BitherAndBtcComUrl uniqueInstance = new BitherAndBtcComUrl();
    private String dns = BTC_COM_URL;

    public static BitherAndBtcComUrl getInstance() {
        return uniqueInstance;
    }

    public void setDns(String dns) {
        this.dns = dns;
    }

    public String getDns() {
        return dns;
    }

    public static String getNextBcDns(String firstBcDns) {
        String nextBcDns = "";
        String currentBcDns = BitherBCUrl.getInstance().getDns();
        if (currentBcDns.equals(BTC_COM_URL)) {
            nextBcDns = BITHER_BC;
        } else if (currentBcDns.equals(BITHER_BC)) {
            nextBcDns = BITHER_BC2;
        } else if (currentBcDns.equals(BITHER_BC2)) {
            nextBcDns = BITHER_BC3;
        } else {
            nextBcDns = BTC_COM_URL;
        }
        BitherAndBtcComUrl.getInstance().setDns(nextBcDns);
        return nextBcDns.equals(firstBcDns) ? null : nextBcDns;
    }

}
