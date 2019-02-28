package net.bither.bitherj.api.http;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC2;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BC3;

public class BitherBCUrl {

    private static BitherBCUrl uniqueInstance = new BitherBCUrl();
    private String dns  = BITHER_BC;

    public static BitherBCUrl getInstance() {
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
        if (currentBcDns.equals(BITHER_BC)) {
            nextBcDns = BITHER_BC2;
        } else if (currentBcDns.equals(BITHER_BC2)) {
            nextBcDns = BITHER_BC3;
        } else {
            nextBcDns = BITHER_BC;
        }
        BitherBCUrl.getInstance().setDns(nextBcDns);
        return nextBcDns.equals(firstBcDns) ? null : nextBcDns;
    }
}
