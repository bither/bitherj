package net.bither.bitherj.api.http;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BLOCKCHAIR_COM_URL;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BLOCKCHAIR_COM_URL;

public class BlockchairUrl {

    private static BlockchairUrl uniqueInstance = new BlockchairUrl();
    private String dns = BITHER_BLOCKCHAIR_COM_URL;

    public static BlockchairUrl getInstance() {
        return uniqueInstance;
    }

    public void setDns(String dns) {
        this.dns = dns;
    }

    public String getDns() {
        return dns;
    }

    public static String getNextDns(String firstDns) {
        return null;
    }

}
