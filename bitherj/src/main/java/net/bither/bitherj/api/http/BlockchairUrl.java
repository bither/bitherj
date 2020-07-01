package net.bither.bitherj.api.http;

import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BITHER_BLOCKCHAIR_COM_URL;
import static net.bither.bitherj.api.http.BitherUrl.BITHER_DNS.BLOCKCHAIR_COM_URL;

public class BlockchairUrl {

    private static BlockchairUrl uniqueInstance = new BlockchairUrl();
    private String dns = BLOCKCHAIR_COM_URL;

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
        String nextDns = "";
        String currentDns = BlockchairUrl.getInstance().getDns();
        if (currentDns.equals(BLOCKCHAIR_COM_URL)) {
            nextDns = BITHER_BLOCKCHAIR_COM_URL;
        } else {
            nextDns = BLOCKCHAIR_COM_URL;
        }
        BlockchairUrl.getInstance().setDns(nextDns);
        return nextDns.equals(firstDns) ? null : nextDns;
    }

}
