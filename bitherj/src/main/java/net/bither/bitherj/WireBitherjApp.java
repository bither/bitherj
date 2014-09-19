package net.bither.bitherj;

import net.bither.bitherj.core.PeerManager;
import net.bither.bitherj.utils.DynamicWire;
import net.bither.bitherj.utils.Utils;

/**
 * Created by nn on 2014/9/19.
 */
public class WireBitherjApp {
    public static void wire(DynamicWire<ISetting> bitherjApp) {
        Utils.BITHERJ_APP = bitherjApp;
        PeerManager.BITHERJ_APP = bitherjApp;
        BitherjApplication.BITHERJ_APP =bitherjApp;
    }
}