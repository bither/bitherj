package net.bither.bitherj;

import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.PeerManager;
import net.bither.bitherj.utils.Utils;

/**
 * Created by nn on 2014/9/19.
 */
public class WireBitherjAppEnv {
    public static void wire(BitherjAppEnv bitherjAppEnv) {
        AddressManager.BITHERJ_APP_ENV = bitherjAppEnv;
        Utils.BITHERJ_APP_ENV = bitherjAppEnv;
        PeerManager.BITHERJ_APP_ENV = bitherjAppEnv;
    }
}
