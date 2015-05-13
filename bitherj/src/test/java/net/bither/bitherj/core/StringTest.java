package net.bither.bitherj.core;

import net.bither.bitherj.qrcode.QRCodeUtil;

import org.junit.Test;

/**
 * Created by nn on 15/1/23.
 */
public class StringTest {
    @Test
    public void testString() {
        boolean result =
                QRCodeUtil.verifyBitherQRCode("-E0B56EB20152755D3287BEBAAB612BB4049E736A44301729D878D54CA0912DF84F88BBDBE7330CA412FF700991BE8FE1/989A374A3B0F301808654DCD6264F368/01f120397c1017c628");
        if (result) {

        } else {

        }
    }
}
