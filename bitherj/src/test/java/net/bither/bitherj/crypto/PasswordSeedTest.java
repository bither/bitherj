package net.bither.bitherj.crypto;

import org.junit.Test;

public class PasswordSeedTest {

    @Test
    public void testPasswordTest() {
        String keyString = "0077b3dad72529632b0728128cba3e70edea7b047b/548BA5896EBFF2DEB66E8D697987222E9B3C7AEE0C6B7580235FCEE1FD3D1119408EB3927DED776F56231AD0FE8AB912/DBE9FAE06805DB4E91C7448B1F7A26F1/014f626c0177990ca5";
        PasswordSeed passwordSeed = new PasswordSeed(keyString);
        boolean reslut = passwordSeed.checkPassword("123456");
        if (reslut) {
            System.out.println("checkPassword pass");
        } else {
            System.out.println("checkPassword no pass");
        }

    }
}
