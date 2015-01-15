package net.bither.bitherj.core;

import net.bither.bitherj.api.ConnectHttps;
import org.junit.Test;

/**
 * Created by nn on 15/1/15.
 */
public class HttpsTest {
    @Test
    public void testCreateHDAddress() {
        try {


            ConnectHttps.main(null);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
