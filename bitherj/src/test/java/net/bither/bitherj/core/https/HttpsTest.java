package net.bither.bitherj.core.https;

import net.bither.bitherj.api.ConnectHttps;
import net.bither.bitherj.api.TrustCert;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class HttpsTest {
    private static final String TrustStorePath = "bithertruststore.jks";
    private static final String TrustStorePassword = "bither";

    @Test
    public void testCreateHDAddress() throws Exception {
        trust();
        try {
            String getRespon = ConnectHttps.httpGet("https://hdm.bither.net/api/v1/1C6FiRktL3UPd4sywhyU5CYSeLdKhvHxhR/hdm/password");
            System.out.println(getRespon);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static final void trust() throws FileNotFoundException {
        InputStream stream = HttpsTest.class.getResourceAsStream(TrustStorePath);
        if (stream == null) {
            throw new FileNotFoundException(TrustStorePath);
        }
        ConnectHttps.trustCerts(new TrustCert(stream, TrustStorePassword.toCharArray(), "jks"));
    }
}
