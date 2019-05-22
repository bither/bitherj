package net.bither.bitherj.api.http;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;


public abstract class HttpsGetResponse<T> extends BaseHttpsResponse<T> {

    public void handleHttpGet() throws Exception {
         final Logger log = LoggerFactory
                .getLogger(BaseHttpResponse.class);

        trustCerts();
        URL url;
        HttpURLConnection con = null;
        try {

            url = new URL(getUrl());
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            System.setProperty("sun.net.client.defaultConnectTimeout", String
                    .valueOf(HttpSetting.HTTP_CONNECTION_TIMEOUT));
            System.setProperty("sun.net.client.defaultReadTimeout", String
                    .valueOf(HttpSetting.HTTP_SO_TIMEOUT));
            StringBuffer out = new StringBuffer();
            byte[] b = new byte[4096];
            for (int n; (n = con.getInputStream().read(b)) != -1; ) {
                out.append(new String(b, 0, n));
            }
            setResult(out.toString());
            log.info("Received https output: " + out.toString());
        } catch (IOException e) {
            if (con.getResponseCode() != 200) {
                String str = getStringFromIn(con.getErrorStream());
                throw new HttpException(con.getResponseCode() + "," + str);
            } else {
                throw e;
            }
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }
}
