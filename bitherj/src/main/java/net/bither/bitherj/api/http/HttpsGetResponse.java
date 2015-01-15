package net.bither.bitherj.api.http;

import javax.net.ssl.HttpsURLConnection;

import java.net.URL;

public abstract class HttpsGetResponse<T> extends BaseHttpsResponse<T> {

    public void handleHttpGet() throws Exception {
        URL url;
        HttpsURLConnection con = null;
        try {

            url = new URL(getUrl());
            con = (HttpsURLConnection) url.openConnection();
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
        } catch (Exception e) {
            e.printStackTrace();
            if (con.getResponseCode() == 400) {

            }
            throw e;
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }
    }
}
