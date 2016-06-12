package net.bither.bitherj.api;

import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.api.http.HttpSetting;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public final class ConnectHttps {
    private static final Logger log = LoggerFactory.getLogger(ConnectHttps.class);

    /**
     * Utility class should not have a public constructor
     */
    private ConnectHttps() {
    }

    public static void trustCerts(TrustCert cert) {
        try {
            KeyStore localTrustStore = cert.getKeyStore();
            if (localTrustStore == null) {
                log.error("can not load key due to no key store instance for type");
                return;
            }
            BitherTrustManager trustManager = new BitherTrustManager(localTrustStore);

            SSLContext sc = SSLContext.getInstance("SSL");

            sc.init(null, new TrustManager[]{trustManager}, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
            log.error("can not load key store https will be disabled");
            if (BitherjSettings.DEV_DEBUG) {
//                throw new RuntimeException(e);
            }
        }
    }

    public static String httpGet(String urlString) throws Exception {
        URL url;
        HttpsURLConnection con = null;
        try {
            System.out.println("\n" + urlString);
            url = new URL(urlString);
            con = (HttpsURLConnection) url.openConnection();
            StringBuffer out = new StringBuffer();
            byte[] b = new byte[4096];
            for (int n;
                 (n = con.getInputStream().read(b)) != -1; ) {
                out.append(new String(b, 0, n));
            }
            return out.toString();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        } finally {
            if (con != null) {
                con.disconnect();
            }
        }

    }

    public static String doPost(String reqUrl, Map parameters) throws Exception {
        HttpsURLConnection url_con = null;
        String responseContent = null;
        try {
            StringBuffer params = new StringBuffer();
            for (Iterator iter = parameters.entrySet().iterator();
                 iter.hasNext(); ) {
                Map.Entry element = (Map.Entry) iter.next();
                params.append(element.getKey().toString());
                params.append("=");
                params.append(URLEncoder.encode(element.getValue().toString(),
                        HttpSetting.REQUEST_ENCODING));
                params.append("&");
            }

            if (params.length() > 0) {
                params = params.deleteCharAt(params.length() - 1);
            }

            URL url = new URL(reqUrl);
            url_con = (HttpsURLConnection) url.openConnection();
            url_con.setRequestMethod("POST");
            System.setProperty("sun.net.client.defaultConnectTimeout",
                    String.valueOf(HttpSetting.HTTP_CONNECTION_TIMEOUT));
            System.setProperty("sun.net.client.defaultReadTimeout",
                    String.valueOf(HttpSetting.HTTP_SO_TIMEOUT));

            url_con.setDoOutput(true);
            byte[] b = params.toString().getBytes();
            url_con.getOutputStream().write(b, 0, b.length);
            url_con.getOutputStream().flush();
            url_con.getOutputStream().close();

            InputStream in = url_con.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(in,
                    HttpSetting.REQUEST_ENCODING));
            String tempLine = rd.readLine();
            StringBuffer tempStr = new StringBuffer();
            String crlf = System.getProperty("line.separator");
            while (tempLine != null) {
                tempStr.append(tempLine);
                tempStr.append(crlf);
                tempLine = rd.readLine();
            }
            responseContent = tempStr.toString();
            rd.close();
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        } finally {
            if (url_con != null) {
                url_con.disconnect();
            }
        }
        return responseContent;
    }
}
