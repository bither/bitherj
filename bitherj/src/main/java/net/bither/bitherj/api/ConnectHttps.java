package net.bither.bitherj.api;

import net.bither.bitherj.api.http.HttpSetting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public final class ConnectHttps {
    private static final Logger log = LoggerFactory.getLogger(ConnectHttps.class);

    private static String requestEncoding = "utf-8";

    public static void main(String[] args) throws Exception {

        trustAllCerts();

        String getRespon = httpGet("https://104.237.157.111/api/v1/1C6FiRktL3UPd4sywhyU5CYSeLdKhvHxhR/hdm/password");
        Map<String, String> map = new HashMap<String, String>();
        byte[] password = new byte[32];
        for (int i = 0; i < password.length; i++) {
            password[i] = 0;
        }
        map.put(HttpSetting.PASSWORD, Base64.getEncoder().encodeToString(password));


        doPost("https://104.237.157.111/api/v1/1C6FiRktL3UPd4sywhyU5CYSeLdKhvHxhR/hdm/password", map);

    }

    /**
     * Utility class should not have a public constructor
     */
    private ConnectHttps() {
    }

    public static void trustAllCerts() {
        /*
         * fix for Exception in thread "main"
         * javax.net.ssl.SSLHandshakeException:
         * sun.security.validator.ValidatorException: PKIX path building failed:
         * sun.security.provider.certpath.SunCertPathBuilderException: unable to
         * find valid certification path to requested target
         */
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                log.debug("checkServerTrusted authType = {}", authType);
            }

        }};

        SSLContext sc;
        try {
            sc = SSLContext.getInstance("SSL");

            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    log.debug("hostname = " + hostname);
                    log.debug("SSLSession = " + session);
                    return true;
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyException e) {
            e.printStackTrace();
        }
    }

    private static String httpGet(String urlString) {
        URL url;
        try {
            System.out.println("\n" + urlString);
            String str;
            url = new URL(urlString);

            URLConnection con = url.openConnection();
            StringBuffer out = new StringBuffer();
            byte[] b = new byte[4096];
            for (int n; (n = con.getInputStream().read(b)) != -1; ) {
                out.append(new String(b, 0, n));
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String doPost(String reqUrl, Map parameters) {
        HttpsURLConnection url_con = null;
        String responseContent = null;
        try {
            StringBuffer params = new StringBuffer();
            for (Iterator iter = parameters.entrySet().iterator(); iter
                    .hasNext(); ) {
                Map.Entry element = (Map.Entry) iter.next();
                params.append(element.getKey().toString());
                params.append("=");
                params.append(URLEncoder.encode(element.getValue().toString(),
                        requestEncoding));
                params.append("&");
            }

            if (params.length() > 0) {
                params = params.deleteCharAt(params.length() - 1);
            }

            URL url = new URL(reqUrl);
            url_con = (HttpsURLConnection) url.openConnection();
            url_con.setRequestMethod("POST");
            System.setProperty("sun.net.client.defaultConnectTimeout", String
                    .valueOf(HttpSetting.HTTP_CONNECTION_TIMEOUT));
            System.setProperty("sun.net.client.defaultReadTimeout", String
                    .valueOf(HttpSetting.HTTP_SO_TIMEOUT));

            url_con.setDoOutput(true);
            byte[] b = params.toString().getBytes();
            url_con.getOutputStream().write(b, 0, b.length);
            url_con.getOutputStream().flush();
            url_con.getOutputStream().close();

            InputStream in = url_con.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(in,
                    requestEncoding));
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
        } finally {
            if (url_con != null) {
                url_con.disconnect();
            }
        }
        return responseContent;
    }
}
