package net.bither.bitherj.api.http;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.Map;

public abstract class HttpsPostResponse<T> extends BaseHttpsResponse<T> {

    public void handleHttpPost() throws Exception {
        HttpsURLConnection url_con = null;
        String responseContent = null;
        try {

            StringBuffer params = new StringBuffer();
            for (Iterator iter = getParams().entrySet().iterator(); iter
                    .hasNext(); ) {
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

            URL url = new URL(getUrl());
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
        setResult(responseContent);
    }

    public abstract Map<String, String> getParams() throws Exception;
}
