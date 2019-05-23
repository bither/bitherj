package net.bither.bitherj.api.http;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

public abstract class HttpsPostResponse<T> extends BaseHttpsResponse<T> {

    public void handleHttpPost() throws Exception {
        trustCerts();
        HttpsURLConnection con = null;
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
            con = (HttpsURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            System.setProperty("sun.net.client.defaultConnectTimeout", String
                    .valueOf(HttpSetting.HTTP_CONNECTION_TIMEOUT));
            System.setProperty("sun.net.client.defaultReadTimeout", String
                    .valueOf(HttpSetting.HTTP_SO_TIMEOUT));

            con.setDoOutput(true);
            byte[] b = params.toString().getBytes();
            con.getOutputStream().write(b, 0, b.length);
            con.getOutputStream().flush();
            con.getOutputStream().close();

            InputStream in = con.getInputStream();
            responseContent = getStringFromIn(in);

            in.close();
        } catch (IOException e) {
            e.printStackTrace();
            if (con.getResponseCode() == 400) {
                String str = getStringFromIn(con.getErrorStream());
                JSONObject json = new JSONObject(str);
                Iterator it = json.keys();
                if (it.hasNext()) {
                    String key = (String) it.next();
                    String value = json.getString(key);
                    throw new Http400Exception(Integer.valueOf(key), value);
                }
            } else if (con.getResponseCode() != 200) {
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
        setResult(responseContent);
    }


    public abstract Map<String, String> getParams() throws Exception;
}
