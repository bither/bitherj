package net.bither.bitherj.api.http;

import javax.net.ssl.HttpsURLConnection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

public abstract class BaseHttpsResponse<T> {

    protected T result;
    private String mUrl;

    public T getResult() {
        return result;
    }

    public abstract void setResult(String response) throws Exception;


    protected String getUrl() {
        return mUrl;
    }

    protected void setUrl(String url) {
        this.mUrl = url;
    }

    protected String getStringFromIn(InputStream in) throws IOException {
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
        rd.close();

        return tempStr.toString();
    }


}
