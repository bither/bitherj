package net.bither.bitherj.api.http;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
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




}
