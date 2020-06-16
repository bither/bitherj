package net.bither.bitherj.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class DateTimeUtils {

    public static final String DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";

    public static final int getBlockchairDateTimestamp(String str) {
        SimpleDateFormat df = new SimpleDateFormat(DATE_TIME_FORMAT);
        try {
            long time = new Date(df.parse(str).getTime()).getTime() / 1000 + 8 * 60 * 60;
            return (int) time;
        } catch (ParseException ex) {
            ex.printStackTrace();
            return 0;
        }
    }

}
