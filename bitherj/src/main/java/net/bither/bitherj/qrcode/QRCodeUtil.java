/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.qrcode;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.utils.Base58;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QRCodeUtil {
    public enum QRQuality {
        Normal(328), LOW(216);
        private int quality;

        private QRQuality(int quality) {
            this.quality = quality;
        }

        public int getQuality() {
            return this.quality;
        }

    }


    public static final String QR_CODE_SECONDARY_SPLIT_ESCAPE = "\\$";
    public static final String QR_CODE_SECONDARY_SPLIT = "$";
    public static final String QR_CODE_SPLIT = "/";
    public static final String XRANDOM_FLAG = "+";
    public static final String OLD_QR_CODE_SPLIT = ":";
    public static final String HDM_QR_CODE_FLAG = "-";
    public static final String Enterprise_HDM_QR_CODE_FLAG = "?";
    public static final String HD_MONITOR_QR_PREFIX = "BitherHD:";


    public static String[] splitString(String str) {
        if (str.indexOf(OLD_QR_CODE_SPLIT) >= 0) {
            return str.split(OLD_QR_CODE_SPLIT);
        } else {
            return str.split(QR_CODE_SPLIT);
        }
    }

    public static int indexOfOfPasswordSeed(String str) {
        int indexOfSplit;
        if (str.indexOf(OLD_QR_CODE_SPLIT) >= 0) {
            indexOfSplit = str.indexOf(OLD_QR_CODE_SPLIT);
        } else {
            indexOfSplit = str.indexOf(QR_CODE_SPLIT);
        }
        return indexOfSplit;
    }

    public static String getAddressFromPasswordSeed(String str) {
        if (str.indexOf(OLD_QR_CODE_SPLIT) >= 0) {
            int index = str.indexOf(OLD_QR_CODE_SPLIT);
            return str.substring(0, index);
        } else {
            int index = str.indexOf(QR_CODE_SPLIT);
            return Base58.hexToBase58WithAddress(str.substring(0, index));
        }


    }

    public static String[] splitOfPasswordSeed(String str) {
        if (str.indexOf(OLD_QR_CODE_SPLIT) >= 0) {
            return str.split(OLD_QR_CODE_SPLIT);
        } else {
            return str.split(QR_CODE_SPLIT);
        }

    }

    public static String getNewVersionEncryptPrivKey(String encryptPrivKey) {
        if (encryptPrivKey.contains(OLD_QR_CODE_SPLIT)) {
            return encryptPrivKey.replace(OLD_QR_CODE_SPLIT, QR_CODE_SPLIT);
        } else {
            return encryptPrivKey;
        }
    }

    public static String encodeQrCodeString(String text) {
        return text.toUpperCase(Locale.US);
    }

    public static String decodeQrCodeString(String formatString) {
        if (oldVerifyQrcodeTransport(formatString)) {
            return oldDecodeQrCodeString(formatString);
        }
        return formatString;

    }

    public static boolean verifyBitherQRCode(String text) {
        Pattern pattern = Pattern.compile("[^0-9a-zA-Z/\\+\\$%-]");
        Matcher matcher = pattern.matcher(text);
        boolean verifyNewVersion = true;
        boolean verifyOldVersion = true;
        if (matcher.find()) {
            verifyNewVersion = false;
        }
        if (!oldVerifyQrcodeTransport(text)) {
            verifyOldVersion = false;
        }
        return verifyNewVersion || verifyOldVersion;
    }

    public static List<String> getQrCodeStringList(String str) {
        List<String> stringList = new ArrayList<String>();
        int strLeng = str.length();
        int num = getNumOfQrCodeString(strLeng);
        int pageSize = (strLeng + (num - 1)) / num;
        for (int i = 0;
             i < num;
             i++) {
            int start = i * pageSize;
            int end = (i + 1) * pageSize;
            if (start > strLeng - 1) {
                continue;
            }
            if (end > strLeng) {
                end = strLeng;
            }
            String splitStr = str.substring(start, end);
            String pageString = "";
            pageString = Integer.toString(num - 1) + QR_CODE_SPLIT
                    + Integer.toString(i) + QR_CODE_SPLIT;
            stringList.add(pageString + splitStr);
        }
        return stringList;
    }

    public static int getNumOfQrCodeString(int length) {
        int quality = AbstractApp.bitherjSetting.getQRQuality().getQuality();
        if (length < quality) {
            return 1;
        } else if (length <= (quality - 4) * 10) {
            return length / (quality - 4) + 1;
        } else if (length <= (quality - 5) * 100) {
            return length / (quality - 5) + 1;
        } else if (length <= (quality - 6) * 1000) {
            return length / (quality - 6) + 1;
        } else {
            return 1000;
        }

    }

    private static String oldDecodeQrCodeString(String formatString) {
        formatString = formatString.toLowerCase(Locale.US);
        Pattern pattern = Pattern.compile("\\*([a-z])");
        Matcher matcher = pattern.matcher(formatString);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String letter = matcher.group(1);
            matcher.appendReplacement(sb, letter.toUpperCase(Locale.US));
        }
        matcher.appendTail(sb);
        return sb.toString();

    }

    private static boolean oldVerifyQrcodeTransport(String text) {
        Pattern pattern = Pattern.compile("[^0-9A-Z\\*:]");
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return false;
        }
        return true;
    }
}
