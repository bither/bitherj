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


import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QRCodeEnodeUtil {
    private static final Logger log = LoggerFactory.getLogger(QRCodeEnodeUtil.class);

    private static final String QR_CODE_LETTER = "*";

    public static String getPublicKeyStrOfPrivateKey() {
        String content = "";
        List<Address> addresses = AddressManager.getInstance().getPrivKeyAddresses();
        for (int i = 0; i < addresses.size(); i++) {
            Address address = addresses.get(i);
            String pubStr = "";
            if (address.isFromXRandom()) {
                pubStr = QRCodeUtil.XRANDOM_FLAG;
            }
            pubStr = pubStr + Utils.bytesToHexString(address.getPubKey());
            content += pubStr;
            if (i < addresses.size() - 1) {
                content += QRCodeUtil.QR_CODE_SPLIT;
            }
        }
        content.toUpperCase(Locale.US);
        return content;
    }

    public static boolean checkPubkeysQRCodeContent(String content) {
        String[] strs = QRCodeUtil.splitString(content);
        for (String str : strs) {
            boolean checkCompressed = str.length() == 66 || ((str.length() == 67)
                    && (str.indexOf(QRCodeUtil.XRANDOM_FLAG) == 0));
            boolean checkUnCompressed = str.length() == 130 || ((str.length() == 131)
                    && (str.indexOf(QRCodeUtil.XRANDOM_FLAG) == 0));
            if(str.indexOf(QRCodeUtil.XRANDOM_FLAG) == 0){
                str = str.substring(QRCodeUtil.XRANDOM_FLAG.length());
            }
            org.spongycastle.math.ec.ECPoint ecPoint = ECKey.checkPoint(Utils.hexStringToByteArray(str));

            if (ecPoint == null || !ecPoint.isValid()) {
                return false;
            }
            if (!checkCompressed && !checkUnCompressed) {
                return false;
            }
        }
        return true;
    }

    public static List<Address> formatPublicString(String content) {
        String[] strs = QRCodeUtil.splitString(content);
        ArrayList<Address> wallets = new ArrayList<Address>();
        for (String str : strs) {
            boolean isXRandom = false;
            if (str.indexOf(QRCodeUtil.XRANDOM_FLAG) == 0) {
                isXRandom = true;
                str = str.substring(1);
            }
            byte[] pub = Utils.hexStringToByteArray(str);

            org.spongycastle.math.ec.ECPoint ecPoint = ECKey.checkPoint(pub);
            if (ecPoint != null && ecPoint.isValid()) {
                String addString = Utils.toAddress(Utils.sha256hash160(pub));
                Address address = new Address(addString, pub, null, false, isXRandom);
                wallets.add(address);
            }
        }
        return wallets;

    }

    public static String oldEncodeQrCodeString(String text) {
        Pattern pattern = Pattern.compile("[A-Z]");
        Matcher matcher = pattern.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String letter = matcher.group(0);
            matcher.appendReplacement(sb, QR_CODE_LETTER + letter);
        }
        matcher.appendTail(sb);

        return sb.toString().toUpperCase(Locale.US);
    }

}
