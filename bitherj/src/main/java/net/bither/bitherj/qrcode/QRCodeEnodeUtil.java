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
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;

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
            String addString = Utils.toAddress(Utils.sha256hash160(pub));
            Address address = new Address(addString, pub, null, isXRandom);
            wallets.add(address);
        }
        return wallets;

    }

    private static QRCodeTxTransport fromSendRequestWithUnsignedTransaction(Tx tx, String addressCannotParsed, int hdmIndex) {
        QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
        qrCodeTransport.setMyAddress(tx.getFromAddress());
        String toAddress = tx.getFirstOutAddress();
        if (Utils.isEmpty(toAddress)) {
            toAddress = addressCannotParsed;
        }
        qrCodeTransport.setHdmIndex(hdmIndex);
        qrCodeTransport.setToAddress(toAddress);
        qrCodeTransport.setTo(tx.amountSentToAddress(toAddress));
        qrCodeTransport.setFee(tx.getFee());
        List<String> hashList = new ArrayList<String>();
        for (byte[] h : tx.getUnsignedInHashes()) {
            hashList.add(Utils.bytesToHexString(h));
        }
        qrCodeTransport.setHashList(hashList);
        return qrCodeTransport;
    }

    public static String getPresignTxString(Tx tx, String changeAddress, String addressCannotParsed, int hdmIndex) {
        QRCodeTxTransport qrCodeTransport = fromSendRequestWithUnsignedTransaction(tx, addressCannotParsed, hdmIndex);
        String preSignString = "";
        try {
            String changeStr = "";
            if (!Utils.isEmpty(changeAddress)) {
                long changeAmt = tx.amountSentToAddress(changeAddress);
                if (changeAmt != 0) {
                    String[] changeStrings = new String[]{
                            Base58.bas58ToHexWithAddress(changeAddress), Long.toHexString(changeAmt)
                    };
                    changeStr = Utils.joinString(changeStrings, QRCodeUtil.QR_CODE_SPLIT);

                }
            }
            String hdmIndexString = "";
            if (qrCodeTransport.getHdmIndex() != QRCodeTxTransport.NO_HDM_INDEX) {
                hdmIndexString = Integer.toHexString(qrCodeTransport.getHdmIndex());
            }
            String[] preSigns = new String[]{hdmIndexString,
                    Base58.bas58ToHexWithAddress(qrCodeTransport.getMyAddress())
                    , changeStr, Long.toHexString(qrCodeTransport.getFee()),
                    Base58.bas58ToHexWithAddress(qrCodeTransport.getToAddress()),
                    Long.toHexString(qrCodeTransport.getTo())
            };
            preSignString = Utils.joinString(preSigns, QRCodeUtil.QR_CODE_SPLIT);
            String[] hashStrings = new String[qrCodeTransport.getHashList().size()];
            hashStrings = qrCodeTransport.getHashList().toArray(hashStrings);
            preSignString = preSignString + Utils.joinString(hashStrings, QRCodeUtil.QR_CODE_SPLIT);
            preSignString.toUpperCase(Locale.US);
        } catch (AddressFormatException e) {
            e.printStackTrace();
        }

        return preSignString;
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
