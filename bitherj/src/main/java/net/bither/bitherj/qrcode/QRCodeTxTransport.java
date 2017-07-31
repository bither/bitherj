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

import net.bither.bitherj.core.AbstractHD;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.DesktopHDMAddress;
import net.bither.bitherj.core.EnterpriseHDMAddress;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class QRCodeTxTransport implements Serializable {

    public enum TxTransportType {
        NormalPrivateKey(1), ServiceHDM(2),//no use in new version
        ColdHDM(3), DesktopHDM(4), ColdHD(5);

        private int type;

        private TxTransportType(int type) {
            this.type = type;
        }

        public int getType() {
            return type;
        }
    }

    public static TxTransportType getTxTransportType(int type) {
        switch (type) {
            case 1:
                return TxTransportType.NormalPrivateKey;
            case 2:
                return TxTransportType.ServiceHDM;
            case 3:
                return TxTransportType.ColdHDM;
            case 4:
                return TxTransportType.DesktopHDM;
            case 5:
                return TxTransportType.ColdHD;
            default:
                return TxTransportType.NormalPrivateKey;
        }
    }

    private static final long serialVersionUID = 5979319690741716813L;

    private static final String TX_TRANSPORT_VERSION = "V";

    public static final int NO_HDM_INDEX = -1;

    private List<String> mHashList;
    private String mMyAddress;
    private String mToAddress;
    private long mTo;
    private long mFee;
    private long changeAmt;
    private String changeAddress;
    private int hdmIndex = NO_HDM_INDEX;
    private TxTransportType txTransportType;


    private List<AbstractHD.PathTypeIndex> pathTypeIndexes;


    public List<String> getHashList() {
        return mHashList;
    }

    public void setHashList(List<String> mHashList) {
        this.mHashList = mHashList;
    }

    public String getMyAddress() {
        return mMyAddress;
    }

    public void setMyAddress(String mMyAddress) {
        this.mMyAddress = mMyAddress;
    }

    public String getToAddress() {
        return mToAddress;
    }

    public void setToAddress(String mOtherAddress) {
        this.mToAddress = mOtherAddress;
    }

    public long getTo() {
        return mTo;
    }

    public void setTo(long mTo) {
        this.mTo = mTo;
    }

    public long getFee() {
        return mFee;
    }

    public void setFee(long mFee) {
        this.mFee = mFee;
    }

    public String getChangeAddress() {
        return changeAddress;
    }

    public void setChangeAddress(String changeAddress) {
        this.changeAddress = changeAddress;
    }

    public long getChangeAmt() {
        return changeAmt;
    }

    public void setChangeAmt(long changeAmt) {
        this.changeAmt = changeAmt;
    }

    public int getHdmIndex() {
        return hdmIndex;
    }

    public void setHdmIndex(int hdmIndex) {
        this.hdmIndex = hdmIndex;
    }


    public List<AbstractHD.PathTypeIndex> getPathTypeIndexes() {
        return pathTypeIndexes;
    }

    public void setPathTypeIndexes(List<AbstractHD.PathTypeIndex> pathTypeIndexes) {
        this.pathTypeIndexes = pathTypeIndexes;
    }

    public TxTransportType getTxTransportType() {
        return txTransportType;
    }

    public void setTxTransportType(TxTransportType txTransportType) {
        this.txTransportType = txTransportType;
    }

    public static String getHDAccountMonitoredUnsignedTx(Tx tx, String toAddress,
                                                         HDAccount account) {
        TxTransportType txTransportType = TxTransportType.ColdHD;
        List<HDAccount.HDAccountAddress> addresses = account.getSigningAddressesForInputs(tx
                .getIns());
        List<byte[]> hashes;
        if (tx.isBtc()) {
             hashes = tx.getUnsignedInHashes();
        } else {
            hashes = tx.getBccForkUnsignedInHashes();
        }

        QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();

        qrCodeTransport.setMyAddress(tx.getFromAddress());
        qrCodeTransport.setToAddress(toAddress);
        qrCodeTransport.setTo(tx.amountSentToAddress(toAddress));
        qrCodeTransport.setFee(tx.getFee());
        List<String> hashList = new ArrayList<String>();

        for (int i = 0;
             i < addresses.size();
             i++) {
            HDAccount.HDAccountAddress address = addresses.get(i);
            byte[] h = hashes.get(i);
            String[] strings = new String[]{Integer.toString(address.getPathType().getValue()),
                    Integer.toString(address.getIndex()), Utils.bytesToHexString(h).toUpperCase
                    (Locale.US)};
            hashList.add(Utils.joinString(strings, QRCodeUtil.QR_CODE_SECONDARY_SPLIT));
        }
        qrCodeTransport.setHashList(hashList);

        String preSignString;
        try {
            String versionStr = "";
            if (txTransportType != null) {
                versionStr = TX_TRANSPORT_VERSION + txTransportType.getType();
            }
            String[] preSigns = new String[]{versionStr, Base58.bas58ToHexWithAddress
                    (qrCodeTransport.getMyAddress()), Long.toHexString(qrCodeTransport.getFee()),
                    Base58.bas58ToHexWithAddress(qrCodeTransport.getToAddress()), Long
                    .toHexString(qrCodeTransport.getTo())};
            preSignString = Utils.joinString(preSigns, QRCodeUtil.QR_CODE_SPLIT);
            String[] hashStrings = new String[qrCodeTransport.getHashList().size()];
            hashStrings = qrCodeTransport.getHashList().toArray(hashStrings);
            preSignString = preSignString + QRCodeUtil.QR_CODE_SPLIT + Utils.joinString
                    (hashStrings, QRCodeUtil.QR_CODE_SPLIT);
            preSignString.toUpperCase(Locale.US);
        } catch (AddressFormatException e) {
            e.printStackTrace();
            return null;
        }
        return preSignString;
    }

    private static QRCodeTxTransport changeFormatQRCodeTransportOfDesktopHDM(String str) {
        try {
            String[] strArray = QRCodeUtil.splitString(str);
            QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();

            String address = Base58.hexToBase58WithAddress(strArray[0]);
            if (!Utils.validBicoinAddress(address)) {
                return null;
            }
            qrCodeTransport.setMyAddress(address);
            String changeAddress = Base58.hexToBase58WithAddress(strArray[1]);
            if (!Utils.validBicoinAddress(changeAddress)) {
                return null;
            }
            qrCodeTransport.setChangeAddress(changeAddress);
            qrCodeTransport.setChangeAmt(Long.parseLong(strArray[2], 16));
            qrCodeTransport.setFee(Long.parseLong(strArray[3], 16));
            String toAddress = Base58.hexToBase58WithAddress(strArray[4]);
            if (!Utils.validBicoinAddress(toAddress)) {
                return null;
            }
            qrCodeTransport.setToAddress(toAddress);
            qrCodeTransport.setTo(Long.parseLong(strArray[5], 16));
            List<AbstractHD.PathTypeIndex> pathTypeIndexList = new ArrayList<AbstractHD.PathTypeIndex>();
            List<String> hashList = new ArrayList<String>();
            for (int i = 6;
                 i < strArray.length;
                 i++) {
                String text = strArray[i];

                if (!Utils.isEmpty(text)) {
                    String[] hashPathTypeIndex = text.split(QRCodeUtil.QR_CODE_SECONDARY_SPLIT_ESCAPE);
                    AbstractHD.PathTypeIndex pathTypeIndex = new AbstractHD.PathTypeIndex();
                    pathTypeIndex.pathType = AbstractHD.getTernalRootType(Integer.valueOf(hashPathTypeIndex[0]));
                    pathTypeIndex.index = Integer.valueOf(hashPathTypeIndex[1]);
                    pathTypeIndexList.add(pathTypeIndex);
                    hashList.add(hashPathTypeIndex[2]);
                }
            }
            qrCodeTransport.setPathTypeIndexes(pathTypeIndexList);
            qrCodeTransport.setHashList(hashList);
            return qrCodeTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static QRCodeTxTransport noChangeFormatDesktopHDMQRCodeTransport(String str) {
        try {
            String[] strArray = QRCodeUtil.splitString(str);
            if (Utils.validBicoinAddress(strArray[0])) {
                return oldFormatQRCodeTransport(str);
            }
            QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
            String address = Base58.hexToBase58WithAddress(strArray[0]);

            if (!Utils.validBicoinAddress(address)) {
                return null;
            }
            qrCodeTransport.setMyAddress(address);
            qrCodeTransport.setFee(Long.parseLong(strArray[1], 16));
            qrCodeTransport.setToAddress(Base58.hexToBase58WithAddress(strArray[2]));
            qrCodeTransport.setTo(Long.parseLong(strArray[3], 16));
            List<String> hashList = new ArrayList<String>();
            List<AbstractHD.PathTypeIndex> pathTypeIndexList = new ArrayList<AbstractHD.PathTypeIndex>();
            for (int i = 4;
                 i < strArray.length;
                 i++) {
                String text = strArray[i];
                if (!Utils.isEmpty(text)) {
                    String[] hashPathTypeIndex = text.split(QRCodeUtil.QR_CODE_SECONDARY_SPLIT_ESCAPE);
                    AbstractHD.PathTypeIndex pathTypeIndex = new AbstractHD.PathTypeIndex();
                    pathTypeIndex.pathType = AbstractHD.getTernalRootType(Integer.valueOf(hashPathTypeIndex[0]));
                    pathTypeIndex.index = Integer.valueOf(hashPathTypeIndex[1]);
                    pathTypeIndexList.add(pathTypeIndex);
                    hashList.add(hashPathTypeIndex[2]);
                }
            }
            qrCodeTransport.setHashList(hashList);
            qrCodeTransport.setPathTypeIndexes(pathTypeIndexList);
            return qrCodeTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static QRCodeTxTransport formatQRCodeTransportOfDesktopHDM(String str) {
        try {
            QRCodeTxTransport qrCodeTxTransport = null;
            TxTransportType txTransportType = null;
//            int hdmIndex = QRCodeTxTransport.NO_HDM_INDEX;
            String[] strArray = QRCodeUtil.splitString(str);
            String str1 = strArray[0];
            if (hasVersion(str1)) {
                String versionStr = str1.replace(TX_TRANSPORT_VERSION, "");
                int version = Integer.valueOf(versionStr);
                txTransportType = getTxTransportType(version);
                str = str.substring(strArray[0].length() + 1);
                strArray = QRCodeUtil.splitString(str);
            }
//            boolean isHDM = !isAddressHex(strArray[0]);
//            if (isHDM) {
//                hdmIndex = Integer.parseInt(strArray[0], 16);
//                str = str.substring(strArray[0].length() + 1);
//                strArray = QRCodeUtil.splitString(str);
//            }
            boolean hasChangeAddress = isAddressHex(strArray[1]);
            if (hasChangeAddress) {
                qrCodeTxTransport = changeFormatQRCodeTransportOfDesktopHDM(str);

            } else {
                qrCodeTxTransport = noChangeFormatDesktopHDMQRCodeTransport(str);
            }
            qrCodeTxTransport.setTxTransportType(txTransportType);


            return qrCodeTxTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static QRCodeTxTransport formatQRCodeTransport(String str) {
        try {
            QRCodeTxTransport qrCodeTxTransport;
            TxTransportType txTransportType = null;
            int hdmIndex = QRCodeTxTransport.NO_HDM_INDEX;
            String[] strArray = QRCodeUtil.splitString(str);
            String str1 = strArray[0];
            if (hasVersion(str1)) {
                String versionStr = str1.replace(TX_TRANSPORT_VERSION, "");
                int version = Integer.valueOf(versionStr);
                txTransportType = getTxTransportType(version);
                str = str.substring(strArray[0].length() + 1);
                strArray = QRCodeUtil.splitString(str);
            }
            boolean isHDM = !isAddressHex(strArray[0]);
            if (isHDM) {
                hdmIndex = Integer.parseInt(strArray[0], 16);
                str = str.substring(strArray[0].length() + 1);
                strArray = QRCodeUtil.splitString(str);
            }
            boolean hasChangeAddress = isAddressHex(strArray[1]);
            if (hasChangeAddress) {
                qrCodeTxTransport = changeFormatQRCodeTransport(str);
            } else {
                qrCodeTxTransport = noChangeFormatQRCodeTransport(str);
            }
            qrCodeTxTransport.setHdmIndex(hdmIndex);
            qrCodeTxTransport.setTxTransportType(txTransportType);
            if (txTransportType == TxTransportType.ColdHD) {
                List<String> strs = qrCodeTxTransport.getHashList();
                ArrayList<String> hashes = new ArrayList<String>();
                ArrayList<AbstractHD.PathTypeIndex> paths = new ArrayList<AbstractHD
                        .PathTypeIndex>();
                for (String s : strs) {
                    String[] hs = s.split(QRCodeUtil.QR_CODE_SECONDARY_SPLIT_ESCAPE);
                    AbstractHD.PathTypeIndex path = new AbstractHD.PathTypeIndex();
                    path.pathType = AbstractHD.getTernalRootType(Integer.valueOf(hs[0]));
                    path.index = Integer.valueOf(hs[1]);
                    paths.add(path);
                    hashes.add(hs[2]);
                }
                qrCodeTxTransport.setHashList(hashes);
                qrCodeTxTransport.setPathTypeIndexes(paths);
            }
            return qrCodeTxTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }


    private static QRCodeTxTransport changeFormatQRCodeTransport(String str) {
        try {
            String[] strArray = QRCodeUtil.splitString(str);
            QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();

            String address = Base58.hexToBase58WithAddress(strArray[0]);
            if (!Utils.validBicoinAddress(address)) {
                return null;
            }
            qrCodeTransport.setMyAddress(address);
            String changeAddress = Base58.hexToBase58WithAddress(strArray[1]);
            if (!Utils.validBicoinAddress(changeAddress)) {
                return null;
            }
            qrCodeTransport.setChangeAddress(changeAddress);
            qrCodeTransport.setChangeAmt(Long.parseLong(strArray[2], 16));
            qrCodeTransport.setFee(Long.parseLong(strArray[3], 16));
            String toAddress = Base58.hexToBase58WithAddress(strArray[4]);
            if (!Utils.validBicoinAddress(toAddress)) {
                return null;
            }
            qrCodeTransport.setToAddress(toAddress);
            qrCodeTransport.setTo(Long.parseLong(strArray[5], 16));
            List<String> hashList = new ArrayList<String>();
            for (int i = 6;
                 i < strArray.length;
                 i++) {
                String text = strArray[i];
                if (!Utils.isEmpty(text)) {
                    hashList.add(text);
                }
            }
            qrCodeTransport.setHashList(hashList);
            return qrCodeTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static QRCodeTxTransport noChangeFormatQRCodeTransport(String str) {
        try {
            String[] strArray = QRCodeUtil.splitString(str);
            if (Utils.validBicoinAddress(strArray[0])) {
                return oldFormatQRCodeTransport(str);
            }
            QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
            String address = Base58.hexToBase58WithAddress(strArray[0]);

            if (!Utils.validBicoinAddress(address)) {
                return null;
            }
            qrCodeTransport.setMyAddress(address);
            qrCodeTransport.setFee(Long.parseLong(strArray[1], 16));
            qrCodeTransport.setToAddress(Base58.hexToBase58WithAddress(strArray[2]));
            qrCodeTransport.setTo(Long.parseLong(strArray[3], 16));
            List<String> hashList = new ArrayList<String>();
            for (int i = 4;
                 i < strArray.length;
                 i++) {
                String text = strArray[i];
                if (!Utils.isEmpty(text)) {
                    hashList.add(text);
                }
            }
            qrCodeTransport.setHashList(hashList);
            return qrCodeTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static QRCodeTxTransport oldFormatQRCodeTransport(String str) {
        try {
            String[] strArray = QRCodeUtil.splitString(str);
            QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
            String address = strArray[0];
            if (!Utils.validBicoinAddress(address)) {
                return null;
            }
            qrCodeTransport.setMyAddress(address);
            qrCodeTransport.setFee(Long.parseLong(strArray[1], 16));
            qrCodeTransport.setToAddress(strArray[2]);
            qrCodeTransport.setTo(Long.parseLong(strArray[3], 16));
            List<String> hashList = new ArrayList<String>();
            for (int i = 4;
                 i < strArray.length;
                 i++) {
                String text = strArray[i];
                if (!Utils.isEmpty(text)) {
                    hashList.add(text);
                }
            }
            qrCodeTransport.setHashList(hashList);
            return qrCodeTransport;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static QRCodeTxTransport oldFromSendRequestWithUnsignedTransaction(Tx tx,
                                                                               String addressCannotParsed) {
        QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
        qrCodeTransport.setMyAddress(tx.getFromAddress());
        String toAddress = tx.getFirstOutAddress();
        if (Utils.isEmpty(toAddress)) {
            toAddress = addressCannotParsed;
        }
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

    public static String oldGetPreSignString(Tx tx, String addressCannotParsed) {
        QRCodeTxTransport qrCodeTransport = oldFromSendRequestWithUnsignedTransaction(tx,
                addressCannotParsed);
        String preSignString = qrCodeTransport.getMyAddress() + QRCodeUtil.OLD_QR_CODE_SPLIT +
                Long.toHexString(qrCodeTransport.getFee()).toLowerCase(Locale.US) + QRCodeUtil
                .OLD_QR_CODE_SPLIT + qrCodeTransport.getToAddress() + QRCodeUtil
                .OLD_QR_CODE_SPLIT + Long.toHexString(qrCodeTransport.getTo()).toLowerCase(Locale
                .US) + QRCodeUtil.OLD_QR_CODE_SPLIT;
        for (int i = 0;
             i < qrCodeTransport.getHashList().size();
             i++) {
            String hash = qrCodeTransport.getHashList().get(i);
            if (i < qrCodeTransport.getHashList().size() - 1) {
                preSignString = preSignString + hash + QRCodeUtil.OLD_QR_CODE_SPLIT;
            } else {
                preSignString = preSignString + hash;
            }
        }

        return preSignString;
    }

    private static boolean isAddressHex(String str) {
        boolean isAddress = false;
        if (str.length() % 2 == 0) {
            try {
                String address = Base58.hexToBase58WithAddress(str);
                isAddress = Utils.validBicoinAddress(address);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return isAddress;
    }

    private static QRCodeTxTransport fromSendRequestWithUnsignedTransaction(Tx tx,
                                                                            String addressCannotParsed,
                                                                            int hdmIndex, TxTransportType txTransportType) {
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
        if (hdmIndex < 0) {
            for (byte[] h : tx.getUnsignedInHashes()) {
                hashList.add(Utils.bytesToHexString(h));
            }
        } else {
            if (txTransportType == TxTransportType.ColdHDM) {
                EnterpriseHDMAddress a = null;
                for (EnterpriseHDMAddress address : AddressManager.getInstance().getEnterpriseHDMKeychain()
                        .getAddresses()) {
                    if (address.getIndex() == hdmIndex) {
                        a = address;
                        break;
                    }
                }
                for (byte[] h : tx.getUnsignedInHashesForHDM(a.getPubKey())) {
                    hashList.add(Utils.bytesToHexString(h));
                }
            } else {
                HDMAddress a = null;
                for (HDMAddress address : AddressManager.getInstance().getHdmKeychain()
                        .getAllCompletedAddresses()) {
                    if (address.getIndex() == hdmIndex) {
                        a = address;
                        break;
                    }
                }
                for (byte[] h : tx.getUnsignedInHashesForHDM(a.getPubKey())) {
                    hashList.add(Utils.bytesToHexString(h));
                }
            }
        }
        qrCodeTransport.setHashList(hashList);
        return qrCodeTransport;
    }


    private static QRCodeTxTransport fromDeskpHDMSendRequestWithUnsignedTransaction(TxTransportType txTransportType, Tx tx, List<DesktopHDMAddress> desktopHDMAddresses,
                                                                                    String addressCannotParsed) {
        if (!AddressManager.getInstance().hasDesktopHDMKeychain()) {
            return null;
        }
        QRCodeTxTransport qrCodeTransport = new QRCodeTxTransport();
        qrCodeTransport.setMyAddress(tx.getFromAddress());
        String toAddress = tx.getFirstOutAddress();
        if (Utils.isEmpty(toAddress)) {
            toAddress = addressCannotParsed;
        }

        qrCodeTransport.setToAddress(toAddress);
        qrCodeTransport.setTo(tx.amountSentToAddress(toAddress));
        qrCodeTransport.setFee(tx.getFee());
        List<String> hashList = new ArrayList<String>();
        if (txTransportType == TxTransportType.DesktopHDM) {

            for (int i = 0; i < desktopHDMAddresses.size(); i++) {
                DesktopHDMAddress desktopHDMAddress = desktopHDMAddresses.get(i);
                for (byte[] h : tx.getUnsignedInHashesForDesktpHDM(desktopHDMAddress.getPubKey(), i)) {
                    String[] strings = new String[]{Integer.toString(desktopHDMAddress.getPathType().getValue()),
                            Integer.toString(desktopHDMAddress.getIndex()), Utils.bytesToHexString(h)};
                    hashList.add(Utils.joinString(strings, QRCodeUtil.QR_CODE_SECONDARY_SPLIT));
                }

            }
        }
        qrCodeTransport.setHashList(hashList);
        return qrCodeTransport;
    }

    public static String getDeskpHDMPresignTxString(TxTransportType txTransportType, Tx tx, String changeAddress,
                                                    String addressCannotParsed, List<DesktopHDMAddress> desktopHDMAddresses) {
        QRCodeTxTransport qrCodeTransport = fromDeskpHDMSendRequestWithUnsignedTransaction(txTransportType, tx, desktopHDMAddresses,
                addressCannotParsed);
        String preSignString = "";
        try {
            String versionStr = "";
            if (txTransportType != null) {
                versionStr = TX_TRANSPORT_VERSION + txTransportType.getType();
            }
            String changeStr = "";
            if (!Utils.isEmpty(changeAddress)) {
                long changeAmt = tx.amountSentToAddress(changeAddress);
                if (changeAmt != 0) {
                    String[] changeStrings = new String[]{Base58.bas58ToHexWithAddress
                            (changeAddress), Long.toHexString(changeAmt)};
                    changeStr = Utils.joinString(changeStrings, QRCodeUtil.QR_CODE_SPLIT);

                }
            }
            String hdmIndexString = "";
            if (qrCodeTransport.getHdmIndex() != QRCodeTxTransport.NO_HDM_INDEX) {
                hdmIndexString = Integer.toHexString(qrCodeTransport.getHdmIndex());
            }
            String[] preSigns = new String[]{versionStr, hdmIndexString, Base58.bas58ToHexWithAddress
                    (qrCodeTransport.getMyAddress()), changeStr, Long.toHexString(qrCodeTransport
                    .getFee()), Base58.bas58ToHexWithAddress(qrCodeTransport.getToAddress()),
                    Long.toHexString(qrCodeTransport.getTo())};
            preSignString = Utils.joinString(preSigns, QRCodeUtil.QR_CODE_SPLIT);
            String[] hashStrings = new String[qrCodeTransport.getHashList().size()];
            hashStrings = qrCodeTransport.getHashList().toArray(hashStrings);
            preSignString = preSignString + QRCodeUtil.QR_CODE_SPLIT + Utils.joinString
                    (hashStrings, QRCodeUtil.QR_CODE_SPLIT);
            preSignString.toUpperCase(Locale.US);
        } catch (AddressFormatException e) {
            e.printStackTrace();
        }

        return preSignString;

    }

    public static String getPresignTxString(Tx tx, String changeAddress,
                                            String addressCannotParsed, int hdmIndex) {
        return getPresignTxString(tx, changeAddress, addressCannotParsed, hdmIndex, null);
    }

    public static String getPresignTxString(Tx tx, String changeAddress,
                                            String addressCannotParsed, int hdmIndex, TxTransportType txTransportType) {
        QRCodeTxTransport qrCodeTransport = fromSendRequestWithUnsignedTransaction(tx,
                addressCannotParsed, hdmIndex, txTransportType);
        String preSignString = "";
        try {
            String versionStr = "";
            if (txTransportType != null) {
                versionStr = TX_TRANSPORT_VERSION + txTransportType.getType();
            }
            String changeStr = "";
            if (!Utils.isEmpty(changeAddress)) {
                long changeAmt = tx.amountSentToAddress(changeAddress);
                if (changeAmt != 0) {
                    String[] changeStrings = new String[]{Base58.bas58ToHexWithAddress
                            (changeAddress), Long.toHexString(changeAmt)};
                    changeStr = Utils.joinString(changeStrings, QRCodeUtil.QR_CODE_SPLIT);

                }
            }
            String hdmIndexString = "";
            if (qrCodeTransport.getHdmIndex() != QRCodeTxTransport.NO_HDM_INDEX) {
                hdmIndexString = Integer.toHexString(qrCodeTransport.getHdmIndex());
            }
            String[] preSigns = new String[]{versionStr, hdmIndexString, Base58.bas58ToHexWithAddress
                    (qrCodeTransport.getMyAddress()), changeStr, Long.toHexString(qrCodeTransport
                    .getFee()), Base58.bas58ToHexWithAddress(qrCodeTransport.getToAddress()),
                    Long.toHexString(qrCodeTransport.getTo())};
            preSignString = Utils.joinString(preSigns, QRCodeUtil.QR_CODE_SPLIT);
            String[] hashStrings = new String[qrCodeTransport.getHashList().size()];
            hashStrings = qrCodeTransport.getHashList().toArray(hashStrings);
            preSignString = preSignString + QRCodeUtil.QR_CODE_SPLIT + Utils.joinString
                    (hashStrings, QRCodeUtil.QR_CODE_SPLIT);
            preSignString.toUpperCase(Locale.US);
        } catch (AddressFormatException e) {
            e.printStackTrace();
        }

        return preSignString;
    }

    private static boolean hasVersion(String str) {
        String pattern = "[V][\\d{1,3}]";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(str);
        return m.matches();
    }

}
