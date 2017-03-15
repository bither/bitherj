package net.bither.bitherj.crypto.mnemonic;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Hzz on 2017/3/14.
 */

public enum MnemonicWordList {
    English, ZhCN, ZhTw;

    private static final String ENGLISH = "English";
    private static final String ZH_CN = "ZhCN";
    private static final String ZH_TW = "ZhTw";
    private static final String EN_HD_QR_CODE_FLAG = "%";
    private static final String ZH_CN_HD_QR_CODE_FLAG = "%1%";
    private static final String ZH_TW_HD_QR_CODE_FLAG = "%2%";

    public String getHdQrCodeFlag() {
        switch (this) {
            case English:
                return EN_HD_QR_CODE_FLAG;
            case ZhCN:
                return ZH_CN_HD_QR_CODE_FLAG;
            case ZhTw:
                return ZH_TW_HD_QR_CODE_FLAG;
        }
        return EN_HD_QR_CODE_FLAG;
    }

    public String getMnemonicWordListValue() {
        switch (this) {
            case English:
                return ENGLISH;
            case ZhCN:
                return ZH_CN;
            case ZhTw:
                return ZH_TW;
        }
        return ENGLISH;
    }

    static public MnemonicWordList getMnemonicWordList(String value) {
        for (MnemonicWordList wordList: getAllMnemonicWordLists()) {
           if (wordList.getMnemonicWordListValue().equals(value)) {
               return wordList;
           }
        }
        return English;
    }

    static public ArrayList<MnemonicWordList> getAllMnemonicWordLists() {
        ArrayList<MnemonicWordList> mnemonicWordLists = new ArrayList<MnemonicWordList>();
        mnemonicWordLists.add(English);
        mnemonicWordLists.add(ZhCN);
        mnemonicWordLists.add(ZhTw);
        return mnemonicWordLists;
    }

    static public MnemonicWordList getMnemonicWordListForHdSeed(String string) {
        int zhCnHdQrCodeFlagLength = getHdQrCodeFlagLength(string, MnemonicWordList.ZhCN);
        if (zhCnHdQrCodeFlagLength > 0) {
            return MnemonicWordList.ZhCN;
        }

        int zhTwHdQrCodeFlagLength = getHdQrCodeFlagLength(string, MnemonicWordList.ZhTw);
        if (zhTwHdQrCodeFlagLength > 0) {
            return MnemonicWordList.ZhTw;
        }

        int enHdQrCodeFlagLength = getHdQrCodeFlagLength(string, MnemonicWordList.English);
        if (enHdQrCodeFlagLength > 0) {
            return MnemonicWordList.English;
        }
        return null;
    }

    static public int getHdQrCodeFlagLength(String string, MnemonicWordList wordList) {
        String hdQrCodeFlag = wordList.getHdQrCodeFlag();
        if (string.length() < hdQrCodeFlag.length()) { return 0; }
        String prefixStr = string.substring(0, hdQrCodeFlag.length());
        return hdQrCodeFlag.equals(prefixStr) ? hdQrCodeFlag.length() : 0;
    }
}

