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
}

