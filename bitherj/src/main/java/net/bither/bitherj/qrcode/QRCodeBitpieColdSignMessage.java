package net.bither.bitherj.qrcode;

import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.BitpieColdCoin;
import net.bither.bitherj.core.BitpieHDAccountCold;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.exception.BitpieColdNoSupportCoinException;
import net.bither.bitherj.utils.Utils;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.bither.bitherj.qrcode.QRCodeUtil.HD_MONITOR_QR_SPLIT;

public class QRCodeBitpieColdSignMessage implements Serializable {

    public enum SignMessageType {
        LoginSign(1), ChangeCoinGetXpub(2), ChangeCoinSign(3);

        private int type;

        SignMessageType(int type) {
            this.type = type;
        }

        public int getType() {
            return type;
        }
    }

    public static SignMessageType getSignMessageType(int type) {
        switch (type) {
            case 1:
                return SignMessageType.LoginSign;
            case 2:
                return SignMessageType.ChangeCoinGetXpub;
            case 3:
                return SignMessageType.ChangeCoinSign;
            default:
                return null;
        }
    }

    public static final String SIGN_MESSAGE_VERSION = "S";
    private BitpieColdCoin bitpieColdCoin;
    private String coinDisplayCode;
    private String btcFirstAddress;
    private String unsignedMsg;
    private SignMessageType signMessageType;
    private boolean isOnlyGetXpub;

    public BitpieColdCoin getBitpieColdCoin() {
        return bitpieColdCoin;
    }

    public String getCoinDisplayCode() {
        return coinDisplayCode;
    }

    public String getBtcFirstAddress() {
        return btcFirstAddress;
    }

    public SignMessageType getSignMessageType() {
        return signMessageType;
    }

    public boolean isOnlyGetXpub() {
        return isOnlyGetXpub;
    }

    public static QRCodeBitpieColdSignMessage formatQRCode(String str) throws Exception {
        if (Utils.isEmpty(str) || !str.startsWith(SIGN_MESSAGE_VERSION)) {
            return null;
        }
        SignMessageType signMessageType;
        String[] strArray = str.split(HD_MONITOR_QR_SPLIT);
        String str1 = strArray[0];
        if (hasVersion(str1)) {
            String versionStr = str1.replace(SIGN_MESSAGE_VERSION, "");
            int version = Integer.valueOf(versionStr);
            signMessageType = getSignMessageType(version);
            str = str.substring(strArray[0].length() + 1);
            strArray = str.split(HD_MONITOR_QR_SPLIT);
        } else {
            return null;
        }
        if (signMessageType == null) {
            return null;
        }
        QRCodeBitpieColdSignMessage qrCodeBitpieColdSignMessage = new QRCodeBitpieColdSignMessage();
        qrCodeBitpieColdSignMessage.signMessageType = signMessageType;
        qrCodeBitpieColdSignMessage.btcFirstAddress = strArray[0];
        switch (signMessageType) {
            case LoginSign:
                qrCodeBitpieColdSignMessage.unsignedMsg = strArray[1];
                break;
            case ChangeCoinGetXpub:
            case ChangeCoinSign:
                BitpieColdCoin bitpieColdCoin = BitpieColdCoin.fromValue(strArray[1]);
                if (bitpieColdCoin == null) {
                    throw new BitpieColdNoSupportCoinException();
                }
                qrCodeBitpieColdSignMessage.bitpieColdCoin = bitpieColdCoin;
                qrCodeBitpieColdSignMessage.coinDisplayCode = strArray[2];
                if (signMessageType == SignMessageType.ChangeCoinSign) {
                    qrCodeBitpieColdSignMessage.unsignedMsg = strArray[3];
                } else {
                    qrCodeBitpieColdSignMessage.isOnlyGetXpub = strArray[3].equals("1") ? true : false;
                }
                break;
        }
        return qrCodeBitpieColdSignMessage;
    }

    public String getBitherQrCodeStr(SecureCharSequence password) {
        String[] preQrCodeStrs;
        BitpieHDAccountCold bitpieHDAccountCold = AddressManager.getInstance().getBitpieHDAccountCold();
        String btcFirstAddress = bitpieHDAccountCold.getFirstAddressFromDb();
        String versionStr = SIGN_MESSAGE_VERSION + signMessageType.getType();
        switch (signMessageType) {
            case LoginSign:
                DeterministicKey loginNormalKey = bitpieHDAccountCold.getExternalKey(0, password);
                DeterministicKey loginSegwitKey = bitpieHDAccountCold.getSegwitExternalKey(0, password);
                password.wipe();
                preQrCodeStrs = new String[]{versionStr, btcFirstAddress, loginNormalKey.signMessage(unsignedMsg), loginSegwitKey.signMessage(unsignedMsg)};
                break;
            case ChangeCoinGetXpub:
                try {
                    String changeCoinXpub = DeterministicKey.deserializeB58(bitpieHDAccountCold.xPubB58(password, bitpieColdCoin.getPathNumber())).serializePubB58();
                    password.wipe();
                    preQrCodeStrs = new String[]{versionStr, btcFirstAddress, bitpieColdCoin.code, changeCoinXpub};
                } catch (Exception e) {
                    e.printStackTrace();
                    password.wipe();
                    return null;
                }
                break;
            case ChangeCoinSign:
                String changeCoinXpub;
                try {
                    changeCoinXpub = DeterministicKey.deserializeB58(bitpieHDAccountCold.xPubB58(password, bitpieColdCoin.getPathNumber())).serializePubB58();
                } catch (Exception e) {
                    e.printStackTrace();
                    password.wipe();
                    return null;
                }
                DeterministicKey normalKey = bitpieHDAccountCold.getExternalKey(0, password);
                DeterministicKey changeKey = bitpieHDAccountCold.getExternalKey(0, bitpieColdCoin.getPathNumber(), password);
                password.wipe();
                preQrCodeStrs = new String[]{versionStr, btcFirstAddress, bitpieColdCoin.code, changeCoinXpub, normalKey.signMessage(unsignedMsg), changeKey.signMessage(unsignedMsg)};
                break;
            default:
                password.wipe();
                return null;
        }
        return Utils.joinString(preQrCodeStrs, HD_MONITOR_QR_SPLIT);
    }

    private static boolean hasVersion(String str) {
        String pattern = "[S][\\d{1,3}]";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(str);
        return m.matches();
    }

}
