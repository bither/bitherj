package net.bither.bitherj.utils;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.crypto.hd.DeterministicKey;

/**
 * Created by Hzz on 2018/9/12.
 */

public class HDAccountUtils {

    public static byte[] getRedeemScript(byte[] pubKey) {
        byte[] redeem = Utils.sha256hash160(pubKey);
        byte[] redeemLengthByte = new VarInt(redeem.length).encode();
        byte[] prefByte = {0x00};
        int prefLength = redeem.length + redeemLengthByte.length + prefByte.length;
        byte[] redeemScriptLengthB = new VarInt(prefLength).encode();
        int redeemScriptLength = prefLength + redeemScriptLengthB.length;
        byte[] redeemScript = new byte[redeemScriptLength];
        System.arraycopy(redeemScriptLengthB, 0, redeemScript, 0, redeemScriptLengthB.length);
        System.arraycopy(prefByte, 0, redeemScript, redeemScriptLengthB.length, prefByte.length);
        System.arraycopy(redeemLengthByte, 0, redeemScript, redeemScriptLengthB.length + prefByte.length, redeemLengthByte.length);
        System.arraycopy(redeem, 0, redeemScript, redeemScriptLengthB.length + prefByte.length + redeemLengthByte.length, redeem.length);
        return redeemScript;
    }

    public static byte[] getSign(DeterministicKey key, byte[] unsignedHash) {
        TransactionSignature sign = new TransactionSignature(key.sign(unsignedHash), TransactionSignature.SigHash.ALL, false);
        return sign.encodeToBitcoin();
    }

    public static byte[] getWitness(byte[] pubKey, byte[] sign) {
        byte[] prefix = {0x02};
        byte[] signScript = getBtScript(sign);
        byte[] pubKeyScript = getBtScript(pubKey);
        byte[] witness = new byte[prefix.length + signScript.length + pubKeyScript.length];
        System.arraycopy(prefix, 0, witness, 0, prefix.length);
        System.arraycopy(signScript, 0, witness, prefix.length, signScript.length);
        System.arraycopy(pubKeyScript, 0, witness, prefix.length + signScript.length, pubKeyScript.length);
        return witness;
    }

    public static byte[] getBtScript(byte[] add) {
        byte[] length = new VarInt(add.length).encode();
        byte[] script = new byte[length.length + add.length];
        System.arraycopy(length, 0, script, 0, length.length);
        System.arraycopy(add, 0, script, length.length, add.length);
        return script;
    }

}
