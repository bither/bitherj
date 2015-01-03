package net.bither.bitherj.core;

import net.bither.bitherj.crypto.TransactionSignature;
import net.bither.bitherj.script.ScriptBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhouqi on 15/1/3.
 */
public class HDMAddress extends Address {
    public HDMAddress(String address, byte[] pubKey, long sortTime, boolean isSyncComplete, boolean isFromXRandom, boolean hasPrivKey) {
        super(address, pubKey, sortTime, isSyncComplete, isFromXRandom, hasPrivKey);
    }

    public List<byte[]> formatInScript(List<TransactionSignature> signs1, List<TransactionSignature> signs2, byte[] scriptPubKey) {
        List<byte[]> result = new ArrayList<byte[]>();
        for (int i = 0; i < signs1.size(); i++) {
            List<TransactionSignature> signs = new ArrayList<TransactionSignature>(2);
            signs.add(signs1.get(i));
            signs.add(signs2.get(i));
            result.add(ScriptBuilder.createP2SHMultiSigInputScript(signs, scriptPubKey).getProgram());

        }
        return result;
    }
}
