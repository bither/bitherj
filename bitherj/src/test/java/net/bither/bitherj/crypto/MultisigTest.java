package net.bither.bitherj.crypto;

import net.bither.bitherj.script.Script;
import net.bither.bitherj.script.ScriptBuilder;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Created by zhouqi on 15/1/8.
 */
public class MultisigTest {
    @Test
    public void testAddress() {
        String pubHot = "026e3f39cd82606a3aa0d9c8194cf516b98ee51c1107e6c7f334cde22b5059e928";
        String pubCold = "034d490441de1cc4a8f1e7192083583c16e513b3b550c8410500db7853fd1fa5fe";
        String pubRemote = "0255b72bc52dfa0ffc40742b1a3eb01858714341c1f72bc1f8fdc731098323e96e";
        String address = "3K2Cbzxfoxey8cbq1w2YutLzhvxByxvNxy";

        ECKey keyHot = new ECKey(null, Utils.hexStringToByteArray(pubHot));
        ECKey keyCold = new ECKey(null, Utils.hexStringToByteArray(pubCold));
        ECKey keyRemote = new ECKey(null, Utils.hexStringToByteArray(pubRemote));
        List<byte[]> pubKeyList = new ArrayList<byte[]>();
        pubKeyList.add(keyHot.getPubKey());
        pubKeyList.add(keyCold.getPubKey());
        pubKeyList.add(keyRemote.getPubKey());

        Script script = ScriptBuilder.createMultiSigOutputScript(2, pubKeyList);
        String multisigAddress = Utils.toP2SHAddress(Utils.sha256hash160(script.getProgram()));

        assertEquals(address, multisigAddress);

        pubHot = "033dc6dcf7d90cb8f4ee3adbc87bf55c700d6c32a74800af6de6e1af57f46bfc41";
        pubCold = "025ed1f76ae3fc0cb84782131594020e885a060daf9f55c199fdb299e7169779b9";
        pubRemote = "0378b509c95fd7aa30dc82c4bbe8b84dcb8bb7d7224d891cce7ccf454c79527b5d";
        address = "3ELN8yYSGoz4fTy8HSbfgLRoDWBU6p9zev";

        keyHot = new ECKey(null, Utils.hexStringToByteArray(pubHot));
        keyCold = new ECKey(null, Utils.hexStringToByteArray(pubCold));
        keyRemote = new ECKey(null, Utils.hexStringToByteArray(pubRemote));
        pubKeyList = new ArrayList<byte[]>();
        pubKeyList.add(keyHot.getPubKey());
        pubKeyList.add(keyCold.getPubKey());
        pubKeyList.add(keyRemote.getPubKey());

        script = ScriptBuilder.createMultiSigOutputScript(2, pubKeyList);
        multisigAddress = Utils.toP2SHAddress(Utils.sha256hash160(script.getProgram()));

        assertEquals(address, multisigAddress);

        pubHot = "03d29143a6b76d393075d620df9cf80bbb5eaceb2e2b57e5cc4704a6eb3c125a8d";
        pubCold = "03f7d2d484d903fa498d6069009e77ed9ad0842947a7a58441f9406a4728ae2240";
        pubRemote = "02a5fc2584b879fa5a7b04e67d7ab8abb3b08d7981f9f24b03e9353355162c2e04";
        address = "34RgHSRfg3P7FSk3YBbcWnHaMWxapMtrWf";

        keyHot = new ECKey(null, Utils.hexStringToByteArray(pubHot));
        keyCold = new ECKey(null, Utils.hexStringToByteArray(pubCold));
        keyRemote = new ECKey(null, Utils.hexStringToByteArray(pubRemote));
        pubKeyList = new ArrayList<byte[]>();
        pubKeyList.add(keyHot.getPubKey());
        pubKeyList.add(keyCold.getPubKey());
        pubKeyList.add(keyRemote.getPubKey());

        script = ScriptBuilder.createMultiSigOutputScript(2, pubKeyList);
        multisigAddress = Utils.toP2SHAddress(Utils.sha256hash160(script.getProgram()));

        assertEquals(address, multisigAddress);
    }
}
