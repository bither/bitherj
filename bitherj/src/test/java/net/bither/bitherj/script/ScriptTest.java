/**
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.script;

import com.google.common.collect.Lists;

import net.bither.bitherj.core.In;
import net.bither.bitherj.core.OutPoint;
import net.bither.bitherj.core.Tx;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.exception.ScriptException;
import net.bither.bitherj.exception.VerificationException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.UnsafeByteArrayOutputStream;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static net.bither.bitherj.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.junit.Assert.*;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    static final String sigProg = "47304402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";
//    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();


//    static final NetworkParameters params = TestNet3Params.get();

    @Test
    public void testScriptSig() throws Exception {
        byte[] sigProgBytes = Utils.hexStringToByteArray(sigProg);
        Script script = new Script(sigProgBytes);
        // Test we can extract the from address.
        byte[] hash160 = Utils.sha256hash160(script.getPubKey());
//        Address a = new Address(params, hash160);
        String address = this.toAddress(hash160, 111);
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", address);
    }

    @Test
    public void testScriptPubKey() throws Exception {
        // Check we can extract the to address
        byte[] pubkeyBytes = Utils.hexStringToByteArray(pubkeyProg);
        Script pubkey = new Script(pubkeyBytes);
        assertEquals("DUP HASH160 PUSHDATA(20)[33e81a941e64cda12c6a299ed322ddbdd03f8d0e] EQUALVERIFY CHECKSIG", pubkey.toString());
//        Address toAddr = new Address(params, pubkey.getPubKeyHash());
        String toAddr = this.toAddress(pubkey.getPubKeyHash(), 111);
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", toAddr);
    }

    @Test
    public void testMultiSig() throws Exception {
        SecureRandom random = new SecureRandom();
        List<ECKey> keys = Lists.newArrayList(ECKey.generateECKey(random), ECKey.generateECKey(random), ECKey.generateECKey(random));
        List<byte[]> pubs = new ArrayList<byte[]>();
        for (ECKey key : keys) {
            pubs.add(key.getPubKey());
        }
        assertTrue(ScriptBuilder.createMultiSigOutputScript(2, pubs).isSentToMultiSig());
        assertTrue(ScriptBuilder.createMultiSigOutputScript(3, pubs).isSentToMultiSig());
        assertFalse(ScriptBuilder.createOutputScript(ECKey.generateECKey(random)).isSentToMultiSig());
        try {
            // Fail if we ask for more signatures than keys.
            Script.createMultiSigOutputScript(4, keys);
            fail();
        } catch (Throwable e) {
            // Expected.
        }
        try {
            // Must have at least one signature required.
            Script.createMultiSigOutputScript(0, keys);
        } catch (Throwable e) {
            // Expected.
        }
        // Actual execution is tested by the data driven tests.
    }

    @Test
    public void testP2SHOutputScript() throws Exception {
//        Address p2shAddress = new Address(MainNetParams.get(), "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU");
//        assertTrue(ScriptBuilder.createOutputScript(p2shAddress).isPayToScriptHash());
    }

    @Test
    public void testIp() throws Exception {
        byte[] bytes = Utils.hexStringToByteArray("41043e96222332ea7848323c08116dddafbfa917b8e37f0bdf63841628267148588a09a43540942d58d49717ad3fabfe14978cf4f0a8b84d2435dad16e9aa4d7f935ac");
        Script s = new Script(bytes);
        assertTrue(s.isSentToRawPubKey());
    }

//    public void testCreateMultiSigInputScript() throws AddressFormatException {
//        // Setup transaction and signatures
//        byte[] bytes1 = Base58.decodeChecked("cVLwRLTvz3BxDAWkvS3yzT9pUcTCup7kQnfT2smRjvmmm1wAP6QT");
//        bytes1[0] = (byte) 128;
//        String s1 = Base58.encodeChecked(bytes1);
//        bytes1 = Base58.decodeChecked("cTine92s8GLpVqvebi8rYce3FrUYq78ZGQffBYCS1HmDPJdSTxUo");
//        bytes1[0] = (byte) 128;
//        String s2 = Base58.encodeChecked(bytes1);
//        bytes1 = Base58.decodeChecked("cVHwXSPRZmL9adctwBwmn4oTZdZMbaCsR5XF6VznqMgcvt1FDDxg");
//        bytes1[0] = (byte) 128;
//        String s3 = Base58.encodeChecked(bytes1);
//
//        ECKey key1 = new DumpedPrivateKey("L4ywxRU5YyVh3j3VY2Erd8ekrP9oFN24LkWyvTJvEp7mWGsw4Sjj").getKey();
//        ECKey key2 = new DumpedPrivateKey("L3MoBE31hCeZLQTPDJKjBJ8yddB9Af2sCNXC57jvWB7D8ZZYARid").getKey();
//        ECKey key3 = new DumpedPrivateKey("L4vx4XPa8hdtRC9dYn8eQkJPwQFww87BM3Nmz5YHLF2cg8w5cUCs").getKey();
//        Script multisigScript = ScriptBuilder.createMultiSigOutputScript(2, Arrays.asList(key1, key2, key3));
//        byte[] bytes = Utils.hexStringToByteArray("01000000013df681ff83b43b6585fa32dd0e12b0b502e6481e04ee52ff0fdaf55a16a4ef61000000006b483045022100a84acca7906c13c5895a1314c165d33621cdcf8696145080895cbf301119b7cf0220730ff511106aa0e0a8570ff00ee57d7a6f24e30f592a10cae1deffac9e13b990012102b8d567bcd6328fd48a429f9cf4b315b859a58fd28c5088ef3cb1d98125fc4e8dffffffff02364f1c00000000001976a91439a02793b418de8ec748dd75382656453dc99bcb88ac40420f000000000017a9145780b80be32e117f675d6e0ada13ba799bf248e98700000000");
//        Tx transaction = new Tx(bytes);
//        Out output = transaction.getOuts().get(1);
//        Tx spendTx = new Tx();
////        Address address = new Address(params, "n3CFiCmBXVt5d3HXKQ15EFZyhPz4yj5F3H");
//        byte[] b = Base58.decode("n3CFiCmBXVt5d3HXKQ15EFZyhPz4yj5F3H");
//        byte[] b2 = new byte[20];
//        System.arraycopy(b, 1, b2, 0, 20);
//        String address = this.toAddress(b2, 111);
//        Script outputScript = ScriptBuilder.createOutputScript(address);
//        spendTx.addOutput(output.getOutValue(), outputScript);
//        spendTx.addInput(output);
//        Sha256Hash sighash = new Sha256Hash(spendTx.hashForSignature(0, multisigScript, TransactionSignature.SigHash.ALL, false));
//        ECKey.ECDSASignature party1Signature = key1.sign(sighash.getBytes());
//        ECKey.ECDSASignature party2Signature = key2.sign(sighash.getBytes());
//        TransactionSignature party1TransactionSignature = new TransactionSignature(party1Signature, TransactionSignature.SigHash.ALL, false);
//        TransactionSignature party2TransactionSignature = new TransactionSignature(party2Signature, TransactionSignature.SigHash.ALL, false);
//
//        // Create p2sh multisig input script
//        Script inputScript = ScriptBuilder.createP2SHMultiSigInputScript(ImmutableList.of(party1TransactionSignature, party2TransactionSignature), multisigScript.getProgram());
//
//        // Assert that the input script contains 4 chunks
//        assertTrue(inputScript.getChunks().size() == 4);
//
//        // Assert that the input script created contains the original multisig
//        // script as the last chunk
//        ScriptChunk scriptChunk = inputScript.getChunks().get(inputScript.getChunks().size() - 1);
//        Assert.assertTrue(Arrays.equals(scriptChunk.data, multisigScript.getProgram()));
//
//        // Create regular multisig input script
//        inputScript = ScriptBuilder.createMultiSigInputScript(ImmutableList.of(party1TransactionSignature, party2TransactionSignature));
//
//        // Assert that the input script only contains 3 chunks
//        assertTrue(inputScript.getChunks().size() == 3);
//
//        // Assert that the input script created does not end with the original
//        // multisig script
//        scriptChunk = inputScript.getChunks().get(inputScript.getChunks().size() - 1);
//        Assert.assertTrue(Arrays.equals(scriptChunk.data, multisigScript.getProgram()));
////        Assert.assertThat(scriptChunk.data, IsNot.not(IsEqual.equalTo(multisigScript.getProgram())));
//    }

    private Script parseScriptString(String string) throws Exception {
        String[] words = string.split("[ \\t\\n]");

        UnsafeByteArrayOutputStream out = new UnsafeByteArrayOutputStream();

        for (String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int) val));
                else
                    Script.writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(Utils.hexStringToByteArray(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(Charset.forName("UTF-8")));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                throw new RuntimeException("Invalid Data");
            }
        }

        return new Script(out.toByteArray());
    }

    @Test
    public void testDataDrivenValidScripts() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("script_valid.json"), Charset.forName("UTF-8")));
//        NetworkParameters params = TestNet3Params.get();

        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        String script = "";
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            script += line;
            if (line.equals("]") && script.equals("]") && !in.ready())
                break; // ignore last ]
            if (line.trim().endsWith("],") || line.trim().endsWith("]")) {
                String[] scripts = script.split(",");

                scripts[0] = scripts[0].replaceAll("[\"\\[\\]]", "").trim();
                scripts[1] = scripts[1].replaceAll("[\"\\[\\]]", "").trim();
                Script scriptSig = parseScriptString(scripts[0]);
                Script scriptPubKey = parseScriptString(scripts[1]);

                try {
                    scriptSig.correctlySpends(new Tx(), 0, scriptPubKey, true);
                } catch (ScriptException e) {
                    System.err.println("scriptSig: " + scripts[0]);
                    System.err.println("scriptPubKey: " + scripts[1]);
                    System.err.flush();
                    throw e;
                }
                script = "";
            }
        }
        in.close();
    }

    @Test
    public void testDataDrivenInvalidScripts() throws Exception {

        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("script_invalid.json"), Charset.forName("UTF-8")));

//        NetworkParameters params = TestNet3Params.get();

        // Poor man's JSON parser (because pulling in a lib for this is overkill)
        String script = "";
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            script += line;
            if (line.equals("]") && script.equals("]") && !in.ready())
                break; // ignore last ]
            if (line.trim().endsWith("],") || line.trim().equals("]")) {
                String[] scripts = script.split(",");
                try {
                    scripts[0] = scripts[0].replaceAll("[\"\\[\\]]", "").trim();
                    scripts[1] = scripts[1].replaceAll("[\"\\[\\]]", "").trim();
                    Script scriptSig = parseScriptString(scripts[0]);
                    Script scriptPubKey = parseScriptString(scripts[1]);

                    scriptSig.correctlySpends(new Tx(), 0, scriptPubKey, true);
                    System.err.println("scriptSig: " + scripts[0]);
                    System.err.println("scriptPubKey: " + scripts[1]);
                    System.err.flush();
                    fail();
                } catch (VerificationException e) {
                    // Expected.
                }
                script = "";
            }
        }
        in.close();
    }

    private static class JSONObject {
        String string;
        List<JSONObject> list;
        boolean booleanValue;
        Integer integer;

        JSONObject(String string) {
            this.string = string;
        }

        JSONObject(List<JSONObject> list) {
            this.list = list;
        }

        JSONObject(Integer integer) {
            this.integer = integer;
        }

        JSONObject(boolean value) {
            this.booleanValue = value;
        }

        boolean isList() {
            return list != null;
        }

        boolean isString() {
            return string != null;
        }

        boolean isInteger() {
            return integer != null;
        }

        boolean isBoolean() {
            return !isList() && !isString() && !isInteger();
        }
    }

    private boolean appendToList(List<JSONObject> tx, StringBuffer buffer) {
        if (buffer.length() == 0)
            return true;
        switch (buffer.charAt(0)) {
            case '[':
                int closePos = 0;
                boolean inString = false;
                int inArray = 0;
                for (int i = 1; i < buffer.length() && closePos == 0; i++) {
                    switch (buffer.charAt(i)) {
                        case '"':
                            if (buffer.charAt(i - 1) != '\\')
                                inString = !inString;
                            break;
                        case ']':
                            if (!inString) {
                                if (inArray == 0)
                                    closePos = i;
                                else
                                    inArray--;
                            }
                            break;
                        case '[':
                            if (!inString)
                                inArray++;
                            break;
                        default:
                            break;
                    }
                }
                if (inArray != 0 || closePos == 0)
                    return false;
                List<JSONObject> subList = new ArrayList<JSONObject>(5);
                StringBuffer subBuff = new StringBuffer(buffer.substring(1, closePos));
                boolean finished = appendToList(subList, subBuff);
                if (finished) {
                    buffer.delete(0, closePos + 1);
                    tx.add(new JSONObject(subList));
                    return appendToList(tx, buffer);
                } else
                    return false;
            case '"':
                int finishPos = 0;
                do {
                    finishPos = buffer.indexOf("\"", finishPos + 1);
                } while (finishPos == -1 || buffer.charAt(finishPos - 1) == '\\');
                if (finishPos == -1)
                    return false;
                tx.add(new JSONObject(buffer.substring(1, finishPos)));
                buffer.delete(0, finishPos + 1);
                return appendToList(tx, buffer);
            case ',':
            case ' ':
                buffer.delete(0, 1);
                return appendToList(tx, buffer);
            default:
                String first = buffer.toString().split(",")[0].trim();
                if (first.equals("true")) {
                    tx.add(new JSONObject(true));
                    buffer.delete(0, 4);
                    return appendToList(tx, buffer);
                } else if (first.equals("false")) {
                    tx.add(new JSONObject(false));
                    buffer.delete(0, 5);
                    return appendToList(tx, buffer);
                } else if (first.matches("^-?[0-9]*$")) {
                    tx.add(new JSONObject(Integer.parseInt(first)));
                    buffer.delete(0, first.length());
                    return appendToList(tx, buffer);
                } else
                    fail();
        }
        return false;
    }

    @Test
    public void testDataDrivenValidTransactions() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("tx_valid.json"), Charset.forName("UTF-8")));

//        NetworkParameters params = TestNet3Params.TestNet3Params();

        // Poor man's (aka. really, really poor) JSON parser (because pulling in a lib for this is probably not overkill)
        int lineNum = -1;
        List<JSONObject> tx = new ArrayList<JSONObject>(3);
        in.read(); // remove first [
        StringBuffer buffer = new StringBuffer(1000);
        while (in.ready()) {
            lineNum++;
            String line = in.readLine();
            if (line == null || line.equals("")) continue;
            buffer.append(line);
            if (line.equals("]") && buffer.toString().equals("]") && !in.ready())
                break;
            boolean isFinished = appendToList(tx, buffer);
            while (tx.size() > 0 && tx.get(0).isList() && tx.get(0).list.size() == 1 && tx.get(0).list.get(0).isString())
                tx.remove(0); // ignore last ]
            if (isFinished && tx.size() == 1 && tx.get(0).list.size() == 3) {
                Tx transaction = null;
                try {
                    HashMap<OutPoint, Script> scriptPubKeys = new HashMap<OutPoint, Script>();
                    for (JSONObject input : tx.get(0).list.get(0).list) {
                        String hash = input.list.get(0).string;
                        int index = input.list.get(1).integer;
                        String script = input.list.get(2).string;
                        Sha256Hash sha256Hash = new Sha256Hash(Utils.reverseBytes(Utils.hexStringToByteArray(hash)));
                        scriptPubKeys.put(new OutPoint(sha256Hash.getBytes(), index), parseScriptString(script));
                    }

                    transaction = new Tx(Utils.hexStringToByteArray(tx.get(0).list.get(1).string.toLowerCase()));
                    boolean enforceP2SH = tx.get(0).list.get(2).booleanValue;
                    assertTrue(tx.get(0).list.get(2).isBoolean());

                    transaction.verify();

                    for (int i = 0; i < transaction.getIns().size(); i++) {
                        In input = transaction.getIns().get(i);
                        if (input.getPrevOutSn() == 0xffffffffL)
                            input.setPrevOutSn(-1);
                        assertTrue(scriptPubKeys.containsKey(new OutPoint(input.getPrevTxHash(), input.getPrevOutSn())));
                        new Script(input.getInSignature()).correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()), enforceP2SH);
                    }
                    tx.clear();
                } catch (Exception e) {
                    System.err.println("Exception processing line " + lineNum + ": " + line);
                    if (transaction != null)
                        System.err.println(transaction);
                    throw e;
                }
            }
        }
        in.close();
    }

    @Test
    public void testDataDrivenInvalidTransactions() throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(
                getClass().getResourceAsStream("tx_invalid.json"), Charset.forName("UTF-8")));

//        NetworkParameters params = TestNet3Params.get();

        // Poor man's (aka. really, really poor) JSON parser (because pulling in a lib for this is probably overkill)
        List<JSONObject> tx = new ArrayList<JSONObject>(1);
        in.read(); // remove first [
        StringBuffer buffer = new StringBuffer(1000);
        while (in.ready()) {
            String line = in.readLine();
            if (line == null || line.equals(""))
                continue;
            buffer.append(line);
            if (line.equals("]") && buffer.toString().equals("]") && !in.ready())
                break; // ignore last ]
            boolean isFinished = appendToList(tx, buffer);
            while (tx.size() > 0 && tx.get(0).isList() && tx.get(0).list.size() == 1 && tx.get(0).list.get(0).isString())
                tx.remove(0);
            if (isFinished && tx.size() == 1 && tx.get(0).list.size() == 3) {
                HashMap<OutPoint, Script> scriptPubKeys = new HashMap<OutPoint, Script>();
                for (JSONObject input : tx.get(0).list.get(0).list) {
                    String hash = input.list.get(0).string;
                    int index = input.list.get(1).integer;
                    String script = input.list.get(2).string;
                    Sha256Hash sha256Hash = new Sha256Hash(Utils.reverseBytes(Utils.hexStringToByteArray(hash)));
                    scriptPubKeys.put(new OutPoint(sha256Hash.getBytes(), index), parseScriptString(script));
                }

                Tx transaction = new Tx(Utils.hexStringToByteArray(tx.get(0).list.get(1).string));
                boolean enforceP2SH = tx.get(0).list.get(2).booleanValue;
                assertTrue(tx.get(0).list.get(2).isBoolean());


                boolean valid = true;
                try {
                    transaction.verify();
                } catch (VerificationException e) {
                    valid = false;
                }

                // The reference client checks this case in CheckTransaction, but we leave it to
                // later where we will see an attempt to double-spend, so we explicitly check here
                HashSet<OutPoint> set = new HashSet<OutPoint>();
                for (In input : transaction.getIns()) {
                    if (set.contains(input.getOutpoint()))
                        valid = false;
                    set.add(input.getOutpoint());
                }

                for (int i = 0; i < transaction.getIns().size() && valid; i++) {
                    In input = transaction.getIns().get(i);
                    assertTrue(scriptPubKeys.containsKey(input.getOutpoint()));
                    try {
                        new Script(input.getInSignature()).correctlySpends(transaction, i, scriptPubKeys.get(input.getOutpoint()), enforceP2SH);
                    } catch (VerificationException e) {
                        valid = false;
                    }
                }

                if (valid)
                    fail();

                tx.clear();
            }
        }
        in.close();
    }

    private static String toAddress(byte[] pubKeyHash, int version) {
        byte[] bytes = pubKeyHash;
        checkArgument(bytes.length == 20, "Addresses are 160-bit hashes, " +
                "so you must provide 20 bytes");

        checkArgument(version < 256 && version >= 0);

        byte[] addressBytes = new byte[1 + bytes.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, bytes.length + 1);
        System.arraycopy(check, 0, addressBytes, bytes.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    @Test
    public void testFromAddress() {
        byte[] rawTx = Utils.hexStringToByteArray("0100000001f98a280010ea7397485a2cbde9e6355deeca50b9b73eba5011f2248da1c9d12c00000000fc00463043021f149e45355bbb45b9d70aa2a30a707da871a7e97bf6e5e82ee679ffe078794f02202e94a43d1df4a9659cf187026bea5581c0db7050b70ae4a8c2340dd7353577bf0148304502210087d0e3f03c68a8962dc203a5491ea31d39f78652f241b5aff2b04a2f77a113990220335e5191ab93b54e9fdee18c06c1713ed1da85e92fb2f96ecff3e7f82362c81c014c695221031b2e51069f115a662fafdbe92347ddcbca693df1cfb96a0c41ce46b57fd746e2210202d41f339f2ca186eacf1fe31f8ff5e8ddf376745a96642a7439c3be7bad70662102951d6cbde04a9fdcf036befb767c96f17a4a3d20ab1a01c147f38b6c035e652853aeffffffff02102700000000000017a9145b39adef84a2728e5b147c1d57c11a1660bb31c787a85b01000000000017a914bc6333c8a2fd1b9be0094bfe6d846ff0298636768700000000");
        Tx tx = new Tx(rawTx);
        String fromAddress = new Script(tx.getIns().get(0).getInSignature()).getFromAddress();

        String expected = "3Js7oJY1qc5VH1erNuLCkTm3cHMZvApn1X";
        assertEquals(expected, fromAddress);
        assertEquals("148f1331a08ff419a9fb59628b5c44b5e43e52bdce55eac4b97aeb3ba0424bb9", Utils.hashToString(tx.getTxHash()));

        rawTx = Utils.hexStringToByteArray("0100000001c40754ec26f15ecf62cdbe3bc45d1c1fd2f8490e10fa6aa56941fa9bc9ee8a15010000006c493046022100ef55375c95f78628d57ca5d6b043172b2f32281314c17e7b91f70c8e77026047022100d61d33ed0f2d769381d1239c7d3b93256da87329c6876a74333e3ec77f97ad15012103d628d9bab1c1d0b88e6aad67ba4ca386d815bbeb9cb360293d978a8b9392719fffffffff02b0c0d6170000000017a914252b16322735d7f667ee194e52e2466cd2ca06f0877142e544000000001976a914747786372207612d9573df3a204d49639f6e0b9788ac00000000");
        tx = new Tx(rawTx);
        fromAddress = new Script(tx.getIns().get(0).getInSignature()).getFromAddress();

        expected = "14EMNcB1BpE2oV5caJKWScnzMxtkrhk3re";
        assertEquals(expected, fromAddress);
        assertEquals("de5004877260f86d59479db1eb95082d128131a637484cbe98617f7b6837bddf", Utils.hashToString(tx.getTxHash()));
    }
}
