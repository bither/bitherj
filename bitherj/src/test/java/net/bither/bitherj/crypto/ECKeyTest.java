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
package net.bither.bitherj.crypto;

import net.bither.bitherj.core.Tx;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class ECKeyTest {
    @Test
    public void testNormal() {
        ECKey key = new ECKey(BigInteger.ONE);
        String message = "1";
        String expectSignedMessage = "IJbxSEQOQOySFCJJEAnUSOnvzTNEX0i4ENVwYrSVBCYuHvTNil+wYDwQhRtV2msKkHZMW5GiRXeDFbXIYzn1KXw=";

        String signedMessage = key.signMessage(message);
        assertEquals(expectSignedMessage, signedMessage);
        try {
            key.verifyMessage(message, signedMessage);
        } catch (SignatureException e) {
            e.printStackTrace();
            fail();
        }


        message = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        expectSignedMessage = "IFllaRcUZyAe3nXNWbOlKbP4BZ3dMLZ6somOreoZPOK1YTgjgFrHdczTWarKtjsdoRbP70u3C+D57yU+SOleoGI=";

        signedMessage = key.signMessage(message);
        assertEquals(expectSignedMessage, signedMessage);
        try {
            key.verifyMessage(message, signedMessage);
        } catch (SignatureException e) {
            e.printStackTrace();
            fail();
        }

        message = "比太钱包";
        expectSignedMessage = "Hw6ZIXQwLovmlCijSAuQs1JeVqIS2OB0hL74q0E5x2PAW0LCUIUM0nyjuasSKaYfmFlFWO0Btyx+r+MohYHirbA=";

        signedMessage = key.signMessage(message);
        assertEquals(expectSignedMessage, signedMessage);
        try {
            key.verifyMessage(message, signedMessage);
        } catch (SignatureException e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testGetPubs() {
        List<byte[]> pubKeyS = Arrays.asList(Utils.hexStringToByteArray("02d8ed584a211a9195f0d580617c60398f82f58dcd5b104249737762656e62d52e"),
                Utils.hexStringToByteArray("026fd10f953a13ac14041460cd01eab3d665d140d1c978a01db4bc669bab9a77db"), Utils.hexStringToByteArray("03b5eceb6f5a9a12b8b7fe23ae6297bfdb46aeab39ab0ee89efd4068d251667ae0"));
        byte[] params = Utils.hexStringToByteArray("522102d8ed584a211a9195f0d580617c60398f82f58dcd5b104249737762656e62d52e21026fd10f953a13ac14041460cd01eab3d665d140d1c978a01db4bc669bab9a77db2103b5eceb6f5a9a12b8b7fe23ae6297bfdb46aeab39ab0ee89efd4068d251667ae053ae");
        Tx tx = new Tx(Utils.hexStringToByteArray("010000000196d607b6c1647a1cccd9db40e918627e4d5e190ba56a5663ccef5e1a8ecada0700000000fdfd0000473044022041b2a5f1965b060bbf484218ac1e3b7ced9ec908078ca4565f9c4eef4f0dfec902206c3f3a1320dac89fd1e58627a1208510328d618365dd033d90ce5230c40884fa01483045022100abd2696052faa6e707e02402b7c654d0ab3be7d1d7f14af541abf99eaf16e1fd02205da8e8e2c4a9795046aa4c380e6f1c005e6619b16f7182df37b54405eb28aedc014c69522102d8ed584a211a9195f0d580617c60398f82f58dcd5b104249737762656e62d52e21026fd10f953a13ac14041460cd01eab3d665d140d1c978a01db4bc669bab9a77db2103b5eceb6f5a9a12b8b7fe23ae6297bfdb46aeab39ab0ee89efd4068d251667ae053aeffffffff0128230000000000001976a914f307ea0809f5c60d42482e57dfdd78ed53df580688ac00000000"));
        List<byte[]> signPubs = tx.getIns().get(0).getP2SHPubKeys();
        for (byte[] signs : signPubs) {
            boolean isPub = false;
            for (byte[] pubs : pubKeyS) {
                isPub = Arrays.equals(signs, pubs);
                if (isPub) {
                    break;
                }
            }
            System.out.println("pub:" + Utils.bytesToHexString(signs));
            assertTrue(Utils.bytesToHexString(signs), isPub);
        }

    }

    @Test
    public void testGenerateECKeyWithRandom() {
        ECKey.generateECKey(new TestRandom());
    }

    public class TestRandom extends SecureRandom {
        int index = 0;

        @Override
        public synchronized void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = 0;
            }
            if (index == 0) {
                System.out.println("call nextBytes: " + Utils.bytesToHexString(bytes));
            } else {
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(bytes);

                assertTrue("use new bytes: " + Utils.bytesToHexString(bytes), index > 0);
            }
            index++;


        }
    }

}
