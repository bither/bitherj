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

import org.junit.Test;

import java.math.BigInteger;
import java.security.SignatureException;

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
}
