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

package net.bither.bitherj.core;

import net.bither.bitherj.api.CreateHDMAddressApi;
import net.bither.bitherj.api.GetHDMBIdRandomApi;
import net.bither.bitherj.api.RecoveryHDMApi;
import net.bither.bitherj.api.SignatureHDMApi;
import net.bither.bitherj.api.UploadHDMBidApi;
import net.bither.bitherj.core.https.HttpsTest;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class HDMIdTest {
    private static final Logger log = LoggerFactory.getLogger(HDMIdTest.class);

    @Test
    public void testCreateHDAddress() {
        try {
            HttpsTest.trust();
            ECKey ecKey = new DumpedPrivateKey("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").getKey();
            String address = ecKey.toAddress();
            GetHDMBIdRandomApi getHDMBIdRandomApi = new GetHDMBIdRandomApi(address);
            getHDMBIdRandomApi.handleHttpGet();
            long randomKey = getHDMBIdRandomApi.getResult();
            byte[] decryptedPassword = new byte[32];
            for (int i = 0; i < decryptedPassword.length; i++) {
                decryptedPassword[i] = 0;
            }

            String message = Utils.format(HDMBId.BITID_STRING, address, Utils.bytesToHexString(decryptedPassword).toLowerCase(Locale.US), randomKey);
            byte[] hash = Utils.getPreSignMessage(message);
            byte[] signBytes = ecKey.signHash(hash, null);
            UploadHDMBidApi uploadHDMBidApi = new UploadHDMBidApi(address, address, signBytes, decryptedPassword);
            uploadHDMBidApi.handleHttpPost();
            boolean str = uploadHDMBidApi.getResult();
            HDMAddress.Pubs pubs = new HDMAddress.Pubs(ecKey.getPubKey(), ecKey.getPubKey(), null, 0);
            List<HDMAddress.Pubs> pubsList = new ArrayList<HDMAddress.Pubs>();
            pubsList.add(pubs);

            CreateHDMAddressApi createHDMAddressApi = new CreateHDMAddressApi(address, pubsList, decryptedPassword);
            createHDMAddressApi.handleHttpPost();


            List<byte[]> remotePubs = createHDMAddressApi.getResult();
            for (int i = 0;
                 i < pubsList.size();
                 i++) {
                HDMAddress.Pubs pubss = pubsList.get(i);
                pubss.remote = remotePubs.get(i);
                System.out.println("hot:" + Utils.bytesToHexString(pubss.hot));
                System.out.println("cold:" + Utils.bytesToHexString(pubss.cold));
                System.out.println("remote:" + Utils.bytesToHexString(pubss.remote));
                System.out.println("create,Address:" + pubss.getAddress());
            }

            List<byte[]> unsigns = new ArrayList<byte[]>();
            unsigns.add(Utils.doubleDigest(decryptedPassword));
            SignatureHDMApi signatureHDMApi = new SignatureHDMApi(address, 0, decryptedPassword, unsigns);
            signatureHDMApi.handleHttpPost();
            List<byte[]> bytesList = signatureHDMApi.getResult();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testRecoveryHDM() {
        try {
            HttpsTest.trust();
            ECKey ecKey = new DumpedPrivateKey("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").getKey();
            String address = ecKey.toAddress();
            System.out.println("eckey:" + address);
            byte[] decryptedPassword = new byte[32];
            for (int i = 0; i < decryptedPassword.length; i++) {
                decryptedPassword[i] = 0;
            }
            GetHDMBIdRandomApi getHDMBIdRandomApi = new GetHDMBIdRandomApi(address);
            getHDMBIdRandomApi.handleHttpGet();
            long randomKey = getHDMBIdRandomApi.getResult();
            String message = Utils.format(HDMBId.BITID_STRING, address, Utils.bytesToHexString(decryptedPassword).toLowerCase(Locale.US), randomKey);
            byte[] hash = Utils.getPreSignMessage(message);
            byte[] signBytes = ecKey.signHash(hash, null);
            RecoveryHDMApi recoveryHDMApi = new RecoveryHDMApi(address, signBytes, decryptedPassword);
            recoveryHDMApi.handleHttpPost();
            List<HDMAddress.Pubs> pubses = recoveryHDMApi.getResult();
            for (HDMAddress.Pubs pubs : pubses) {
                System.out.println("hot:" + Utils.bytesToHexString(pubs.hot));
                System.out.println("cold:" + Utils.bytesToHexString(pubs.cold));
                System.out.println("remote:" + Utils.bytesToHexString(pubs.remote));
                System.out.println("address:" + pubs.getAddress());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
