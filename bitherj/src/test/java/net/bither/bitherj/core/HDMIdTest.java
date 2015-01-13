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
import net.bither.bitherj.api.UploadHDMBidApi;
import net.bither.bitherj.crypto.DumpedPrivateKey;
import net.bither.bitherj.crypto.ECKey;
import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class HDMIdTest {

    @Test
    public void testCreateHDAddress() {
        try {
            ECKey ecKey = new DumpedPrivateKey("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").getKey();
            String address = ecKey.toAddress();
            GetHDMBIdRandomApi getHDMBIdRandomApi = new GetHDMBIdRandomApi(address);
            getHDMBIdRandomApi.handleHttpGet();
            long randomKey = getHDMBIdRandomApi.getResult();
            byte[] decryptedPassword = new byte[32];
            for (int i = 0; i < decryptedPassword.length; i++) {
                decryptedPassword[i] = 0;
            }

            String message = Utils.format(HDMBId.BITID_STRING, address, Utils.bytesToHexString(decryptedPassword), randomKey);
            byte[] hash = Utils.getPreSignMessage(message);
            byte[] signBytes = ecKey.signHash(hash, null);
            UploadHDMBidApi uploadHDMBidApi = new UploadHDMBidApi(address, signBytes, decryptedPassword);
            uploadHDMBidApi.handleHttpPost();
            String str = uploadHDMBidApi.getResult();
            HDMAddress.Pubs pubs = new HDMAddress.Pubs(ecKey.getPubKey(), ecKey.getPubKey(), null, 1);
            List<HDMAddress.Pubs> pubsList = new ArrayList<HDMAddress.Pubs>();
            pubsList.add(pubs);
            CreateHDMAddressApi createHDMAddressApi = new CreateHDMAddressApi(address, pubsList, decryptedPassword);
            createHDMAddressApi.handleHttpPost();
            List<byte[]> pubList = createHDMAddressApi.getResult();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
