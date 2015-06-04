/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.core;

import net.bither.bitherj.crypto.hd.DeterministicKey;
import net.bither.bitherj.crypto.hd.HDKeyDerivation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/**
 * Created by songchenwen on 15/6/2.
 */
public class EnterpriseHDMKeychain {

    private int accountId;

    private int threshold;
    private int pubCount;

    private ArrayList<EnterpriseHDMAddress> addresses;

    public EnterpriseHDMKeychain(int threshold, List<byte[]> externalRoots) {
        this(threshold, 0, externalRoots);
    }

    public EnterpriseHDMKeychain(int threshold, int prepareCount, List<byte[]> externalRoots) {
        this.threshold = threshold;
        this.pubCount = externalRoots.size();
        addresses = new ArrayList<EnterpriseHDMAddress>();
        if (prepareCount > 0) {
            try {
                prepareAddresses(prepareCount, externalRoots);
            } catch (KeyNotMatchException e) {
                // Won't happen
                e.printStackTrace();
            }
        }
        //TODO EnterpriseHDMKeychain add to db
    }

    public EnterpriseHDMKeychain(int accountId) {
        this.accountId = accountId;
        initFromDb();
    }

    private void initFromDb() {
        //TODO EnterpriseHDMKeychain init From Db
    }

    public int prepareAddresses(int count, List<byte[]> externalRoots) throws KeyNotMatchException {
        if (count <= 0) {
            return 0;
        }
        assert externalRoots.size() == pubCount();
        externalRoots = sortExternalRoots(externalRoots);

        if (addresses.size() > 0) {
            List<byte[]> firstPubs = addresses.get(0).getPubkeys();

            for (int i = 0;
                 i < pubCount();
                 i++) {
                if (!Arrays.equals(firstPubs.get(i), pubFromExternalRoot(0, externalRoots.get(i))
                )) {
                    throw new KeyNotMatchException(i);
                }
            }
        }

        ArrayList<EnterpriseHDMAddress> as = new ArrayList<EnterpriseHDMAddress>();
        for (int index = addresses.size();
             index < addresses.size() + count;
             index++) {
            ArrayList<byte[]> pubs = new ArrayList<byte[]>();
            for (int j = 0;
                 j < pubCount();
                 j++) {
                pubs.add(pubFromExternalRoot(index, externalRoots.get(j)));
            }
            as.add(new EnterpriseHDMAddress(new EnterpriseHDMAddress.Pubs(index, threshold(),
                    pubs), this, false));
        }
        if (as.size() > 0) {
            addAddressesToDb(as);
        }
        return as.size();
    }

    private void addAddressesToDb(List<EnterpriseHDMAddress> addresses) {
        //TODO EnterpriseHDMKeychain addAddressesToDb
    }

    private byte[] pubFromExternalRoot(int index, byte[] externalRoot) {
        DeterministicKey external = HDKeyDerivation.createMasterPubKeyFromExtendedBytes
                (externalRoot);
        return external.deriveSoftened(index).getPubKey();
    }

    private List<byte[]> sortExternalRoots(List<byte[]> externalRoots) {
        ArrayList<byte[]> sortedExternalRoots = new ArrayList<byte[]>();
        sortedExternalRoots.addAll(externalRoots);
        sortedExternalRoots.sort(externalRootComparator);
        return sortedExternalRoots;
    }

    private Comparator<byte[]> externalRootComparator = new Comparator<byte[]>() {
        @Override
        public int compare(byte[] o1, byte[] o2) {
            return new BigInteger(1, o1).compareTo(new BigInteger(1, o2));
        }
    };

    public int threshold() {
        return threshold;
    }

    public int pubCount() {
        return pubCount;
    }

    public static final class KeyNotMatchException extends Exception {
        private int index;

        public KeyNotMatchException(int index) {
            super("Key not match at index: " + index);
            this.index = index;
        }

        public int index() {
            return index;
        }
    }
}
