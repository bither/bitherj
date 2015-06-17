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
import net.bither.bitherj.db.AbstractDb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Created by songchenwen on 15/6/2.
 */
public class EnterpriseHDMKeychain {
    public static final int MaxPubCount = 10;
    private static final Logger log = LoggerFactory.getLogger(EnterpriseHDMKeychain.class);

    public interface EnterpriseHDMKeychainAddressChangeDelegate {
        void enterpriseHDMKeychainAddedAddress(EnterpriseHDMAddress address);
    }

    private int accountId;

    private int threshold;
    private int pubCount;

    private ArrayList<EnterpriseHDMAddress> addresses = new ArrayList<EnterpriseHDMAddress>();

    private EnterpriseHDMKeychainAddressChangeDelegate addressChangeDelegate;

    public EnterpriseHDMKeychain(int threshold, List<byte[]> externalRoots) {
        this(threshold, 0, externalRoots);
    }

    public EnterpriseHDMKeychain(int threshold, int prepareCount, List<byte[]> externalRoots) {
        this.threshold = threshold;
        this.pubCount = externalRoots.size();
        AbstractDb.enterpriseHDMProvider.addMultiSignSet(this.threshold, this.pubCount);
        if (prepareCount > 0) {
            try {
                prepareAddresses(prepareCount, externalRoots);
            } catch (KeyNotMatchException e) {
                // Won't happen
                e.printStackTrace();
            }
        }
    }

    public EnterpriseHDMKeychain(int accountId) {
        this.accountId = accountId;
        initFromDb();
    }

    private void initFromDb() {
        pubCount = AbstractDb.enterpriseHDMProvider.getPubCount();
        threshold = AbstractDb.enterpriseHDMProvider.getThreshold();
        synchronized (addresses) {
            addresses.clear();
            List<EnterpriseHDMAddress> temp = AbstractDb.enterpriseHDMProvider.
                    getEnterpriseHDMAddress(EnterpriseHDMKeychain.this);
            if (temp != null) {
                addresses.addAll(temp);
            }
        }
    }

    public int prepareAddresses(int count, List<byte[]> externalRoots) throws KeyNotMatchException {
        if (count <= 0) {
            return 0;
        }
        assert externalRoots.size() == pubCount();
        externalRoots = sortExternalRoots(externalRoots);

        ArrayList<DeterministicKey> externalRootPubs = new ArrayList<DeterministicKey>();
        for (byte[] bytes : externalRoots) {
            externalRootPubs.add(HDKeyDerivation.createMasterPubKeyFromExtendedBytes(bytes));
        }

        if (addresses.size() > 0) {
            List<byte[]> firstPubs = addresses.get(0).getPubkeys();

            for (int i = 0;
                 i < pubCount();
                 i++) {
                if (!Arrays.equals(firstPubs.get(i), externalRootPubs.get(i).deriveSoftened(0)
                                .getPubKey()
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
                pubs.add(externalRootPubs.get(j).deriveSoftened(index).getPubKey());
            }
            EnterpriseHDMAddress a = new EnterpriseHDMAddress(new EnterpriseHDMAddress.Pubs
                    (index, threshold(), pubs), this, false);
            as.add(a);
            if (addressChangeDelegate != null) {
                addressChangeDelegate.enterpriseHDMKeychainAddedAddress(a);
            }
        }
        addresses.addAll(as);
        if (as.size() > 0) {
            addAddressesToDb(as);
        }
        return as.size();
    }

    private void addAddressesToDb(List<EnterpriseHDMAddress> addresses) {
        AbstractDb.enterpriseHDMProvider.addEnterpriseHDMAddress(addresses);
    }

    private List<byte[]> sortExternalRoots(List<byte[]> externalRoots) {
        ArrayList<byte[]> sortedExternalRoots = new ArrayList<byte[]>();
        sortedExternalRoots.addAll(externalRoots);
        Collections.sort(sortedExternalRoots, externalRootComparator);
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


    public ArrayList<EnterpriseHDMAddress> getAddresses() {
        return addresses;
    }

    public void setAddressChangeDelegate(EnterpriseHDMKeychainAddressChangeDelegate
                                                 addressChangeDelegate) {
        this.addressChangeDelegate = addressChangeDelegate;
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
