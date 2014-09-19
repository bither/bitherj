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

import net.bither.bitherj.BitherjAppEnv;
import net.bither.bitherj.BitherjApplication;
import net.bither.bitherj.db.TxProvider;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AddressManager {

    private static final Logger log = LoggerFactory.getLogger(AddressManager.class);
    private final byte[] lock = new byte[0];
    private static AddressManager uniqueInstance = new AddressManager();

    protected List<Address> privKeyAddresses = new ArrayList<Address>();
    protected List<Address> watchOnlyAddresses = new ArrayList<Address>();


    private AddressManager() {
        synchronized (lock) {
            initPrivateKeyList();
            initWatchOnlyList();
            Utils.BITHERJ_APP_ENV.addressIsReady();
            BitherjApplication.NOTIFICATION_SERVICE.sendBroadcastAddressLoadCompleteState();
        }
    }

    public static AddressManager getInstance() {
        return uniqueInstance;
    }

    public boolean registerTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        if (TxProvider.getInstance().isExist(tx.getTxHash())) {
            // already in db
            return true;
        }
        boolean needAdd = false;
        for (Address address : this.getAllAddresses()) {
            boolean isRel = this.isAddressContainsTx(address.getAddress(), tx);
            if (!needAdd && isRel) {
                needAdd = true;
                TxProvider.getInstance().add(tx);
                log.info("add tx {} into db", Utils.hashToString(tx.getTxHash()));
            }
            if (isRel) {
                address.notificatTx(tx, txNotificationType);
            }
        }
        return needAdd;
    }

    public boolean isTxRelated(Tx tx) {
        for (Address address : this.getAllAddresses()) {
            if (isAddressContainsTx(address.getAddress(), tx)) {
                return true;
            }
        }
        return false;
    }

    private boolean isAddressContainsTx(String address, Tx tx) {
        Set<String> outAddress = new HashSet<String>();
        for (Out out : tx.getOuts()) {
            outAddress.add(out.getOutAddress());
        }
        if (outAddress.contains(address)) {
            return true;
        } else {
            return TxProvider.getInstance().isAddress(address, tx);
        }
    }

    public boolean addAddress(Address address) {
        synchronized (lock) {
            try {
                if (address.hasPrivKey) {
                    address.savePrivateKey();
                    address.savePubKey();
                    privKeyAddresses.add(0, address);
                } else {
                    address.savePubKey();
                    watchOnlyAddresses.add(0, address);
                }

            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
            return true;
        }
    }


    public boolean stopMonitor(Address address) {
        synchronized (lock) {
            if (!address.hasPrivKey) {
                address.removeWatchOnly();
                watchOnlyAddresses.remove(address);
            } else {
                return false;
            }
            return true;
        }
    }

    public List<Address> getPrivKeyAddresses() {
        synchronized (lock) {
            return this.privKeyAddresses;
        }
    }

    public List<Address> getWatchOnlyAddresses() {
        synchronized (lock) {
            return this.watchOnlyAddresses;
        }
    }

    public List<Address> getAllAddresses() {
        synchronized (lock) {
            ArrayList<Address> result = new ArrayList<Address>();
            result.addAll(this.privKeyAddresses);
            result.addAll(this.watchOnlyAddresses);
            return result;
        }
    }

    public boolean addressIsSyncComplete() {
        for (Address address : AddressManager.getInstance().getAllAddresses()) {
            if (!address.isSyncComplete()) {
                return false;
            }
        }
        return true;
    }

    private void initPrivateKeyList() {
        File[] files = Utils.getPrivateDir().listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.getName().contains(Address.PUBLIC_KEY_FILE_NAME_SUFFIX)) {
                    String content = Utils.readFile(file);
                    String[] strings = content.split(Address.KEY_SPLIT_STRING);
                    String address = file.getName().substring(0,
                            file.getName().length() - Address.PUBLIC_KEY_FILE_NAME_SUFFIX.length());
                    String publicKey = strings[0];
                    int isSyncComplete = Integer.valueOf(strings[1]);
                    long createTime = Long.valueOf(strings[2]);
                    int isFromXRandom = Integer.valueOf(strings[3]);
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), createTime
                            , isSyncComplete == 1, isFromXRandom == 1, true);
                    this.privKeyAddresses.add(add);
                }
            }
            if (this.privKeyAddresses.size() > 0) {
                Collections.sort(this.privKeyAddresses);
            }
        }

    }

    private void initWatchOnlyList() {
        File[] files = Utils.getWatchOnlyDir().listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.getName().contains(Address.PUBLIC_KEY_FILE_NAME_SUFFIX)) {
                    String content = Utils.readFile(file);
                    String[] strings = content.split(Address.KEY_SPLIT_STRING);
                    String address = file.getName().substring(0,
                            file.getName().length() - Address.PUBLIC_KEY_FILE_NAME_SUFFIX.length());
                    String publicKey = strings[0];
                    int isSyncComplete = Integer.valueOf(strings[1]);
                    long createTime = Long.valueOf(strings[2]);
                    int isFromXRandom = Integer.valueOf(strings[3]);
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), createTime
                            , isSyncComplete == 1, isFromXRandom == 1, false);
                    this.watchOnlyAddresses.add(add);
                }
            }
            if (this.watchOnlyAddresses.size() > 0) {
                Collections.sort(this.watchOnlyAddresses);
            }
        }
    }
}
