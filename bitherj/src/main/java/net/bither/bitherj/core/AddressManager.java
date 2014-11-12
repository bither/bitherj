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

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AddressManager {

    private static final Logger log = LoggerFactory.getLogger(AddressManager.class);
    private final byte[] lock = new byte[0];
    private static AddressManager uniqueInstance = new AddressManager();

    protected List<Address> privKeyAddresses = new ArrayList<Address>();
    protected List<Address> watchOnlyAddresses = new ArrayList<Address>();
    protected List<Address> trashAddresses = new ArrayList<Address>();
    protected HashSet<String> addressHashSet = new HashSet<String>();


    private AddressManager() {
        synchronized (lock) {
            initPrivateKeyListByDesc();
            initWatchOnlyListByDesc();
            initTrashListByDesc();
            AbstractApp.addressIsReady = true;
            AbstractApp.notificationService.sendBroadcastAddressLoadCompleteState();
        }
    }

    public static AddressManager getInstance() {
        return uniqueInstance;
    }

    public boolean registerTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        if (AbstractDb.txProvider.isExist(tx.getTxHash())) {
            // already in db
            return true;
        }

        if (AbstractDb.txProvider.isTxDoubleSpendWithConfirmedTx(tx)) {
            // double spend with confirmed tx
            return false;
        }

        HashSet<String> needNotifyAddressHashSet = new HashSet<String>();
        for (Out out : tx.getOuts()) {
            if (addressHashSet.contains(out.getOutAddress()))
                needNotifyAddressHashSet.add(out.getOutAddress());
        }

        List<String> inAddresses = AbstractDb.txProvider.getInAddresses(tx);
        for (String address : inAddresses) {
            if (addressHashSet.contains(address))
                needNotifyAddressHashSet.add(address);
        }
        if (needNotifyAddressHashSet.size() > 0) {
            AbstractDb.txProvider.add(tx);
            log.info("add tx {} into db", Utils.hashToString(tx.getTxHash()));
        }
        for (Address addr : AddressManager.getInstance().getAllAddresses()) {
            if(needNotifyAddressHashSet.contains(addr.getAddress())){
                addr.notificatTx(tx, txNotificationType);
            }
        }
        return needNotifyAddressHashSet.size() > 0;
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
            return AbstractDb.txProvider.isAddressContainsTx(address, tx);
        }
    }

    public boolean addAddress(Address address) {
        synchronized (lock) {
            try {
                if (address.hasPrivKey) {
                    address.savePrivateKey();
                    address.savePubKey(getPrivKeySortTime());
                    privKeyAddresses.add(0, address);
                    addressHashSet.add(address.address);
                } else {
                    address.savePubKey(getWatchOnlySortTime());
                    watchOnlyAddresses.add(0, address);
                    addressHashSet.add(address.address);
                }

            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
            return true;
        }
    }

    private long getWatchOnlySortTime() {
        long sortTime = new Date().getTime();
        if (getWatchOnlyAddresses().size() > 0) {
            long firstSortTime = getWatchOnlyAddresses().get(0).getmSortTime()
                    + getWatchOnlyAddresses().size();
            if (sortTime < firstSortTime) {
                sortTime = firstSortTime;
            }
        }
        return sortTime;
    }

    private long getPrivKeySortTime() {
        long sortTime = new Date().getTime();
        if (getPrivKeyAddresses().size() > 0) {
            long firstSortTime = getPrivKeyAddresses().get(0).getmSortTime()
                    + getPrivKeyAddresses().size();
            if (sortTime < firstSortTime) {
                sortTime = firstSortTime;
            }
        }
        return sortTime;
    }

    public boolean stopMonitor(Address address) {
        synchronized (lock) {
            if (!address.hasPrivKey) {
                address.removeWatchOnly();
                watchOnlyAddresses.remove(address);
                addressHashSet.remove(address.address);
            } else {
                return false;
            }
            return true;
        }
    }

    public boolean trashPrivKey(Address address) {
        synchronized (lock) {
            if (address.hasPrivKey && address.getBalance() == 0) {
                address.trashPrivKey();
                trashAddresses.add(address);
                privKeyAddresses.remove(address);
                addressHashSet.remove(address.address);
                trashAddresses.add(address);
            } else {
                return false;
            }
            return true;
        }
    }

    public boolean restorePrivKey(Address address) {
        synchronized (lock) {
            try {
                if (address.hasPrivKey) {
                    address.restorePrivKey();
                    trashAddresses.remove(address);
                    long sortTime = getPrivKeySortTime();
                    address.savePubKey(sortTime);
                    trashAddresses.remove(address);
                    privKeyAddresses.add(0, address);
                    addressHashSet.add(address.address);
                } else {
                    return false;
                }
                return true;
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
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

    public List<Address> getTrashAddresses() {
        synchronized (lock) {
            return this.trashAddresses;
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

    public HashSet<String> getAddressHashSet() {
        synchronized (lock) {
            return this.addressHashSet;
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

    private void initPrivateKeyListByDesc() {
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
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), createTime
                            , isSyncComplete == 1, isFromXRandom, true);
                    this.privKeyAddresses.add(add);
                    addressHashSet.add(add.address);
                }
            }
            if (this.privKeyAddresses.size() > 0) {
                Collections.sort(this.privKeyAddresses);
            }
        }
    }

    private void initWatchOnlyListByDesc() {
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
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), createTime
                            , isSyncComplete == 1, isFromXRandom, false);
                    this.watchOnlyAddresses.add(add);
                    addressHashSet.add(add.address);
                }
            }
            if (this.watchOnlyAddresses.size() > 0) {
                Collections.sort(this.watchOnlyAddresses);
            }
        }
    }

    private void initTrashListByDesc() {
        File[] files = Utils.getTrashDir().listFiles();
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
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), createTime
                            , isSyncComplete == 1, isFromXRandom, true);
                    this.trashAddresses.add(add);
                }
            }
            if (this.trashAddresses.size() > 0) {
                Collections.sort(this.trashAddresses);
            }
        }
    }

    public boolean changePassword(SecureCharSequence oldPassword, SecureCharSequence newPassword) throws IOException {
        List<Address> privKeyAddresses = AddressManager.getInstance().getPrivKeyAddresses();
        List<Address> trashAddresses = AddressManager.getInstance().getTrashAddresses();
        if (privKeyAddresses.size() + trashAddresses.size() == 0) {
            return true;
        }
        for (Address a : privKeyAddresses) {
            String encryptedStr = a.getEncryptPrivKey();
            String newEncryptedStr = PrivateKeyUtil.changePassword(encryptedStr, oldPassword, newPassword);
            if (newEncryptedStr == null) {
                return false;
            }
            a.setEncryptPrivKey(newEncryptedStr);
        }
        for (Address a : trashAddresses) {
            String encryptedStr = a.getEncryptPrivKey();
            String newEncryptedStr = PrivateKeyUtil.changePassword(encryptedStr, oldPassword, newPassword);
            if (newEncryptedStr == null) {
                return false;
            }
            a.setEncryptPrivKey(newEncryptedStr);
        }

        for (Address address : privKeyAddresses) {
            address.savePrivateKey();
        }
        for (Address address : trashAddresses) {
            address.saveTrashKey();
        }
        return true;
    }
}
