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
import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AddressManager implements HDMKeychain.HDMAddressChangeDelegate {

    private static final Logger log = LoggerFactory.getLogger(AddressManager.class);
    private final byte[] lock = new byte[0];
    private static AddressManager uniqueInstance = new AddressManager();

    protected List<Address> privKeyAddresses = new ArrayList<Address>();
    protected List<Address> watchOnlyAddresses = new ArrayList<Address>();
    protected List<Address> trashAddresses = new ArrayList<Address>();
    protected HashSet<String> addressHashSet = new HashSet<String>();
    protected HDMKeychain hdmKeychain;

    private AddressManager() {
        synchronized (lock) {
            initAddress();
            initHDMKeychain();
            AbstractApp.addressIsReady = true;
            AbstractApp.notificationService.sendBroadcastAddressLoadCompleteState();
        }
    }

    public static AddressManager getInstance() {
        return uniqueInstance;
    }

    private void initAddress() {
        List<Address> addressList = AbstractDb.addressProvider.getAddresses();
        for (Address address : addressList) {
            if (address.hasPrivKey()) {
                if (address.isTrashed()) {
                    this.trashAddresses.add(address);
                } else {
                    this.privKeyAddresses.add(address);
                    this.addressHashSet.add(address.getAddress());
                }
            } else {
                this.watchOnlyAddresses.add(address);
                this.addressHashSet.add(address.getAddress());
            }

        }


    }

    public boolean registerTx(Tx tx, Tx.TxNotificationType txNotificationType) {
        if (AbstractDb.txProvider.isTxDoubleSpendWithConfirmedTx(tx)) {
            // double spend with confirmed tx
            return false;
        }

        boolean isRegister = false;
        Tx compressedTx = compressTx(tx);
        HashSet<String> needNotifyAddressHashSet = new HashSet<String>();
        for (Out out : compressedTx.getOuts()) {
            if (addressHashSet.contains(out.getOutAddress()))
                needNotifyAddressHashSet.add(out.getOutAddress());
        }

        Tx txInDb = AbstractDb.txProvider.getTxDetailByTxHash(tx.getTxHash());
        if (txInDb != null) {
            for (Out out : txInDb.getOuts()) {
                if (needNotifyAddressHashSet.contains(out.getOutAddress()))
                    needNotifyAddressHashSet.remove(out.getOutAddress());
            }
            isRegister = true;
        } else {
            List<String> inAddresses = AbstractDb.txProvider.getInAddresses(compressedTx);
            for (String address : inAddresses) {
                if (addressHashSet.contains(address))
                    needNotifyAddressHashSet.add(address);
            }
            isRegister = needNotifyAddressHashSet.size() > 0;
        }
        if (needNotifyAddressHashSet.size() > 0) {
            AbstractDb.txProvider.add(compressedTx);
            log.info("add tx {} into db", Utils.hashToString(tx.getTxHash()));
        }
        for (Address addr : AddressManager.getInstance().getAllAddresses()) {
            if (needNotifyAddressHashSet.contains(addr.getAddress())) {
                addr.notificatTx(tx, txNotificationType);
            }
        }
        return isRegister;
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
            if (getAllAddresses().contains(address)) {
                return false;
            }
            if (address.hasPrivKey()) {
                if (!this.getTrashAddresses().contains(address)) {
                    AbstractDb.addressProvider.addAddress(address);
                    privKeyAddresses.add(0, address);
                    addressHashSet.add(address.address);
                } else {
                    address.setSyncComplete(false);
                    AbstractDb.addressProvider.restorePrivKeyAddress(address);
                    trashAddresses.remove(address);
                    privKeyAddresses.add(0, address);
                    addressHashSet.add(address.address);
                }
            } else {
                long sortTime = getWatchOnlySortTime();
                address.setSortTime(sortTime);
                AbstractDb.addressProvider.addAddress(address);
                watchOnlyAddresses.add(0, address);
                addressHashSet.add(address.address);
            }
            return true;
        }
    }

    public long getSortTime(boolean hasPrivateKey) {
        if (hasPrivateKey) {
            return getPrivKeySortTime();
        } else {
            return getWatchOnlySortTime();
        }
    }

    private long getWatchOnlySortTime() {
        long sortTime = new Date().getTime();
        if (getWatchOnlyAddresses().size() > 0) {
            long firstSortTime = getWatchOnlyAddresses().get(0).getSortTime()
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
            long firstSortTime = getPrivKeyAddresses().get(0).getSortTime()
                    + getPrivKeyAddresses().size();
            if (sortTime < firstSortTime) {
                sortTime = firstSortTime;
            }
        }
        return sortTime;
    }

    public boolean stopMonitor(Address address) {
        synchronized (lock) {
            if (!address.hasPrivKey()) {
                AbstractDb.addressProvider.removeWatchOnlyAddress(address);
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
            if ((address.hasPrivKey() || address.isHDM()) && address.getBalance() == 0) {
                if (address.isHDM() && hdmKeychain.getAddresses().size() <= 1) {
                    return false;
                }
                address.setTrashed(true);
                AbstractDb.addressProvider.trashPrivKeyAddress(address);
                trashAddresses.add(address);
                privKeyAddresses.remove(address);
                addressHashSet.remove(address.address);
            } else {
                return false;
            }
            return true;
        }
    }

    public boolean restorePrivKey(Address address) {
        synchronized (lock) {
            if (address.hasPrivKey() || address.isHDM()) {
                long sortTime = getPrivKeySortTime();
                address.setSortTime(sortTime);
                address.setSyncComplete(false);
                address.setTrashed(false);
                AbstractDb.addressProvider.restorePrivKeyAddress(address);
                if (address.hasPrivKey() && !address.isHDM()) {
                    privKeyAddresses.add(0, address);
                }
                trashAddresses.remove(address);
                addressHashSet.add(address.address);
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

    public List<Address> getTrashAddresses() {
        synchronized (lock) {
            return this.trashAddresses;
        }
    }

    public List<Address> getAllAddresses() {
        synchronized (lock) {
            ArrayList<Address> result = new ArrayList<Address>();
            if (hasHDMKeychain()) {
                result.addAll(getHdmKeychain().getAddresses());
            }
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

    private void initHDMKeychain() {
        List<Integer> seeds = AbstractDb.addressProvider.getHDSeeds();
        if (seeds.size() > 0) {
            hdmKeychain = new HDMKeychain(seeds.get(0));
            hdmKeychain.setAddressChangeDelegate(this);
            List<HDMAddress> addresses = hdmKeychain.getAddresses();
            for (HDMAddress a : addresses) {
                addressHashSet.add(a.getAddress());
            }
        }
    }

    public void setHDMKeychain(HDMKeychain keychain) {
        synchronized (lock) {
            if (hdmKeychain != null && hdmKeychain != keychain) {
                throw new RuntimeException("can not add a different hdm keychain to address manager");
            }
            if (hdmKeychain == keychain) {
                return;
            }
            hdmKeychain = keychain;
            hdmKeychain.setAddressChangeDelegate(this);
            List<HDMAddress> addresses = hdmKeychain.getAddresses();
            for (HDMAddress a : addresses) {
                addressHashSet.add(a.getAddress());
            }
        }
    }

    public boolean hasHDMKeychain() {
        synchronized (lock) {
            if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
                return hdmKeychain != null;
            } else {
                return hdmKeychain != null && hdmKeychain.getAddresses().size() > 0;
            }
        }
    }

    public HDMKeychain getHdmKeychain() {
        synchronized (lock) {
            return hdmKeychain;
        }
    }

    @Override
    public void hdmAddressAdded(HDMAddress address) {
        addressHashSet.add(address.getAddress());
    }

    public boolean changePassword(SecureCharSequence oldPassword, SecureCharSequence newPassword) throws IOException {
        List<Address> privKeyAddresses = AddressManager.getInstance().getPrivKeyAddresses();
        List<Address> trashAddresses = AddressManager.getInstance().getTrashAddresses();
        if (privKeyAddresses.size() + trashAddresses.size() == 0 && getHdmKeychain() == null) {
            return true;
        }
        for (Address a : privKeyAddresses) {
            String encryptedStr = a.getFullEncryptPrivKey();
            String newEncryptedStr = PrivateKeyUtil.changePassword(encryptedStr, oldPassword, newPassword);
            if (newEncryptedStr == null) {
                return false;
            }
            a.setEncryptPrivKey(newEncryptedStr);
        }
        for (Address a : trashAddresses) {
            String encryptedStr = a.getFullEncryptPrivKey();
            String newEncryptedStr = PrivateKeyUtil.changePassword(encryptedStr, oldPassword, newPassword);
            if (newEncryptedStr == null) {
                return false;
            }
            a.setEncryptPrivKey(newEncryptedStr);
        }
        HDMBId hdmbId = HDMBId.getHDMBidFromDb();
        if (hdmbId != null) {
            String oldEncryptedBitherPassword = hdmbId.getEncryptedBitherPasswordString();
            String newEncryptedBitherPassword = PrivateKeyUtil.changePassword(oldEncryptedBitherPassword, oldPassword, newPassword);
            hdmbId.setEncryptedData(new EncryptedData(newEncryptedBitherPassword));
        }
        for (Address address : privKeyAddresses) {
            address.updatePrivateKey();
        }
        for (Address address : trashAddresses) {
            address.updatePrivateKey();
        }
        if (hdmbId != null) {
            hdmbId.saveEncryptedBitherPassword();
        }

        if (getHdmKeychain() != null) {
            getHdmKeychain().changePassword(oldPassword, newPassword);
        }

        return true;
    }

    public List<Tx> compressTxsForApi(List<Tx> txList, Address address) {
        List<Sha256Hash> txHashList = new ArrayList<Sha256Hash>();
        for (Tx tx : txList) {
            txHashList.add(new Sha256Hash(tx.getTxHash()));
        }
        for (Tx tx : txList) {
            if (!isSendFromMe(tx, txHashList) && tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM) {
                List<Out> outList = new ArrayList<Out>();
                for (Out out : tx.getOuts()) {
                    if (Utils.compareString(address.getAddress(), out.getOutAddress())) {
                        outList.add(out);
                    }
                }
                tx.setOuts(outList);
            }
        }

        return txList;
    }

    private boolean isSendFromMe(Tx tx, List<Sha256Hash> txHashList) {
        for (In in : tx.getIns()) {
            if (txHashList.contains(new Sha256Hash(in.getPrevTxHash()))) {
                return true;
            }
        }
        return false;
    }

    public Tx compressTx(Tx tx) {
        if (!isSendFromMe(tx) && tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM) {
            List<Out> outList = new ArrayList<Out>();
            for (Out out : tx.getOuts()) {
                String outAddress = out.getOutAddress();
                if (addressHashSet.contains(outAddress)) {
                    outList.add(out);
                }
            }
            tx.setOuts(outList);
        }
        return tx;
    }

    private boolean isSendFromMe(Tx tx) {
        boolean canParseFromScript = true;
        List<String> fromAddress = new ArrayList<String>();
        for (In in : tx.getIns()) {
            String address = in.getFromAddress();
            if (address != null) {
                fromAddress.add(address);
            } else {
                canParseFromScript = false;
                break;
            }
        }
        List<String> addresses = null;
        if (canParseFromScript) {
            addresses = fromAddress;
        } else {
            addresses = AbstractDb.txProvider.getInAddresses(tx);
        }
        return this.addressHashSet.containsAll(fromAddress);
    }

}
