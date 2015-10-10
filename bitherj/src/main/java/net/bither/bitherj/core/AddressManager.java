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
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.script.Script;
import net.bither.bitherj.utils.Sha256Hash;
import net.bither.bitherj.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
    protected HDAccount hdAccount;

    private AddressManager() {
        synchronized (lock) {
            initAddress();
            initHDMKeychain();
            initHDAccount();
            initAliasAndVanityLen();
            AbstractApp.addressIsReady = true;
            AbstractApp.notificationService.sendBroadcastAddressLoadCompleteState();
        }
    }

    public static AddressManager getInstance() {
        return uniqueInstance;
    }

    private void initAliasAndVanityLen() {
        Map<String, String> addressAlias = AbstractDb.addressProvider.getAliases();
        Map<String, Integer> vanityAddresses = AbstractDb.addressProvider.getVanitylens();
        if (addressAlias.size() == 0 && vanityAddresses.size() == 0) {
            return;
        }
        for (Address address : privKeyAddresses) {
            String addressStr = address.getAddress();
            if (addressAlias.containsKey(addressStr)) {
                String alias = addressAlias.get(addressStr);
                address.setAlias(alias);
            }
            if (vanityAddresses.containsKey(addressStr)) {
                int vanityLen = vanityAddresses.get(addressStr);
                address.setVanityLen(vanityLen);
            }
        }
        for (Address address : watchOnlyAddresses) {
            String addressStr = address.getAddress();
            if (addressAlias.containsKey(addressStr)) {
                String alias = addressAlias.get(addressStr);
                address.setAlias(alias);
            }
            if (vanityAddresses.containsKey(addressStr)) {
                int vanityLen = vanityAddresses.get(addressStr);
                address.setVanityLen(vanityLen);
            }
        }
        if (hdmKeychain != null) {
            for (HDMAddress address : hdmKeychain.getAllCompletedAddresses()) {
                if (addressAlias.containsKey(address.getAddress())) {
                    String alias = addressAlias.get(address.getAddress());
                    address.setAlias(alias);
                }
            }
        }
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

    private void initHDAccount() {
        List<Integer> seeds = AbstractDb.addressProvider.getHDAccountSeeds();
        if (seeds.size() > 0) {
            hdAccount = new HDAccount(seeds.get(0));
        }
    }

    public boolean registerTx(Tx tx, Tx.TxNotificationType txNotificationType, boolean isConfirmed) {
        if (isConfirmed) {
            byte[] existTx = AbstractDb.txProvider.isIdentify(tx);
            if (existTx.length > 0) {
                AbstractDb.txProvider.remove(existTx);
            }
        } else {
            byte[] existTx = AbstractDb.txProvider.isIdentify(tx);
            if (existTx.length > 0) {
                return false;
            }
        }
        if (AbstractDb.txProvider.isTxDoubleSpendWithConfirmedTx(tx)) {
            // double spend with confirmed tx
            return false;
        }
       // long begin = System.currentTimeMillis();
        List<String> inAddresses = tx.getInAddresses();
       // log.info("getInAddresses time : {} ,ins:{}", (System.currentTimeMillis() - begin), tx.getIns().size());
        boolean isRegister = false;
        Tx compressedTx;
        if (txNotificationType != Tx.TxNotificationType.txSend) {
            compressedTx = compressTx(tx, inAddresses);
        } else {
            compressedTx = tx;
        }

        HashSet<String> needNotifyAddressHashSet = new HashSet<String>();
        HashSet<String> needNotifyHDAccountHS = new HashSet<String>();
        List<HDAccount.HDAccountAddress> relatedAddresses = new ArrayList<HDAccount.HDAccountAddress>();
        HashSet<String> relatedAddressesHS = new HashSet<String>();


        if (hdAccount != null) {
            relatedAddresses = hdAccount.getRelatedAddressesForTx(compressedTx, inAddresses);
        }

        for (HDAccount.HDAccountAddress hdAccountAddress : relatedAddresses) {
            relatedAddressesHS.add(hdAccountAddress.getAddress());
        }


        for (Out out : compressedTx.getOuts()) {
            String outAddress = out.getOutAddress();
            if (addressHashSet.contains(outAddress)) {
                needNotifyAddressHashSet.add(outAddress);
            }

            if (relatedAddressesHS.contains(outAddress)) {
                needNotifyHDAccountHS.add(outAddress);
            }

        }

        Tx txInDb = AbstractDb.txProvider.getTxDetailByTxHash(tx.getTxHash());
        if (txInDb != null) {
            for (Out out : txInDb.getOuts()) {
                String outAddress = out.getOutAddress();
                if (needNotifyAddressHashSet.contains(outAddress)) {
                    needNotifyAddressHashSet.remove(outAddress);
                }

                if (needNotifyHDAccountHS.contains(outAddress)) {
                    needNotifyHDAccountHS.remove(outAddress);
                }

            }
            isRegister = true;
        } else {
            for (String address : inAddresses) {
                if (addressHashSet.contains(address)) {
                    needNotifyAddressHashSet.add(address);
                }

                if (relatedAddressesHS.contains(address)) {
                    needNotifyHDAccountHS.add(address);
                }
            }
            isRegister = needNotifyAddressHashSet.size() > 0
                    || needNotifyHDAccountHS.size() > 0;
        }


        if (needNotifyAddressHashSet.size() > 0 || needNotifyHDAccountHS.size() > 0) {
            AbstractDb.txProvider.add(compressedTx);
            log.info("add tx {} into db", Utils.hashToString(tx.getTxHash()));
        }
        for (Address addr : AddressManager.getInstance().getAllAddresses()) {
            if (needNotifyAddressHashSet.contains(addr.getAddress())) {
                addr.notificatTx(tx, txNotificationType);
            }
        }

        List<HDAccount.HDAccountAddress> needNotifityAddressList = new ArrayList<HDAccount.HDAccountAddress>();
        for (HDAccount.HDAccountAddress hdAccountAddress : relatedAddresses) {
            if (needNotifyHDAccountHS.contains(hdAccountAddress.getAddress())) {
                needNotifityAddressList.add(hdAccountAddress);
            }
        }

        if (needNotifityAddressList.size() > 0) {
            getHdAccount().onNewTx(tx, needNotifityAddressList, txNotificationType);
        }
        return isRegister;
    }

    public boolean isTxRelated(Tx tx, List<String> inAddresses) {
        for (Address address : this.getAllAddresses()) {
            if (isAddressContainsTx(address.getAddress(), tx)) {
                return true;
            }
        }
        if (hasHDAccount()) {
            return getHdAccount().isTxRelated(tx, inAddresses);
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
                long sortTime = getPrivKeySortTime();
                address.setSortTime(sortTime);
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
        if (hdAccount != null && !hdAccount.isSyncComplete()) {
            return false;
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

    public void setHdAccount(HDAccount hdAccount) {
        this.hdAccount = hdAccount;
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

    public boolean hasHDAccount() {
        synchronized (lock) {
            return hdAccount != null;
        }
    }

    public HDAccount getHdAccount() {
        synchronized (lock) {
            return hdAccount;
        }
    }

    @Override
    public void hdmAddressAdded(HDMAddress address) {
        addressHashSet.add(address.getAddress());
    }


    public List<Tx> compressTxsForApi(List<Tx> txList, Address address) {
        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
        for (Tx tx : txList) {
            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
        }
        for (Tx tx : txList) {
            if (!isSendFromMe(tx, txHashList, address) && tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM) {
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

    public List<Tx> compressTxsForHDAccount(List<Tx> txList) {
        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
        for (Tx tx : txList) {
            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
        }
        for (Tx tx : txList) {
            if (!isSendFromHDAccount(tx, txHashList) && tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM) {
                List<Out> outList = new ArrayList<Out>();
                HashSet<String> addressHashSet = AbstractDb.hdAccountProvider.
                        getBelongAccountAddresses(tx.getOutAddressList());
                for (Out out : tx.getOuts()) {
                    if (addressHashSet.contains(out.getOutAddress())) {
                        outList.add(out);
                    }
                }
                tx.setOuts(outList);
            }
        }

        return txList;
    }

    private boolean isSendFromMe(Tx tx, Map<Sha256Hash, Tx> txHashList, Address address) {
        for (In in : tx.getIns()) {
            Sha256Hash prevTxHahs = new Sha256Hash(in.getPrevTxHash());
            if (txHashList.containsKey(prevTxHahs)) {
                Tx preTx = txHashList.get(prevTxHahs);
                for (Out out : preTx.getOuts()) {
                    if (out.getOutSn() == in.getPrevOutSn()) {
                        if (Utils.compareString(out.getOutAddress(), address.getAddress())) {
                            return true;
                        }

                    }
                }
            }

        }
        return false;
    }


    private boolean isSendFromHDAccount(Tx tx, Map<Sha256Hash, Tx> txHashList) {
        List<String> inAddressList = new ArrayList<String>();
        for (In in : tx.getIns()) {
            Sha256Hash prevTxHahs = new Sha256Hash(in.getPrevTxHash());
            if (txHashList.containsKey(prevTxHahs)) {
                Tx preTx = txHashList.get(prevTxHahs);
                for (Out out : preTx.getOuts()) {
                    if (out.getOutSn() == in.getPrevOutSn()) {
                        inAddressList.add(out.getOutAddress());
                    }
                }
            }
        }
        List<HDAccount.HDAccountAddress> hdAccountAddressList = AbstractDb.hdAccountProvider
                .belongAccount(inAddressList);
        return hdAccountAddressList.size() > 0;
    }

    public Tx compressTx(Tx tx, List<String> inAddresses) {
        if (!isSendFromMe(tx, inAddresses) &&
                (hdAccount == null || !hdAccount.isSendFromMe(inAddresses))
                && tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM) {
            List<Out> outList = new ArrayList<Out>();
            HashSet<String> hdAddressesSet = new HashSet<String>();
            if (hasHDAccount()) {
                hdAddressesSet = hdAccount.getBelongAccountAddresses(tx.getOutAddressList());
            }
            for (Out out : tx.getOuts()) {
                String outAddress = out.getOutAddress();
                if (addressHashSet.contains(outAddress)
                        || hdAddressesSet.contains(outAddress)) {
                    outList.add(out);
                }
            }

            tx.setOuts(outList);
        }
        return tx;
    }

    private boolean isSendFromMe(Tx tx, List<String> addresses) {
        return this.addressHashSet.containsAll(addresses);
    }


    public static boolean isPrivateLimit() {
        int maxPrivateKey = AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD ?
                AbstractApp.bitherjSetting.watchOnlyAddressCountLimit()
                : AbstractApp.bitherjSetting.privateKeyOfHotCountLimit();
        return AddressManager.getInstance().getPrivKeyAddresses() != null
                && AddressManager.getInstance().getPrivKeyAddresses().size() >= maxPrivateKey;
    }

    public static boolean isWatchOnlyLimit() {
        return AddressManager.getInstance().getWatchOnlyAddresses() != null
                && AddressManager.getInstance().getWatchOnlyAddresses().size() >= AbstractApp.bitherjSetting.watchOnlyAddressCountLimit();
    }

    public static int canAddPrivateKeyCount() {
        int max;
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
            max = AbstractApp.bitherjSetting.watchOnlyAddressCountLimit() - AddressManager.getInstance()
                    .getAllAddresses().size();
        } else {
            max = AbstractApp.bitherjSetting.privateKeyOfHotCountLimit() - AddressManager.getInstance()
                    .getPrivKeyAddresses().size();
        }
        return max;
    }

    public static boolean isHDMKeychainLimit() {
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
            return AddressManager.getInstance().getHdmKeychain() != null;
        } else {
            if (AddressManager.getInstance().getHdmKeychain() == null) {
                return false;
            }
            return AddressManager.getInstance().getHdmKeychain().getAllCompletedAddresses().size() > 0;
        }
    }


    public static boolean isHDMAddressLimit() {
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
            return true;
        }
        if (AddressManager.getInstance().getHdmKeychain() == null) {
            return false;
        }
        return AddressManager.getInstance().getHdmKeychain().getAllCompletedAddresses().size()
                >= AbstractApp.bitherjSetting.hdmAddressPerSeedCount();
    }

    public HashMap<String, Address> getNeededPrivKeyAddresses(Tx tx) {
        HashMap<String, Address> result = new HashMap<String, Address>();
        for (In in : tx.getIns()) {
            Script pubKeyScript = new Script(in.getPrevOutScript());
            String address = pubKeyScript.getToAddress();
            for (Address privKey : this.getPrivKeyAddresses()) {
                if (Utils.compareString(address, privKey.address)) {
                    result.put(address, privKey);
                    break;
                }
            }
        }
        return result;
    }
}
