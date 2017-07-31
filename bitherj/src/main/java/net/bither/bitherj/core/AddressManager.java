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

public class AddressManager implements HDMKeychain.HDMAddressChangeDelegate,
        EnterpriseHDMKeychain.EnterpriseHDMKeychainAddressChangeDelegate {

    private static final Logger log = LoggerFactory.getLogger(AddressManager.class);
    private final byte[] lock = new byte[0];
    private static AddressManager uniqueInstance = new AddressManager();

    protected List<Address> privKeyAddresses = new ArrayList<Address>();
    protected List<Address> watchOnlyAddresses = new ArrayList<Address>();
    protected List<Address> trashAddresses = new ArrayList<Address>();
    protected HashSet<String> addressHashSet = new HashSet<String>();
    protected HDMKeychain hdmKeychain;
    protected EnterpriseHDMKeychain enterpriseHDMKeychain;
    protected HDAccount hdAccountHot;
    protected HDAccount hdAccountMonitored;
    protected List<DesktopHDMKeychain> desktopHDMKeychains;

    private AddressManager() {
        synchronized (lock) {
            initAddress();
            initHDMKeychain();
            initEnterpriseHDMKeychain();
            initHDAccounts();
            initDesktopHDMKeychain();
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
        if (enterpriseHDMKeychain != null) {
            for (EnterpriseHDMAddress address : enterpriseHDMKeychain.getAddresses()) {
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

    private void initHDAccounts() {
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.HOT) {
            List<Integer> seeds = AbstractDb.hdAccountProvider.getHDAccountSeeds();
            for (int seedId : seeds) {
                if (hdAccountHot == null && AbstractDb.hdAccountProvider.hasMnemonicSeed(seedId)) {
                    hdAccountHot = new HDAccount(seedId);
                } else if (hdAccountMonitored == null && !AbstractDb.hdAccountProvider.hasMnemonicSeed(seedId)) {
                    hdAccountMonitored = new HDAccount(seedId);
                }
            }
        }
    }

    private void initDesktopHDMKeychain() {
        if (AbstractDb.desktopAddressProvider != null) {
            List<Integer> seeds = AbstractDb.desktopAddressProvider.getDesktopKeyChainSeed();
            if (seeds.size() > 0) {
                desktopHDMKeychains = new ArrayList<DesktopHDMKeychain>();
                for (int i = 0;
                     i < seeds.size();
                     i++) {
                    desktopHDMKeychains.add(new DesktopHDMKeychain(seeds.get(i)));
                }
            }
        }
    }

    public boolean hasDesktopHDMKeychain() {
        return desktopHDMKeychains != null && desktopHDMKeychains.size() > 0;
    }

    public void setDesktopHDMKeychains(List<DesktopHDMKeychain> desktopHDMKeychains) {
        this.desktopHDMKeychains = desktopHDMKeychains;
    }

    public List<DesktopHDMKeychain> getDesktopHDMKeychains() {
        return this.desktopHDMKeychains;
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
        // log.info("getInAddresses time : {} ,ins:{}", (System.currentTimeMillis() - begin), tx
        // .getIns().size());
        boolean isRegister = false;
        Tx compressedTx;
        tx = AbstractDb.hdAccountAddressProvider.updateOutHDAccountId(tx);
        if (txNotificationType != Tx.TxNotificationType.txSend) {
            compressedTx = compressTx(tx, inAddresses);
        } else {
            compressedTx = tx;
        }

        HashSet<String> needNotifyAddressHashSet = new HashSet<String>();
//        HashSet<String> needNotifyHDAccountHS = new HashSet<String>();
//        HashSet<String> needNotifyHDAccountMonitoredHS = new HashSet<String>();
        HashSet<String> needNotifyDesktopHDMHS = new HashSet<String>();
        HashSet<Integer> needNotifyHDAccountIdHS = new HashSet<Integer>();

//        List<HDAccount.HDAccountAddress> relatedAddresses = new ArrayList<HDAccount
//                .HDAccountAddress>();
//        List<HDAccount.HDAccountAddress> relatedHDMonitoredAddresses = new ArrayList<HDAccount
//                .HDAccountAddress>();
        List<DesktopHDMAddress> relatedDesktopHDMAddresses = new ArrayList<DesktopHDMAddress>();

//        HashSet<String> relatedAddressesHS = new HashSet<String>();
//        HashSet<String> relatedHDMonitoredAddressesHS = new HashSet<String>();
        HashSet<String> relatedDesktopHDMAddressesHS = new HashSet<String>();


//        if (hdAccountHot != null) {
//            relatedAddresses = hdAccountHot.getRelatedAddressesForTx(compressedTx, inAddresses);
//        }
//        if (hdAccountMonitored != null) {
//            relatedHDMonitoredAddresses = hdAccountMonitored.getRelatedAddressesForTx
//                    (compressedTx, inAddresses);
//        }
        if (hasDesktopHDMKeychain()) {
            DesktopHDMKeychain desktopHDMKeychain = desktopHDMKeychains.get(0);
            relatedDesktopHDMAddresses = desktopHDMKeychain.getRelatedAddressesForTx
                    (compressedTx, inAddresses);
        }

//        for (HDAccount.HDAccountAddress hdAccountAddress : relatedAddresses) {
//            relatedAddressesHS.add(hdAccountAddress.getAddress());
//        }
//        for (HDAccount.HDAccountAddress hdAccountAddress : relatedHDMonitoredAddresses) {
//            relatedHDMonitoredAddressesHS.add(hdAccountAddress.getAddress());
//        }
        for (DesktopHDMAddress desktopHDMAddress : relatedDesktopHDMAddresses) {
            relatedDesktopHDMAddressesHS.add(desktopHDMAddress.getAddress());
        }


        for (Out out : compressedTx.getOuts()) {
            String outAddress = out.getOutAddress();
            if (addressHashSet.contains(outAddress)) {
                needNotifyAddressHashSet.add(outAddress);
            }

//            if (relatedAddressesHS.contains(outAddress)) {
//                needNotifyHDAccountHS.add(outAddress);
//            }
//
//            if (relatedHDMonitoredAddressesHS.contains(outAddress)) {
//                needNotifyHDAccountMonitoredHS.add(outAddress);
//            }
            if (relatedDesktopHDMAddressesHS.contains(outAddress)) {
                needNotifyDesktopHDMHS.add(outAddress);
            }
            if (out.getHDAccountId() > 0) {
                needNotifyHDAccountIdHS.add(out.getHDAccountId());
            }
        }

        Tx txInDb = AbstractDb.txProvider.getTxDetailByTxHash(tx.getTxHash());
        if (txInDb != null) {
            for (Out out : txInDb.getOuts()) {
                String outAddress = out.getOutAddress();
                if (needNotifyAddressHashSet.contains(outAddress)) {
                    needNotifyAddressHashSet.remove(outAddress);
                }

//                if (needNotifyHDAccountHS.contains(outAddress)) {
//                    needNotifyHDAccountHS.remove(outAddress);
//                }
//                if (needNotifyHDAccountMonitoredHS.contains(outAddress)) {
//                    needNotifyHDAccountMonitoredHS.remove(outAddress);
//                }
                if (needNotifyDesktopHDMHS.contains(outAddress)) {
                    needNotifyDesktopHDMHS.remove(outAddress);
                }
                if (out.getHDAccountId() > 0 && needNotifyHDAccountIdHS.contains(out.getHDAccountId())) {
                    needNotifyHDAccountIdHS.remove(out.getHDAccountId());
                }
            }
            isRegister = true;
        } else {
            for (String address : inAddresses) {
                if (addressHashSet.contains(address)) {
                    needNotifyAddressHashSet.add(address);
                }

//                if (relatedAddressesHS.contains(address)) {
//                    needNotifyHDAccountHS.add(address);
//                }
//                if (relatedHDMonitoredAddressesHS.contains(address)) {
//                    needNotifyHDAccountMonitoredHS.add(address);
//                }
                if (relatedDesktopHDMAddressesHS.contains(address)) {
                    needNotifyDesktopHDMHS.add(address);
                }
            }
            needNotifyHDAccountIdHS.addAll(AbstractDb.hdAccountAddressProvider.getRelatedHDAccountIdList(inAddresses));
            isRegister = needNotifyAddressHashSet.size() > 0
                    || needNotifyDesktopHDMHS.size() > 0 || needNotifyHDAccountIdHS.size() > 0;
        }


        if (needNotifyAddressHashSet.size() > 0 || needNotifyHDAccountIdHS.size() > 0
                || needNotifyDesktopHDMHS.size() > 0) {
            AbstractDb.txProvider.add(compressedTx);
            log.info("add tx {} into db", Utils.hashToString(tx.getTxHash()));
        }
        for (Address addr : AddressManager.getInstance().getAllAddresses()) {
            if (needNotifyAddressHashSet.contains(addr.getAddress())) {
                addr.notificatTx(tx, txNotificationType);
            }
        }

//        List<HDAccount.HDAccountAddress> needNotifityAddressList = new ArrayList<HDAccount
//                .HDAccountAddress>();
//        for (HDAccount.HDAccountAddress hdAccountAddress : relatedAddresses) {
//            if (needNotifyHDAccountHS.contains(hdAccountAddress.getAddress())) {
//                needNotifityAddressList.add(hdAccountAddress);
//            }
//        }
//
//        List<HDAccount.HDAccountAddress> needNotifyHDMonitoredAddressList = new
//                ArrayList<HDAccount.HDAccountAddress>();
//        for (HDAccount.HDAccountAddress hdAccountAddress : relatedHDMonitoredAddresses) {
//            if (needNotifyHDAccountMonitoredHS.contains(hdAccountAddress.getAddress())) {
//                needNotifyHDMonitoredAddressList.add(hdAccountAddress);
//            }
//        }

        List<DesktopHDMAddress> needNotifityDesktopHDMAddressList = new
                ArrayList<DesktopHDMAddress>();
        for (DesktopHDMAddress desktopHDMAddress : relatedDesktopHDMAddresses) {
            if (needNotifyDesktopHDMHS.contains(desktopHDMAddress.getAddress())) {
                needNotifityDesktopHDMAddressList.add(desktopHDMAddress);
            }
        }
//        if (needNotifityAddressList.size() > 0) {
//            getHDAccountHot().onNewTx(tx, needNotifityAddressList, txNotificationType);
//        }
//        if (needNotifyHDAccountMonitoredHS.size() > 0) {
//            getHDAccountMonitored().onNewTx(tx, needNotifyHDMonitoredAddressList,
//                    txNotificationType);
//        }
        if (needNotifityDesktopHDMAddressList.size() > 0) {
            DesktopHDMKeychain desktopHDMKeychain = desktopHDMKeychains.get(0);
            desktopHDMKeychain.onNewTx(tx, needNotifityDesktopHDMAddressList, txNotificationType);
        }
        this.onNewTx(tx, needNotifyHDAccountIdHS, txNotificationType);
        return isRegister;
    }

    private void onNewTx(Tx tx, HashSet<Integer> relatedHDAccountIdList, Tx.TxNotificationType txNotificationType) {
        for (Integer i : relatedHDAccountIdList) {
            if (hasHDAccountHot() && getHDAccountHot().getHdSeedId() == i) {
                getHDAccountHot().onNewTx(tx, txNotificationType);
            }
            if (hasHDAccountMonitored() && getHDAccountMonitored().getHdSeedId() == i) {
                getHDAccountMonitored().onNewTx(tx, txNotificationType);
            }
        }
    }

    public boolean isTxRelated(Tx tx, List<String> inAddresses) {
        for (Address address : this.getAllAddresses()) {
            // todo: may be do not need query in db, just ^ with in and out 's address
            if (isAddressContainsTx(address.getAddress(), tx)) {
                return true;
            }
        }
        tx = AbstractDb.hdAccountAddressProvider.updateOutHDAccountId(tx);
        for (Out out : tx.getOuts()) {
            if (out.getHDAccountId() > 0) {
                return true;
            }
        }
        List<String> addressList = tx.getOutAddressList();
        addressList.addAll(inAddresses);
        if (AbstractDb.hdAccountAddressProvider.getRelatedAddressCnt(addressList) > 0){
            return true;
        }
//        if (hasHDAccountHot()) {
//            if (getHDAccountHot().isTxRelated(tx, inAddresses)) {
//                return true;
//            }
//        }
//        if (hasHDAccountMonitored()) {
//            if (getHDAccountMonitored().isTxRelated(tx, inAddresses)) {
//                return true;
//            }
//        }
        if (hasDesktopHDMKeychain()) {
            if (getDesktopHDMKeychains().get(0).isTxRelated(tx, inAddresses)) {
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
            if (hasEnterpriseHDMKeychain()) {
                result.addAll(getEnterpriseHDMKeychain().getAddresses());
            }
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
        if (hdAccountHot != null && !hdAccountHot.isSyncComplete()) {
            return false;
        }
        if (hdAccountMonitored != null && !hdAccountMonitored.isSyncComplete()) {
            return false;
        }
        if (hasDesktopHDMKeychain() && !desktopHDMKeychains.get(0).isSyncComplete()) {
            return false;
        }
        if (hasHDAccountMonitored() && !getHDAccountMonitored().isSyncComplete()) {
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

    private void initEnterpriseHDMKeychain() {
        if (AbstractDb.enterpriseHDMProvider != null) {
            List<Integer> ids = AbstractDb.enterpriseHDMProvider.getEnterpriseHDMKeychainIds();
            if (ids != null && ids.size() > 0) {
                enterpriseHDMKeychain = new EnterpriseHDMKeychain(ids.get(0));
                enterpriseHDMKeychain.setAddressChangeDelegate(this);
                List<EnterpriseHDMAddress> addresses = enterpriseHDMKeychain.getAddresses();
                for (EnterpriseHDMAddress a : addresses) {
                    addressHashSet.add(a.getAddress());
                }
            }
        }
    }

    public void setHdAccountHot(HDAccount hdAccountHot) {
        this.hdAccountHot = hdAccountHot;
    }

    public void setHDMKeychain(HDMKeychain keychain) {
        synchronized (lock) {
            if (hdmKeychain != null && hdmKeychain != keychain) {
                throw new RuntimeException("can not add a different hdm keychain to address " +
                        "manager");
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

    public void setEnterpriseHDMKeychain(EnterpriseHDMKeychain keychain) {
        synchronized (lock) {
            if (enterpriseHDMKeychain != null && enterpriseHDMKeychain != keychain) {
                throw new RuntimeException("can not add a different enterprise hdm keychain to "
                        + "address manager");
            }
            if (keychain == enterpriseHDMKeychain) {
                return;
            }
            enterpriseHDMKeychain = keychain;
            enterpriseHDMKeychain.setAddressChangeDelegate(this);
            List<EnterpriseHDMAddress> addresses = enterpriseHDMKeychain.getAddresses();
            for (EnterpriseHDMAddress a : addresses) {
                addressHashSet.add(a.getAddress());
            }
        }
    }

    public boolean hasEnterpriseHDMKeychain() {
        synchronized (lock) {
            if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
                return false;
            } else {
                return enterpriseHDMKeychain != null;
            }
        }
    }

    public EnterpriseHDMKeychain getEnterpriseHDMKeychain() {
        synchronized (lock) {
            return enterpriseHDMKeychain;
        }
    }

    public boolean hasHDAccountHot() {
        synchronized (lock) {
            return hdAccountHot != null;
        }
    }

    public HDAccount getHDAccountHot() {
        synchronized (lock) {
            return hdAccountHot;
        }
    }

    public void setHDAccountMonitored(HDAccount account) {
        synchronized (lock) {
            hdAccountMonitored = account;
        }
    }

    public boolean hasHDAccountMonitored() {
        synchronized (lock) {
            return hdAccountMonitored != null;
        }
    }

    public HDAccount getHDAccountMonitored() {
        synchronized (lock) {
            return hdAccountMonitored;
        }
    }

    public boolean hasHDAccountCold() {
        synchronized (lock) {
            if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
                List<Integer> seeds = AbstractDb.hdAccountProvider.getHDAccountSeeds();
                for (int seedId : seeds) {
                    if (AbstractDb.hdAccountProvider.hasMnemonicSeed(seedId)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    public HDAccountCold getHDAccountCold() {
        synchronized (lock) {
            if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
                List<Integer> seeds = AbstractDb.hdAccountProvider.getHDAccountSeeds();
                for (int seedId : seeds) {
                    if (AbstractDb.hdAccountProvider.hasMnemonicSeed(seedId)) {
                        return new HDAccountCold(seedId);
                    }
                }
            }
            return null;
        }
    }

//    @Override
    public void hdmAddressAdded(HDMAddress address) {
        addressHashSet.add(address.getAddress());
    }

//    @Override
    public void enterpriseHDMKeychainAddedAddress(EnterpriseHDMAddress address) {
        if (address != null) {
            addressHashSet.add(address.getAddress());
        }
    }

    public List<Tx> compressTxsForApi(List<Tx> txList, Address address) {
        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
        for (Tx tx : txList) {
            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
        }
        for (Tx tx : txList) {
            if (!isSendFromMe(tx, txHashList, address) && tx.getOuts().size() > BitherjSettings
                    .COMPRESS_OUT_NUM) {
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
            AbstractDb.hdAccountAddressProvider.updateOutHDAccountId(tx);
        }
        for (Tx tx : txList) {
            if (!isSendFromHDAccount(tx, txHashList) && tx.getOuts().size() > BitherjSettings
                    .COMPRESS_OUT_NUM) {
                List<Out> outList = new ArrayList<Out>();
                HashSet<String> addressHashSet = AbstractDb.hdAccountAddressProvider.
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

//    public List<Tx> compressTxsForHDAccountMoitored(List<Tx> txList) {
//        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
//        for (Tx tx : txList) {
//            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
//        }
//        for (Tx tx : txList) {
//            if (!isSendFromHDAccount(tx, txHashList) && tx.getOuts().size() > BitherjSettings
//                    .COMPRESS_OUT_NUM) {
//                List<Out> outList = new ArrayList<Out>();
//                HashSet<String> addressHashSet = AbstractDb.hdAccountAddressProvider.
//                        getBelongAccountAddresses(tx.getOutAddressList());
//                for (Out out : tx.getOuts()) {
//                    if (addressHashSet.contains(out.getOutAddress())) {
//                        outList.add(out);
//                    }
//                }
//                tx.setOuts(outList);
//            }
//        }
//
//        return txList;
//    }

//    public List<Tx> compressTxsForHDAccountMonitored(List<Tx> txList) {
//        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
//        for (Tx tx : txList) {
//            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
//        }
//        for (Tx tx : txList) {
//            if (!isSendFromHDAccountMonitored(tx, txHashList) && tx.getOuts().size() >
//                    BitherjSettings.COMPRESS_OUT_NUM) {
//                List<Out> outList = new ArrayList<Out>();
//                HashSet<String> addressHashSet = AbstractDb.hdAccountAddressProvider
//                        .getBelongAccountAddresses(tx.getOutAddressList());
//                for (Out out : tx.getOuts()) {
//                    if (addressHashSet.contains(out.getOutAddress())) {
//                        outList.add(out);
//                    }
//                }
//                tx.setOuts(outList);
//            }
//        }
//
//        return txList;
//    }


    public List<Tx> compressTxsForDesktopHDM(List<Tx> txList) {
        Map<Sha256Hash, Tx> txHashList = new HashMap<Sha256Hash, Tx>();
        for (Tx tx : txList) {
            txHashList.put(new Sha256Hash(tx.getTxHash()), tx);
        }
        for (Tx tx : txList) {
            if (!isSendFromHDAccount(tx, txHashList) && tx.getOuts().size() > BitherjSettings
                    .COMPRESS_OUT_NUM) {
                List<Out> outList = new ArrayList<Out>();
                HashSet<String> addressHashSet = AbstractDb.desktopTxProvider.
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
        return AbstractDb.hdAccountAddressProvider.getRelatedAddressCnt(inAddressList) > 0;
    }

//    private boolean isSendFromHDAccountMonitored(Tx tx, Map<Sha256Hash, Tx> txHashList) {
//        List<String> inAddressList = new ArrayList<String>();
//        for (In in : tx.getIns()) {
//            Sha256Hash prevTxHash = new Sha256Hash(in.getPrevTxHash());
//            if (txHashList.containsKey(prevTxHash)) {
//                Tx preTx = txHashList.get(prevTxHash);
//                for (Out out : preTx.getOuts()) {
//                    if (out.getOutSn() == in.getPrevOutSn()) {
//                        inAddressList.add(out.getOutAddress());
//                    }
//                }
//            }
//        }
//        List<HDAccount.HDAccountAddress> hdAccountAddressList = AbstractDb.hdAccountAddressProvider
//                .belongAccount(this.hdAccountHot.hdSeedId, inAddressList);
//        return hdAccountAddressList != null && hdAccountAddressList.size() > 0;
//    }

    public Tx compressTx(Tx tx, List<String> inAddresses) {
        if (tx.getOuts().size() > BitherjSettings.COMPRESS_OUT_NUM
                && !isSendFromMe(tx, inAddresses)) {
            List<Out> outList = new ArrayList<Out>();
            for (Out out : tx.getOuts()) {
                String outAddress = out.getOutAddress();
                if (addressHashSet.contains(outAddress) || out.getHDAccountId() > 0) {
                    outList.add(out);
                }
            }
            tx.setOuts(outList);
        }
        return tx;
    }

    private boolean isSendFromMe(Tx tx, List<String> addresses) {
        return this.addressHashSet.containsAll(addresses) || AbstractDb.hdAccountAddressProvider.getRelatedAddressCnt(addresses) > 0;
    }


    public static boolean isPrivateLimit() {
        int maxPrivateKey = AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode
                .COLD ?
                AbstractApp.bitherjSetting.watchOnlyAddressCountLimit()
                : AbstractApp.bitherjSetting.privateKeyOfHotCountLimit();
        return AddressManager.getInstance().getPrivKeyAddresses() != null
                && AddressManager.getInstance().getPrivKeyAddresses().size() >= maxPrivateKey;
    }

    public static boolean isWatchOnlyLimit() {
        return AddressManager.getInstance().getWatchOnlyAddresses() != null
                && AddressManager.getInstance().getWatchOnlyAddresses().size() >= AbstractApp
                .bitherjSetting.watchOnlyAddressCountLimit();
    }

    public static int canAddPrivateKeyCount() {
        int max;
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.COLD) {
            max = AbstractApp.bitherjSetting.watchOnlyAddressCountLimit() - AddressManager
                    .getInstance()
                    .getAllAddresses().size();
        } else {
            max = AbstractApp.bitherjSetting.privateKeyOfHotCountLimit() - AddressManager
                    .getInstance()
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
            return AddressManager.getInstance().getHdmKeychain().getAllCompletedAddresses().size
                    () > 0;
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

    public long getAmount(List<Out> outs) {
        long amount = 0;
        for (Out out : outs) {
            amount += out.getOutValue();
        }
        return amount;
    }
}
