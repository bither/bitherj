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

package net.bither.bitherj.utils;

import net.bither.bitherj.AbstractApp;
import net.bither.bitherj.BitherjSettings;
import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.qrcode.QRCodeUtil;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UpgradeAddressUtil {


    private static List<Address> initPrivateKeyListByDesc() {
        List<Address> privKeyAddresses = new ArrayList<Address>();

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
                    long sortTime = Long.valueOf(strings[2]);
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }
                    String privateKeyFullFileName = Utils.format(BitherjSettings
                            .PRIVATE_KEY_FILE_NAME, Utils.getPrivateDir(), address);
                    String encryptPrivate = QRCodeUtil.getNewVersionEncryptPrivKey(Utils.readFile(new File(privateKeyFullFileName)));
                    encryptPrivate = PrivateKeyUtil.formatEncryptPrivateKeyForDb(encryptPrivate);
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), sortTime
                            , isSyncComplete == 1, isFromXRandom, false, encryptPrivate);
                    privKeyAddresses.add(add);

                }
            }
            if (privKeyAddresses.size() > 0) {
                Collections.sort(privKeyAddresses);
            }
        }
        return privKeyAddresses;
    }


    private static List<Address> initWatchOnlyListByDesc() {
        List<Address> watchOnlyAddresses = new ArrayList<Address>();
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
                    long sortTime = Long.valueOf(strings[2]);
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), sortTime
                            , isSyncComplete == 1, isFromXRandom, false, null);
                    watchOnlyAddresses.add(add);

                }
            }
            if (watchOnlyAddresses.size() > 0) {
                Collections.sort(watchOnlyAddresses);
            }
        }
        return watchOnlyAddresses;
    }

    private static List<Address> initTrashListByDesc() {
        File[] files = Utils.getTrashDir().listFiles();
        List<Address> trashAddresses = new ArrayList<Address>();
        if (files != null) {
            for (File file : files) {
                if (file.getName().contains(Address.PUBLIC_KEY_FILE_NAME_SUFFIX)) {
                    String content = Utils.readFile(file);
                    String[] strings = content.split(Address.KEY_SPLIT_STRING);
                    String address = file.getName().substring(0,
                            file.getName().length() - Address.PUBLIC_KEY_FILE_NAME_SUFFIX.length());
                    String publicKey = strings[0];
                    int isSyncComplete = Integer.valueOf(strings[1]);
                    long sortTime = Long.valueOf(strings[2]);
                    boolean isFromXRandom = false;
                    if (strings.length == 4) {
                        isFromXRandom = Utils.compareString(strings[3], QRCodeUtil.XRANDOM_FLAG);
                    }

                    String privateKeyFullFileName = Utils.format(BitherjSettings
                            .PRIVATE_KEY_FILE_NAME, Utils.getTrashDir(), address);
                    String encryptPrivate = QRCodeUtil.getNewVersionEncryptPrivKey(Utils.readFile(new File(privateKeyFullFileName)));
                    encryptPrivate = PrivateKeyUtil.formatEncryptPrivateKeyForDb(encryptPrivate);
                    Address add = new Address(address, Utils.hexStringToByteArray(publicKey), sortTime
                            , isSyncComplete == 1, isFromXRandom, true, encryptPrivate);
                    add.setTrashed(true);
                    trashAddresses.add(add);
                }
            }
            if (trashAddresses.size() > 0) {
                Collections.sort(trashAddresses);
            }
        }
        return trashAddresses;
    }


    public static boolean upgradeAddress() throws Exception {
        boolean success = true;
        List<Address> addressList = new ArrayList<Address>();
        addressList.addAll(initPrivateKeyListByDesc());
        addressList.addAll(initWatchOnlyListByDesc());
        addressList.addAll(initTrashListByDesc());
        Collections.reverse(addressList);
        for (Address address : addressList) {
            address.setSyncComplete(false);
            AddressManager.getInstance().addAddress(address);
        }
        if (AbstractApp.bitherjSetting.getAppMode() == BitherjSettings.AppMode.HOT) {
            if (addressList.size() > 0) {
                AbstractDb.txProvider.clearAllTx();
            }
        }
        return success;
    }


}
