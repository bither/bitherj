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

package net.bither.bitherj.crypto;


import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.PrivateKeyUtil;
import net.bither.bitherj.utils.Utils;


public class PasswordSeed {
    private String address;
    private String keyStr;

    public PasswordSeed(String str) {
        int indexOfSplit = QRCodeUtil.indexOfOfPasswordSeed(str);
        this.address = QRCodeUtil.getAddressFromPasswordSeed(str);
        this.keyStr = str.substring(indexOfSplit + 1);
    }


    public PasswordSeed(String address, String encryptedKey) {
        this.address = address;
        this.keyStr = encryptedKey;
    }

    public boolean checkPassword(CharSequence password) {
        ECKey ecKey = PrivateKeyUtil.getECKeyFromSingleString(keyStr, password);
        String ecKeyAddress;
        if (ecKey == null) {
            return false;
        } else {
            ecKeyAddress = ecKey.toAddress();
            ecKey.clearPrivateKey();
        }
        return Utils.compareString(this.address,
                ecKeyAddress);

    }

    public boolean changePassword(CharSequence oldPassword, CharSequence newPassword) {
        keyStr = PrivateKeyUtil.changePassword(keyStr, oldPassword, newPassword);
        return !Utils.isEmpty(keyStr);

    }

    public ECKey getECKey(CharSequence password) {
        return PrivateKeyUtil.getECKeyFromSingleString(keyStr, password);
    }

    public String getAddress() {
        return this.address;
    }

    public String getKeyStr() {
        return this.keyStr;
    }


    public String toPasswordSeedString() {
        try {
            String passwordSeedString = Base58.bas58ToHexWithAddress(this.address) + QRCodeUtil.QR_CODE_SPLIT
                    + QRCodeUtil.getNewVersionEncryptPrivKey(this.keyStr);
            return passwordSeedString;
        } catch (AddressFormatException e) {
            throw new RuntimeException("passwordSeed  address is format error ," + this.address);

        }

    }

    public static boolean hasPasswordSeed() {
        return AbstractDb.addressProvider.hasPasswordSeed();
    }

    public static PasswordSeed getPasswordSeed() {
        return AbstractDb.addressProvider.getPasswordSeed();
    }

}
