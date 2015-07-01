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

package net.bither.bitherj.factory;

import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.HDAccountCold;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

import java.util.List;

public abstract class ImportHDSeed {
    public enum ImportHDSeedType {
        HDMColdSeedQRCode, HDMColdPhrase, HDSeedQRCode, HDSeedPhrase
    }

    public static final int PASSWORD_IS_DIFFEREND_LOCAL = 0;
    public static final int NOT_HDM_COLD_SEED = 1;
    public static final int PASSWORD_WRONG = 3;
    public static final int IMPORT_FAILED = 4;

    public static final int NOT_HD_ACCOUNT_SEED = 5;
    private String content;
    private List<String> worlds;
    protected SecureCharSequence password;

    private ImportHDSeedType importPrivateKeyType;


    public ImportHDSeed(ImportHDSeedType importHDSeedType
            , String content, List<String> worlds, SecureCharSequence password) {
        this.content = content;
        this.password = password;
        this.importPrivateKeyType = importHDSeedType;
        this.worlds = worlds;
    }

    public HDMKeychain importHDMKeychain() {
        switch (this.importPrivateKeyType) {
            case HDMColdSeedQRCode:
                if (content.indexOf(QRCodeUtil.HDM_QR_CODE_FLAG) == 0) {
                    String keyString = content.substring(1);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[0], passwordSeeds[1], passwordSeeds[2]}, QRCodeUtil.QR_CODE_SPLIT);
                    PasswordSeed passwordSeed = PasswordSeed.getPasswordSeed();
                    if (passwordSeed != null && !passwordSeed.checkPassword(password)) {
                        importError(PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    }
                    try {
                        return new HDMKeychain(new EncryptedData(encreyptString)
                                , password, null);

                    } catch (Exception e) {
                        importError(IMPORT_FAILED);
                        e.printStackTrace();
                        return null;
                    }

                } else {
                    importError(NOT_HDM_COLD_SEED);
                    return null;
                }

            case HDMColdPhrase:
                try {
                    byte[] mnemonicCodeSeed = MnemonicCode.instance().toEntropy(worlds);
                    HDMKeychain hdmKeychain = new HDMKeychain(mnemonicCodeSeed, password);
                    return hdmKeychain;
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                }
                return null;

        }
        return null;

    }

    public HDAccountCold importHDAccountCold() {
        switch (importPrivateKeyType) {
            case HDSeedQRCode:

                if (content.indexOf(QRCodeUtil.HD_QR_CODE_FLAG) == 0) {
                    String keyString = content.substring(1);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[0],
                            passwordSeeds[1], passwordSeeds[2]}, QRCodeUtil.QR_CODE_SPLIT);
                    PasswordSeed passwordSeed = PasswordSeed.getPasswordSeed();
                    if (passwordSeed != null && !passwordSeed.checkPassword(password)) {
                        importError(PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    }
                    try {
                        return new HDAccountCold(new EncryptedData(encreyptString), password);
                    } catch (Exception e) {
                        importError(IMPORT_FAILED);
                        e.printStackTrace();
                        return null;
                    }

                } else {
                    importError(NOT_HD_ACCOUNT_SEED);
                    return null;
                }
            case HDSeedPhrase:
                try {
                    byte[] mnemonicCodeSeed = MnemonicCode.instance().toEntropy(worlds);
                    HDAccountCold hdAccount = new HDAccountCold(mnemonicCodeSeed, password, false);
                    return hdAccount;
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                }
                return null;
        }
        return null;
    }

    public HDAccount importHDAccount() {
        switch (importPrivateKeyType) {
            case HDSeedQRCode:

                if (content.indexOf(QRCodeUtil.HD_QR_CODE_FLAG) == 0) {
                    String keyString = content.substring(1);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[0], passwordSeeds[1], passwordSeeds[2]}, QRCodeUtil.QR_CODE_SPLIT);
                    PasswordSeed passwordSeed = PasswordSeed.getPasswordSeed();
                    if (passwordSeed != null && !passwordSeed.checkPassword(password)) {
                        importError(PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    }
                    try {
                        return new HDAccount(new EncryptedData(encreyptString)
                                , password, false);
                    } catch (Exception e) {
                        importError(IMPORT_FAILED);
                        e.printStackTrace();
                        return null;
                    }

                } else {
                    importError(NOT_HD_ACCOUNT_SEED);
                    return null;
                }
            case HDSeedPhrase:
                try {
                    byte[] mnemonicCodeSeed = MnemonicCode.instance().toEntropy(worlds);
                    HDAccount hdAccount = new HDAccount(mnemonicCodeSeed, password, false);
                    return hdAccount;
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                }
                return null;
        }
        return null;

    }

    public abstract void importError(int errorCode);

}
