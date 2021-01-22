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

import net.bither.bitherj.api.BitherErrorApi;
import net.bither.bitherj.core.AbstractHD;
import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.core.HDAccount;
import net.bither.bitherj.core.HDAccountCold;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.crypto.mnemonic.MnemonicCode;
import net.bither.bitherj.crypto.mnemonic.MnemonicWordList;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
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
    public static final int DUPLICATED_HD_ACCOUNT_SEED = 6;
    private String content;
    private List<String> worlds;
    protected SecureCharSequence password;

    private ImportHDSeedType importPrivateKeyType;
    protected MnemonicCode mnemonicCode = MnemonicCode.instance();


    public ImportHDSeed(ImportHDSeedType importHDSeedType
            , String content, List<String> worlds, SecureCharSequence password, MnemonicCode mnemonicCode) {
        this.content = content;
        this.password = password;
        this.importPrivateKeyType = importHDSeedType;
        this.worlds = worlds;
        this.mnemonicCode = mnemonicCode;
    }

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
                        e.printStackTrace();
                        importError(IMPORT_FAILED);
                        uploadError(e);
                        return null;
                    }

                } else {
                    importError(NOT_HDM_COLD_SEED);
                    return null;
                }

            case HDMColdPhrase:
                try {
                    byte[] mnemonicCodeSeed = mnemonicCode.toEntropy(worlds);
                    HDMKeychain hdmKeychain = new HDMKeychain(mnemonicCodeSeed, password);
                    return hdmKeychain;
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                    uploadError(e);
                }
                return null;

        }
        return null;

    }

    public HDAccountCold importHDAccountCold() {
        HDAccountCold hdAccount = null;
        switch (importPrivateKeyType) {
            case HDSeedQRCode:
                int hdQrCodeFlagLength = MnemonicWordList.getHdQrCodeFlagLength(content, mnemonicCode.getMnemonicWordList());
                if (hdQrCodeFlagLength > 0) {
                    String keyString = content.substring(hdQrCodeFlagLength);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[0],
                            passwordSeeds[1], passwordSeeds[2]}, QRCodeUtil.QR_CODE_SPLIT);
                    PasswordSeed passwordSeed = PasswordSeed.getPasswordSeed();
                    if (passwordSeed != null && !passwordSeed.checkPassword(password)) {
                        importError(PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    }
                    try {
                        hdAccount = new HDAccountCold(mnemonicCode, new EncryptedData(encreyptString), password);
                    } catch (Exception e) {
                        e.printStackTrace();
                        importError(IMPORT_FAILED);
                        uploadError(e);
                    }
                } else {
                    importError(NOT_HD_ACCOUNT_SEED);
                }
                break;
            case HDSeedPhrase:
                try {
                    byte[] mnemonicCodeSeed = mnemonicCode.toEntropy(worlds);
                    hdAccount = new HDAccountCold(mnemonicCode, mnemonicCodeSeed, password, false);
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                    uploadError(e);
                }
                break;
        }
        return hdAccount;
    }

    public HDAccount importHDAccount() {
        HDAccount hdAccount = null;
        switch (importPrivateKeyType) {
            case HDSeedQRCode:
                int hdQrCodeFlagLength = MnemonicWordList.getHdQrCodeFlagLength(content, mnemonicCode.getMnemonicWordList());
                if (hdQrCodeFlagLength > 0) {
                    String keyString = content.substring(hdQrCodeFlagLength);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[0], passwordSeeds[1], passwordSeeds[2]}, QRCodeUtil.QR_CODE_SPLIT);
                    PasswordSeed passwordSeed = PasswordSeed.getPasswordSeed();
                    if (passwordSeed != null && !passwordSeed.checkPassword(password)) {
                        importError(PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    }
                    try {
                        hdAccount = new HDAccount(mnemonicCode, new EncryptedData(encreyptString)
                                , password, false);
                    } catch (HDAccount.DuplicatedHDAccountException e) {
                        e.printStackTrace();
                        importError(DUPLICATED_HD_ACCOUNT_SEED);
                    } catch (Exception e) {
                        e.printStackTrace();
                        importError(IMPORT_FAILED);
                        uploadError(e);
                    }
                } else {
                    importError(NOT_HD_ACCOUNT_SEED);
                }
                break;
            case HDSeedPhrase:
                try {
                    byte[] mnemonicCodeSeed = mnemonicCode.toEntropy(worlds);
                    hdAccount = new HDAccount(mnemonicCode, mnemonicCodeSeed, password, false);
                }  catch (HDAccount.DuplicatedHDAccountException e) {
                    e.printStackTrace();
                    importError(DUPLICATED_HD_ACCOUNT_SEED);
                } catch (Exception e) {
                    e.printStackTrace();
                    importError(IMPORT_FAILED);
                    uploadError(e);
                }
                break;
        }
        return hdAccount;
    }

    public abstract void importError(int errorCode);

    private void uploadError(final Exception ex) {
        PrintStream printStream = null;
        ByteArrayOutputStream baos = null;
        try {
            baos = new ByteArrayOutputStream();
            printStream = new PrintStream(baos);
            ex.printStackTrace(printStream);
            String exception = baos.toString();
            if (!Utils.isEmpty(exception)) {
                BitherErrorApi addFeedbackApi = new BitherErrorApi(exception);
                addFeedbackApi.handleHttpPost();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (printStream != null) {
                    printStream.close();
                }
                if (baos != null) {
                    baos.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
