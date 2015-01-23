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

import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.SecureCharSequence;
import net.bither.bitherj.qrcode.QRCodeUtil;
import net.bither.bitherj.utils.Utils;

public abstract class ImportHDSeed {
    public enum ImportHDSeedType {
        HDMColdSeedQRCode, HDMColdPhrase
    }

    public static final int PASSWORD_IS_DIFFEREND_LOCAL = 0;
    public static final int NOT_HDM_COLD_SEED = 1;

    private String content;
    protected SecureCharSequence password;

    private ImportHDSeedType importPrivateKeyType;


    public ImportHDSeed(ImportHDSeedType importHDSeedType
            , String content, SecureCharSequence password) {
        this.content = content;
        this.password = password;
        this.importPrivateKeyType = importHDSeedType;
    }

    public HDMKeychain importHDSeed() {
        switch (this.importPrivateKeyType) {
            case HDMColdSeedQRCode:
                if (content.indexOf(QRCodeUtil.HDM_QR_CODE_FLAG) == 0) {
                    String keyString = content.substring(1);
                    String[] passwordSeeds = QRCodeUtil.splitOfPasswordSeed(keyString);
                    String encreyptString = Utils.joinString(new String[]{passwordSeeds[1], passwordSeeds[2], passwordSeeds[3]}, QRCodeUtil.QR_CODE_SPLIT);
                    EncryptedData encryptedData = new EncryptedData(encreyptString);
                    byte[] result = null;
                    try {
                        result = encryptedData.decrypt(this.password);
                    } catch (Exception e) {
                        e.printStackTrace();
                        return null;

                    }
                    if (result == null) {
                        importError(ImportPrivateKey.PASSWORD_IS_DIFFEREND_LOCAL);
                        return null;
                    } else {
                        try {
                            return new HDMKeychain(new EncryptedData(encreyptString)
                                    , password, null);

                        } catch (Exception e) {
                            e.printStackTrace();
                            return null;
                        }
                    }
                } else {
                    importError(NOT_HDM_COLD_SEED);
                    return null;
                }

            case HDMColdPhrase:
                return null;

        }
        return null;

    }

    public abstract void importError(int errorCode);

}
