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

package net.bither.bitherj;

import net.bither.bitherj.qrcode.QRCodeUtil;

import org.apache.http.client.CookieStore;

import java.io.File;

public abstract class ISetting {

    private static final int HDM_ADDRESS_PER_SEED_COUNT_LIMIT = 100;
    private static final int HDM_ADDRESS_PER_SEED_PREPARE_COUNT = 100;
    private static final int WATCH_ONLY_ADDRESS_COUNT_LIMIT = 150;
    private static final int PRIVATE_KEY_OF_HOT_COUNT_LIMIT = 50;

    public abstract BitherjSettings.AppMode getAppMode();

    public abstract boolean getBitherjDoneSyncFromSpv();

    public abstract void setBitherjDoneSyncFromSpv(boolean isDone);

    public abstract boolean getDownloadSpvFinish();

    public abstract void setDownloadSpvFinish(boolean finish);

    public abstract QRCodeUtil.QRQuality getQRQuality();

    public abstract BitherjSettings.TransactionFeeMode getTransactionFeeMode();

    public abstract BitherjSettings.ApiConfig getApiConfig();

    public abstract File getPrivateDir(String dirName);

    public abstract boolean isApplicationRunInForeground();

    public abstract CookieStore getCookieStore();

    public int hdmAddressPerSeedCount() {
        return HDM_ADDRESS_PER_SEED_COUNT_LIMIT;
    }

    public int hdmAddressPerSeedPrepareCount() {
        return HDM_ADDRESS_PER_SEED_PREPARE_COUNT;
    }

    public int watchOnlyAddressCountLimit() {
        return WATCH_ONLY_ADDRESS_COUNT_LIMIT;
    }

    public int privateKeyOfHotCountLimit() {
        return PRIVATE_KEY_OF_HOT_COUNT_LIMIT;
    }

}
