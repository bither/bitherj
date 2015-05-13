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
import net.bither.bitherj.ISetting;
import net.bither.bitherj.NotificationService;
import net.bither.bitherj.api.TrustCert;
import net.bither.bitherj.qrcode.QRCodeUtil;

import org.apache.http.client.CookieStore;
import org.apache.http.impl.client.BasicCookieStore;

import java.io.File;

public class TestImplAbstractApp extends AbstractApp {
    private CookieStore cookieStore = new BasicCookieStore();

    @Override
    public TrustCert initTrustCert() {
        return null;
    }

    @Override
    public ISetting initSetting() {
        return new ISetting() {
            @Override
            public BitherjSettings.AppMode getAppMode() {
                return BitherjSettings.AppMode.HOT;
            }

            @Override
            public boolean getBitherjDoneSyncFromSpv() {
                return true;
            }

            @Override
            public void setBitherjDoneSyncFromSpv(boolean isDone) {
                // AppSharedPreference.getInstance().setBitherjDoneSyncFromSpv(isDone);
            }

            @Override
            public BitherjSettings.TransactionFeeMode getTransactionFeeMode() {
                return BitherjSettings.TransactionFeeMode.Low;
            }

            @Override
            public File getPrivateDir(String dirName) {
                File file = new File("test/wallet");
                if (!file.exists()) {
                    file.mkdirs();
                }
                return file;
            }

            @Override
            public boolean isApplicationRunInForeground() {

                return true;
            }

            @Override
            public QRCodeUtil.QRQuality getQRQuality() {
                return QRCodeUtil.QRQuality.Normal;
            }

            @Override
            public boolean getDownloadSpvFinish() {
                return true;
            }

            @Override
            public void setDownloadSpvFinish(boolean finish) {
                // AppSharedPreference.getInstance().setDownloadSpvFinish(finish);
            }

            @Override
            public CookieStore getCookieStore() {
                return cookieStore;
            }


        };
    }

    @Override
    public NotificationService initNotification() {
        return null;
    }
}
