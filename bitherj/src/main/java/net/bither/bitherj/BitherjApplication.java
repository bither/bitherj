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

import android.app.Application;
import android.content.Context;
import android.database.sqlite.SQLiteOpenHelper;

import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.crypto.IRandom;
import net.bither.bitherj.db.BitherjDatabaseHelper;

import org.slf4j.LoggerFactory;

import java.io.File;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.android.LogcatAppender;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;

public abstract class BitherjApplication extends Application {


    public static Context mContext;
    public static SQLiteOpenHelper mDbHelper;
    public static boolean addressIsReady = false;


    @Override
    public void onCreate() {
        mContext = getApplicationContext();
        mDbHelper = new BitherjDatabaseHelper(mContext);
        super.onCreate();
        App.notificationService.removeAddressLoadCompleteState();
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        mDbHelper.close();
    }





}
