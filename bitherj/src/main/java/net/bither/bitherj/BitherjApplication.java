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
import android.content.Intent;
import android.database.sqlite.SQLiteOpenHelper;

import net.bither.bitherj.core.AddressManager;
import net.bither.bitherj.crypto.URandom;
import net.bither.bitherj.db.BitherjDatabaseHelper;
import net.bither.bitherj.utils.NotificationUtil;
import net.bither.bitherj.utils.Utils;

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
    protected static IBitherjApp mIinitialize;
    public static boolean addressIsReady = false;

    @Override
    public void onCreate() {
        mContext = getApplicationContext();
        init();
        mDbHelper = new BitherjDatabaseHelper(mContext);
        super.onCreate();
        new URandom();
        NotificationUtil.removeAddressLoadCompleteState();
        initApp();

    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        mDbHelper.close();
    }

    public static IBitherjApp getInitialize() {
        return mIinitialize;

    }

    public abstract void init();

    private void initLogging() {
        final File logDir = BitherjApplication.mContext.getDir("log", Context.MODE_WORLD_READABLE);
        final File logFile = new File(logDir, "bitherj.log");
        final LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        final PatternLayoutEncoder filePattern = new PatternLayoutEncoder();
        filePattern.setContext(context);
        filePattern.setPattern("%d{HH:mm:ss.SSS} [%thread] %logger{0} - %msg%n");
        filePattern.start();

        final RollingFileAppender<ILoggingEvent> fileAppender = new
                RollingFileAppender<ILoggingEvent>();
        fileAppender.setContext(context);
        fileAppender.setFile(logFile.getAbsolutePath());

        final TimeBasedRollingPolicy<ILoggingEvent> rollingPolicy = new
                TimeBasedRollingPolicy<ILoggingEvent>();
        rollingPolicy.setContext(context);
        rollingPolicy.setParent(fileAppender);
        rollingPolicy.setFileNamePattern(logDir.getAbsolutePath() + "/bitherj.%d.log.gz");
        rollingPolicy.setMaxHistory(7);
        rollingPolicy.start();

        fileAppender.setEncoder(filePattern);
        fileAppender.setRollingPolicy(rollingPolicy);
        fileAppender.start();

        final PatternLayoutEncoder logcatTagPattern = new PatternLayoutEncoder();
        logcatTagPattern.setContext(context);
        logcatTagPattern.setPattern("%logger{0}");
        logcatTagPattern.start();

        final PatternLayoutEncoder logcatPattern = new PatternLayoutEncoder();
        logcatPattern.setContext(context);
        logcatPattern.setPattern("[%thread] %msg%n");
        logcatPattern.start();

        final LogcatAppender logcatAppender = new LogcatAppender();
        logcatAppender.setContext(context);
        logcatAppender.setTagEncoder(logcatTagPattern);
        logcatAppender.setEncoder(logcatPattern);
        logcatAppender.start();

        final ch.qos.logback.classic.Logger log = context.getLogger(Logger.ROOT_LOGGER_NAME);
        log.addAppender(fileAppender);
        log.addAppender(logcatAppender);
        log.setLevel(Level.INFO);
    }

    private void initApp() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                AddressManager.getInstance();
                initLogging();
            }
        }).start();
    }

    public static void sendConnectedChangeBroadcast(String connectedChangeBroadcast, boolean isConnected) {
        Intent intent = new Intent(connectedChangeBroadcast);
        intent.putExtra(connectedChangeBroadcast, isConnected);
        BitherjApplication.mContext.sendBroadcast(intent);
    }

    public static File getPrivateDir(String dirName) {
        File file = BitherjApplication.mContext.getDir(dirName, Context.MODE_PRIVATE);
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }
}
