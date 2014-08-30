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

package net.bither.bitherj.test;

import android.test.ApplicationTestCase;

import net.bither.bitherj.BitherjApplication;
import net.bither.bitherj.test.core.BlockTest;
import net.bither.bitherj.test.core.TxTest;

/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public class ApplicationTest extends ApplicationTestCase<BitherjTestApplication> {
    public ApplicationTest() {
        super(BitherjTestApplication.class);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        createApplication();
    }

    public void testApp() {
       // assertEquals(BitherjApplication.mContext, null);
       // assertEquals(BitherjApplication.mDbHelper,null);
         BlockTest blockTest=new BlockTest();
        blockTest.testText();
        TxTest txTest=new TxTest();
        txTest.testDb();
    }
}