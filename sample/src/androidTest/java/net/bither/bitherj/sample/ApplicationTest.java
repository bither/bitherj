package net.bither.bitherj.sample;

import android.app.Application;
import android.test.ApplicationTestCase;

import net.bither.bitherj.sample.core.BlockTest;
import net.bither.bitherj.sample.core.TxTest;


/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public  class ApplicationTest extends ApplicationTestCase<BitherjTestApplication> {
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
        BlockTest blockTest = new BlockTest();
        blockTest.testText();
        TxTest txTest = new TxTest();
        txTest.testDb();
    }
}
