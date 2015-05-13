package net.bither.bitherj.core;

import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Created by songchenwen on 15/1/6.
 */
public class MultisigAddressTest {
    // first test case comes from https://gist.github.com/gavinandresen/3966071
    TestCase[] cases = new TestCase[]{
            new TestCase(new HDMAddress.Pubs(
                    Utils.hexStringToByteArray("0491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f86"),
                    Utils.hexStringToByteArray("04865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec6874"),
                    Utils.hexStringToByteArray("048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d46213"),
                    0),
                    "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
                    "52410491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f864104865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec687441048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d4621353ae")
    };

    @Test
    public void testMultisigAddress() {
        for (int i = 0; i < cases.length; i++) {
            TestCase c = cases[i];
            assertArrayEquals("script program not match", c.script, c.pubs.getMultiSigScript().getProgram());
            System.out.println("\nscript program match: " + Utils.bytesToHexString(c.script));
            String a = c.pubs.getAddress();
            assertEquals("address not match", a, c.address);
            System.out.println("\naddress match: " + a);
        }
    }

    private static final class TestCase {
        HDMAddress.Pubs pubs;
        String address;
        byte[] script;

        TestCase(HDMAddress.Pubs pubs, String address, String script) {
            this.pubs = pubs;
            this.address = address;
            this.script = Utils.hexStringToByteArray(script);
        }
    }
}
