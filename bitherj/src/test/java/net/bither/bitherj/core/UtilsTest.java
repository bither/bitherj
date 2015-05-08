package net.bither.bitherj.core;

import net.bither.bitherj.utils.Utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilsTest {
    @Test
    public void testPassword() {
        String password = "0aA`~!@#$%^&*()_-+={}[]|:;\\\"'<>,.?/";
        boolean validP = Utils.validPassword(password);
        assertTrue(validP);
        password = "ASDF简繁";
        assertFalse(Utils.validPassword(password));
    }
}
