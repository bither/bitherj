/**
 * Copyright 2013 Jim Burton.
 * Copyright 2014 Andreas Schildbach
 * <p/>
 * Licensed under the MIT license (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://opensource.org/licenses/mit-license.php
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.crypto;

import junit.framework.Assert;

import net.bither.bitherj.utils.Utils;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

public class KeyCrypterScryptTest {
    private final Logger log = LoggerFactory.getLogger(KeyCrypterScryptTest.class);

    // Nonsense bytes for encryption test.
    private final byte[] TEST_BYTES1 = {0, -101, 2, 103, -4, 105, 6, 107, 8, -109, 10, 111, -12, 113, 14, -115, 16, 117, -18, 119, 20, 121, 22, 123, -24, 125, 26, 127, -28, 29, -30, 31};

    private final CharSequence PASSWORD1 = "aTestPassword";
    private final CharSequence PASSWORD2 = "0123456789";

    private final CharSequence WRONG_PASSWORD = "thisIsTheWrongPassword";

    //    private ScryptParameters scryptParameters;
    private byte[] salt;

    public KeyCrypterScryptTest() {
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(KeyCrypterScrypt.SALT_LENGTH);
        this.salt = salt;
    }

    @Test
    public void testKeyCrypterGood1() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(salt);

        // Encrypt.
        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        Assert.assertNotNull(encryptedPrivateKey);

        // Decrypt.
        byte[] reborn = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));
        log.debug("Original: " + Utils.bytesToHexString(TEST_BYTES1));
        log.debug("Reborn  : " + Utils.bytesToHexString(reborn));
        Assert.assertEquals(Utils.bytesToHexString(TEST_BYTES1), Utils.bytesToHexString(reborn));
    }

    /**
     * Test with random plain text strings and random passwords.
     * UUIDs are used and hence will only cover hex characters (and the separator hyphen).
     *
     * @throws KeyCrypterException
     * @throws java.io.UnsupportedEncodingException
     */
    @Test
    public void testKeyCrypterGood2() throws Exception {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(salt);

        System.out.print("EncrypterDecrypterTest: Trying  UUIDs for plainText and passwords :");
        int numberOfTests = 16;
        for (int i = 0; i < numberOfTests; i++) {
            // Create a UUID as the plaintext and use another for the password.
            String plainText = UUID.randomUUID().toString();
            CharSequence password = UUID.randomUUID().toString();

            EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(plainText.getBytes(), keyCrypter.deriveKey(password));

            Assert.assertNotNull(encryptedPrivateKey);

            byte[] reconstructedPlainBytes = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(password));
            Assert.assertEquals(Utils.bytesToHexString(plainText.getBytes()), Utils.bytesToHexString(reconstructedPlainBytes));
            System.out.print('.');
        }
        System.out.println(" Done.");
    }

    @Test
    public void testKeyCrypterWrongPassword() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(salt);

        // create a longer encryption string
        StringBuilder stringBuffer = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            stringBuffer.append(i).append(" ").append("The quick brown fox");
        }

        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(stringBuffer.toString().getBytes(), keyCrypter.deriveKey(PASSWORD2));
        Assert.assertNotNull(encryptedPrivateKey);

        try {
            keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(WRONG_PASSWORD));
            // TODO: This test sometimes fails due to relying on padding.
            Assert.fail("Decrypt with wrong password did not throw exception");
        } catch (KeyCrypterException ede) {
            Assert.assertTrue(ede.getMessage().contains("Could not decrypt"));
        }
    }

    @Test
    public void testEncryptDecryptBytes1() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(salt);

        // Encrypt bytes.
        EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(TEST_BYTES1, keyCrypter.deriveKey(PASSWORD1));
        Assert.assertNotNull(encryptedPrivateKey);
        log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + encryptedPrivateKey.getEncryptedBytes().length + "\n---------------\n" + Utils.bytesToHexString(encryptedPrivateKey.getEncryptedBytes()) + "\n---------------\n");

        byte[] rebornPlainBytes = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));

        log.debug("Original: " + Utils.bytesToHexString(TEST_BYTES1));
        log.debug("Reborn1 : " + Utils.bytesToHexString(rebornPlainBytes));
        Assert.assertEquals(Utils.bytesToHexString(TEST_BYTES1), Utils.bytesToHexString(rebornPlainBytes));
    }

    @Test
    public void testEncryptDecryptBytes2() throws KeyCrypterException {
        KeyCrypterScrypt keyCrypter = new KeyCrypterScrypt(salt);

        // Encrypt random bytes of various lengths up to length 50.
        Random random = new Random();

        for (int i = 0; i < 50; i++) {
            byte[] plainBytes = new byte[i];
            random.nextBytes(plainBytes);

            EncryptedPrivateKey encryptedPrivateKey = keyCrypter.encrypt(plainBytes, keyCrypter.deriveKey(PASSWORD1));
            Assert.assertNotNull(encryptedPrivateKey);
            //log.debug("\nEncrypterDecrypterTest: cipherBytes = \nlength = " + cipherBytes.length + "\n---------------\n" + Utils.HEX.encode(cipherBytes) + "\n---------------\n");

            byte[] rebornPlainBytes = keyCrypter.decrypt(encryptedPrivateKey, keyCrypter.deriveKey(PASSWORD1));

            log.debug("Original: (" + i + ") " + Utils.bytesToHexString(plainBytes));
            log.debug("Reborn1 : (" + i + ") " + Utils.bytesToHexString(rebornPlainBytes));
            Assert.assertEquals(Utils.bytesToHexString(plainBytes), Utils.bytesToHexString(rebornPlainBytes));
        }
    }
}
