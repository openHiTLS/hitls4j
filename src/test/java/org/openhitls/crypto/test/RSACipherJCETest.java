package org.openhitls.crypto.test;

import org.junit.Test;
import static org.junit.Assert.*;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.openhitls.crypto.jce.key.generator.RSAKeyPairGenerator;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class RSACipherJCETest {
    private static final int[] KEY_SIZES = {1024, 2048, 3072};
    private static final byte[] TEST_DATA = "Hello, RSA encryption test!".getBytes();

    static {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testRSAEncryptDecryptWithJCE() throws Exception {
        for (int keySize : KEY_SIZES) {
            // Generate key pair
            RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
            keyGen.initialize(keySize, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            // Encrypt test data
            byte[] encrypted = encryptCipher.doFinal(TEST_DATA);
            assertNotNull("Encrypted data should not be null", encrypted);
            assertFalse("Encrypted data should be different from original", Arrays.equals(TEST_DATA, encrypted));

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            // Decrypt data
            byte[] decrypted = decryptCipher.doFinal(encrypted);
            assertNotNull("Decrypted data should not be null", decrypted);
            assertArrayEquals("Decrypted data should match original", TEST_DATA, decrypted);
        }
    }

    @Test
    public void testRSAEncryptDecryptLargeDataWithJCE() throws Exception {
        // Generate 2048-bit key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create large test data (240 bytes, which is close to the maximum for 2048-bit RSA with PKCS#1 padding)
        byte[] largeData = new byte[240];
        new SecureRandom().nextBytes(largeData);

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Encrypt test data
        byte[] encrypted = encryptCipher.doFinal(largeData);
        assertNotNull("Encrypted data should not be null", encrypted);
        assertFalse("Encrypted data should be different from original", Arrays.equals(largeData, encrypted));

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Decrypt data
        byte[] decrypted = decryptCipher.doFinal(encrypted);
        assertNotNull("Decrypted data should not be null", decrypted);
        assertArrayEquals("Decrypted data should match original", largeData, decrypted);
    }

    @Test(expected = IllegalStateException.class)
    public void testEncryptWithInvalidKey() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        cipher.doFinal(TEST_DATA);
    }

    @Test
    public void testRSAWithDifferentPaddingModes() throws Exception {
        // Generate 2048-bit key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        String[] paddingModes = {"RSA/ECB/PKCS1Padding", "RSA/ECB/NoPadding"};
        
        for (String paddingMode : paddingModes) {
            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance(paddingMode, "HITLS4J");
            encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            // For NoPadding, ensure data is exactly the right length
            byte[] testData = paddingMode.contains("NoPadding") ? 
                new byte[encryptCipher.getBlockSize()] : TEST_DATA;
            if (paddingMode.contains("NoPadding")) {
                new SecureRandom().nextBytes(testData);
            }

            // Encrypt test data
            byte[] encrypted = encryptCipher.doFinal(testData);
            assertNotNull("Encrypted data should not be null", encrypted);
            assertFalse("Encrypted data should be different from original", Arrays.equals(testData, encrypted));

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance(paddingMode, "HITLS4J");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            // Decrypt data
            byte[] decrypted = decryptCipher.doFinal(encrypted);
            assertNotNull("Decrypted data should not be null", decrypted);
            assertArrayEquals("Decrypted data should match original", testData, decrypted);
        }
    }
} 