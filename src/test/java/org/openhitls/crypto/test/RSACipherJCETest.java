package org.openhitls.crypto.test;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    @Test
    public void testRSAEncryptDecryptWithNonDefaultPublicExponentAfterImport() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "HITLS4J");
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "HITLS4J");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = encryptCipher.doFinal(TEST_DATA);

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = decryptCipher.doFinal(encrypted);

        assertArrayEquals("Imported non-65537 RSA key should decrypt with its real public exponent",
                TEST_DATA, decrypted);
    }

    @Test
    public void testMinimalRSAPrivateKeyDecryptionRejectedAtInit() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "HITLS4J");
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "HITLS4J");

        PrivateKey minimalPrivate = keyFactory.generatePrivate(
                new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent()));

        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = encryptCipher.doFinal(
                "RSA private key without public exponent is rejected during cipher init"
                        .getBytes(StandardCharsets.UTF_8));

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        try {
            decryptCipher.init(Cipher.DECRYPT_MODE, minimalPrivate);
            fail("Expected RSA cipher init to reject private key without public exponent");
        } catch (InvalidKeyException expected) {
            assertTrue("Failure should identify the missing public exponent",
                    expected.getMessage().contains("public exponent"));
        }
        assertNotNull("Encrypted data should still be produced by the valid public key", encrypted);
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
