/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.crypto.test;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.openhitls.crypto.jce.key.generator.RSAKeyPairGenerator;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class RSACipherTest {
    private static final int[] KEY_SIZES = {1024, 2048, 3072};
    private static final byte[] TEST_DATA = "Hello, RSA encryption test!".getBytes();

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testRSAEncryptDecrypt() throws Exception {
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
    public void testRSAEncryptDecryptWithNoPadding() throws Exception {
        // Generate 2048-bit key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Create test data that matches the block size
        int blockSize = encryptCipher.getBlockSize();
        byte[] testData = new byte[blockSize];
        new SecureRandom().nextBytes(testData);

        // Encrypt test data
        byte[] encrypted = encryptCipher.doFinal(testData);
        assertNotNull("Encrypted data should not be null", encrypted);
        assertFalse("Encrypted data should be different from original", Arrays.equals(testData, encrypted));

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NoPadding", "HITLS4J");
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Decrypt data
        byte[] decrypted = decryptCipher.doFinal(encrypted);
        assertNotNull("Decrypted data should not be null", decrypted);
        assertArrayEquals("Decrypted data should match original", testData, decrypted);
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void testRSAEncryptWithLargeData() throws Exception {
        // Generate 2048-bit key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Create test data larger than the maximum allowed size
        byte[] largeData = new byte[300]; // Larger than RSA block size
        new SecureRandom().nextBytes(largeData);

        // This should throw IllegalBlockSizeException
        encryptCipher.doFinal(largeData);
    }

    @Test(expected = IllegalStateException.class)
    public void testRSAEncryptWithUpdate() throws Exception {
        // Generate 2048-bit key pair
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // This should throw IllegalStateException
        encryptCipher.update(TEST_DATA);
    }
} 
