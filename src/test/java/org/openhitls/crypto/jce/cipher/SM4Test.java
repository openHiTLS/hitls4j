package org.openhitls.crypto.jce.cipher;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SM4Test extends BaseTest {
    private static final byte[] TEST_KEY = new byte[] {
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10
    };

    private static final byte[] TEST_KEY_XTS = new byte[] {
        // First 16-byte key
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10,
        // Second 16-byte key
        (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18,
        (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f, (byte)0x20
    };

    private static final byte[] TEST_IV = new byte[] {
        (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88,
        (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff, (byte)0x00
    };

    private static final byte[] TEST_DATA = new byte[] {
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10,
        (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18,
        (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f, (byte)0x20
    };

    // Test data that's not block aligned (20 bytes)
    private static final byte[] UNALIGNED_DATA = new byte[] {
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
        (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10,
        (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14
    };

    @Test
    public void testSm4KeyGen() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", HiTls4jProvider.PROVIDER_NAME);
        keyGen.init(128);
        byte[] key = keyGen.generateKey().getEncoded();
        assertEquals(128 / 8, key.length);
    }

    @Test
    public void testSm4CbcJce() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key and IV specifications
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/CBC/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/CBC/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }
    
    @Test
    public void testSm4CtrJce() {
        try {
            // Register HITLS provider if not already registered
            if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HiTls4jProvider());
            }

            // Create key and IV specifications
            SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("SM4/CTR/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // Encrypt the test data
            byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("SM4/CTR/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypt the data
            byte[] decryptedData = decryptCipher.doFinal(encryptedData);

            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);

            // Test with unaligned data
            encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);
            decryptedData = decryptCipher.doFinal(encryptedData);
            assertArrayEquals("Decrypted unaligned data should match original", UNALIGNED_DATA, decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testSm4CfbJce() {
        try {
            // Register HITLS provider if not already registered
            if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HiTls4jProvider());
            }

            // Create key and IV specifications
            SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("SM4/CFB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // Encrypt the test data
            byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("SM4/CFB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypt the data
            byte[] decryptedData = decryptCipher.doFinal(encryptedData);

            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);

            // Test with unaligned data
            encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);
            decryptedData = decryptCipher.doFinal(encryptedData);
            assertArrayEquals("Decrypted unaligned data should match original", UNALIGNED_DATA, decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testSm4OfbJce() {
        try {
            // Register HITLS provider if not already registered
            if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HiTls4jProvider());
            }

            // Create key and IV specifications
            SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("SM4/OFB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // Encrypt the test data
            byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("SM4/OFB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypt the data
            byte[] decryptedData = decryptCipher.doFinal(encryptedData);

            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);

            // Test with unaligned data
            encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);
            decryptedData = decryptCipher.doFinal(encryptedData);
            assertArrayEquals("Decrypted unaligned data should match original", UNALIGNED_DATA, decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception occurred: " + e.getMessage());
        }
    }

     @Test
    public void testSm4GcmEncryptionDecryption() throws Exception {
        // Create key and IV specifications
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
    
        // Generate IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        
        // Generate Aad
        byte[] aad = new byte[16];
        new SecureRandom().nextBytes(aad);
        
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        
        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        encryptCipher.updateAAD(aad);
        byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        decryptCipher.updateAAD(aad);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);
    }

    // @Test
    // public void testSm4GcmJce() {
    //     try {
    //         // Register HITLS provider if not already registered
    //         if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
    //             Security.addProvider(new HiTls4jProvider());
    //         }

    //         // Create key and IV specifications
    //         SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
    //         // Generate IV
    //         byte[] iv = new byte[16];
    //         new SecureRandom().nextBytes(iv);
            
    //         // Generate Aad
    //         byte[] aad = new byte[16];
    //         new SecureRandom().nextBytes(aad);
            
    //         GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

    //         // Initialize cipher for encryption
    //         Cipher encryptCipher = Cipher.getInstance("SM4/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
    //         encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            
    //         // Encrypt the test data
    //         byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

    //         // Initialize cipher for decryption
    //         Cipher decryptCipher = Cipher.getInstance("SM4/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
    //         decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

    //         // Decrypt the data
    //         byte[] decryptedData = decryptCipher.doFinal(encryptedData);

    //         // Verify the decrypted data matches the original
    //         assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);

    //         // Test with unaligned data
    //         encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);
    //         decryptedData = decryptCipher.doFinal(encryptedData);
    //         assertArrayEquals("Decrypted unaligned data should match original", UNALIGNED_DATA, decryptedData);
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //         fail("Exception occurred: " + e.getMessage());
    //     }
    // }

    @Test
    public void testSm4XtsJce() {
        try {
            // Register HITLS provider if not already registered
            if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new HiTls4jProvider());
            }

            // Create key and IV specifications
            SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY_XTS, "SM4");
            IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("SM4/XTS/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            // For XTS mode, input length must be at least one block (16 bytes)
            byte[] testData = new byte[32];  // Using 2 blocks for testing
            System.arraycopy(TEST_DATA, 0, testData, 0, 32);

            // Encrypt the test data
            byte[] encryptedData = encryptCipher.doFinal(testData);

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("SM4/XTS/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

            // Decrypt the data
            byte[] decryptedData = decryptCipher.doFinal(encryptedData);

            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", testData, decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testSm4CbcPkcs5JceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key and IV specifications
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }

    @Test
    public void testSm4CbcIso7816JceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key and IV specifications
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/CBC/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/CBC/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }

    @Test
    public void testSm4CbcZerosJceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key and IV specifications
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(TEST_IV);

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/CBC/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/CBC/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // For zeros padding, we need to trim trailing zeros
        int actualLength = UNALIGNED_DATA.length;
        byte[] trimmedDecrypted = Arrays.copyOf(decryptedData, actualLength);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, trimmedDecrypted);
    }

    @Test
    public void testSm4EcbPkcs7JceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key specification
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/ECB/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/ECB/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }

    @Test
    public void testSm4EcbPkcs5JceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key specification
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/ECB/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/ECB/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }

    @Test
    public void testSm4EcbIso7816JceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key specification
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/ECB/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/ECB/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, decryptedData);
    }

    @Test
    public void testSm4EcbZerosJceTest() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Create key specification
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "SM4");

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM4/ECB/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec);

        // Encrypt the test data
        byte[] encryptedData = encryptCipher.doFinal(UNALIGNED_DATA);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM4/ECB/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec);

        // Decrypt the data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        // For zeros padding, we need to trim trailing zeros
        int actualLength = UNALIGNED_DATA.length;
        byte[] trimmedDecrypted = Arrays.copyOf(decryptedData, actualLength);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", UNALIGNED_DATA, trimmedDecrypted);
    }

    @Test
    public void testMultiThreaded() throws Exception {
        final int threadCount = 4;
        final int iterationsPerThread = 100;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch latch = new CountDownLatch(threadCount);
        final Exception[] threadExceptions = new Exception[threadCount];

        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < iterationsPerThread; j++) {
                        // Test CBC mode with PKCS5 padding
                        SecretKeySpec key = new SecretKeySpec(TEST_KEY, "SM4");
                        IvParameterSpec iv = new IvParameterSpec(TEST_IV);

                        // Encrypt
                        Cipher encryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
                        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        byte[] encrypted = encryptCipher.doFinal(TEST_DATA);

                        // Decrypt
                        Cipher decryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
                        decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
                        byte[] decrypted = decryptCipher.doFinal(encrypted);

                        if (!Arrays.equals(TEST_DATA, decrypted)) {
                            throw new AssertionError("Decrypted data doesn't match in thread " + threadIndex);
                        }

                        // Also test incremental updates
                        encryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
                        encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
                        byte[] part1 = encryptCipher.update(Arrays.copyOfRange(TEST_DATA, 0, 16));
                        byte[] part2 = encryptCipher.update(Arrays.copyOfRange(TEST_DATA, 16, TEST_DATA.length));
                        byte[] part3 = encryptCipher.doFinal();
                        
                        // Combine parts
                        byte[] incrementalEncrypted = new byte[part1.length + part2.length + part3.length];
                        System.arraycopy(part1, 0, incrementalEncrypted, 0, part1.length);
                        System.arraycopy(part2, 0, incrementalEncrypted, part1.length, part2.length);
                        System.arraycopy(part3, 0, incrementalEncrypted, part1.length + part2.length, part3.length);

                        // Decrypt incremental
                        decryptCipher = Cipher.getInstance("SM4/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
                        decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
                        byte[] incrementalDecrypted = decryptCipher.doFinal(incrementalEncrypted);

                        if (!Arrays.equals(TEST_DATA, incrementalDecrypted)) {
                            throw new AssertionError("Incremental decrypted data doesn't match in thread " + threadIndex);
                        }
                    }
                } catch (Exception e) {
                    threadExceptions[threadIndex] = e;
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue("Threads did not complete in time", 
                  latch.await(30, TimeUnit.SECONDS));
        executor.shutdown();
        assertTrue("Executor did not shut down cleanly", 
                  executor.awaitTermination(5, TimeUnit.SECONDS));

        // Check for any exceptions that occurred in the threads
        for (int i = 0; i < threadCount; i++) {
            if (threadExceptions[i] != null) {
                throw new AssertionError("Exception in thread " + i, threadExceptions[i]);
            }
        }
    }

    private byte[] combineArrays(byte[] first, byte[] second) {
        if (first == null) return second;
        if (second == null) return first;
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}