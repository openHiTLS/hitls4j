package org.openhitls.crypto.jce.cipher;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AESTest extends BaseTest {
    private static final String[] MODES = {"ECB", "CBC", "CTR"};
    private static final int[] KEY_SIZES = {128, 192, 256};

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testAESEncryptDecrypt() throws Exception {
        for (String mode : MODES) {
            for (int keySize : KEY_SIZES) {
                // Generate key
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(keySize);
                SecretKey key = keyGen.generateKey();

                // Create cipher
                Cipher cipher = Cipher.getInstance("AES/" + mode + "/NOPADDING", HiTls4jProvider.PROVIDER_NAME);

                // Test data
                String testData = "Hello, AES Test!";
                byte[] input = testData.getBytes(StandardCharsets.UTF_8);
                // Pad input to block size
                int blockSize = cipher.getBlockSize();
                int padding = blockSize - (input.length % blockSize);
                byte[] paddedInput = Arrays.copyOf(input, input.length + padding);

                // Generate IV for modes that need it
                byte[] iv = null;
                if (!mode.equals("ECB")) {
                    iv = new byte[16];  // AES block size
                    new SecureRandom().nextBytes(iv);
                    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                }
                
                // Encrypt
                byte[] encrypted = cipher.doFinal(paddedInput);

                // Decrypt
                if (iv != null) {
                    // For modes that use IV (CBC, CTR, GCM), we need to pass it back
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                } else {
                    // ECB mode doesn't use IV
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }
                byte[] decrypted = cipher.doFinal(encrypted);

                // Verify
                assertArrayEquals("Decryption failed for mode " + mode + " with key size " + keySize,
                                paddedInput, decrypted);
                
                // For CBC mode, verify that different IVs produce different ciphertexts
                if (mode.equals("CBC")) {
                    // Create a second cipher with a different IV
                    Cipher cipher2 = Cipher.getInstance("AES/CBC/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
                    byte[] iv2 = new byte[16];
                    new SecureRandom().nextBytes(iv2);
                    cipher2.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv2));
                    byte[] encrypted2 = cipher2.doFinal(paddedInput);
                    
                    // The ciphertexts should be different due to different IVs
                    assertFalse("CBC mode with different IVs produced same ciphertext",
                              Arrays.equals(encrypted, encrypted2));
                    
                    // But decryption should still work
                    cipher2.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv2));
                    byte[] decrypted2 = cipher2.doFinal(encrypted2);
                    assertArrayEquals("CBC decryption with different IV failed",
                                    paddedInput, decrypted2);
                }
            }
        }
    }

    @Test
    public void testAesGcmEncryptionDecryption() throws Exception {
        // Create key and IV specifications
        // Generate key
        for (int keySize : KEY_SIZES) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize);
            SecretKey key = keyGen.generateKey();
        
            // Generate IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            
            // Generate Aad
            byte[] aad = new byte[16];
            new SecureRandom().nextBytes(aad);
            
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            
            // Initialize cipher for encryption
            Cipher encryptCipher = Cipher.getInstance("AES/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

            // Encrypt the test data
            String testData = "Hello, AES Test!";
            byte[] input = testData.getBytes(StandardCharsets.UTF_8);
            encryptCipher.updateAAD(aad);
            byte[] encryptedData = encryptCipher.doFinal(input);

            // Initialize cipher for decryption
            Cipher decryptCipher = Cipher.getInstance("AES/GCM/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
            decryptCipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            decryptCipher.updateAAD(aad);

            // Decrypt the data
            byte[] decryptedData = decryptCipher.doFinal(encryptedData);

            // Verify the decrypted data matches the original
            assertArrayEquals("Decrypted data should match original", input, decryptedData);
        }
    }

    @Test
    public void testMultipleBlocksEncryption() throws Exception {
        // Generate a 256-bit key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Create cipher in ECB mode
        Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Test data (multiple blocks)
        byte[] input = new byte[64]; // 4 AES blocks
        Arrays.fill(input, (byte)0x42);

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(input);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("Multi-block encryption/decryption failed", input, decrypted);
    }

    @Test
    public void testIncrementalProcessing() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Test data (3 AES blocks)
        byte[] input = new byte[48];
        Arrays.fill(input, (byte)0x42);

        // Encrypt incrementally
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] output = new byte[48];
        int outputOffset = 0;

        // Process first block
        outputOffset += cipher.update(input, 0, 16, output, outputOffset);

        // Process second block
        outputOffset += cipher.update(input, 16, 16, output, outputOffset);

        // Process third (final) block
        outputOffset += cipher.update(input, 32, 16, output, outputOffset);

        // For ECB mode with NoPadding, there's no final block to process
        // but we still need to call doFinal() to complete the operation
        cipher.doFinal();

        // Verify total length
        assertEquals("Incorrect output length", 48, outputOffset);

        // Decrypt incrementally
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = new byte[48];
        outputOffset = 0;

        // Process first block
        outputOffset += cipher.update(output, 0, 16, decrypted, outputOffset);

        // Process second block 
        outputOffset += cipher.update(output, 16, 16, decrypted, outputOffset);

        // Process third (final) block
        outputOffset += cipher.update(output, 32, 16, decrypted, outputOffset);

        // Complete decryption
        cipher.doFinal();

        // Verify total length
        assertEquals("Incorrect decrypted length", 48, outputOffset);

        // Verify decrypted data matches input
        assertArrayEquals("Incremental processing failed", input, decrypted);
    }

    @Test
    public void testCBCMode() throws Exception {
        // Generate key and IV
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", HiTls4jProvider.PROVIDER_NAME);
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Test data (exactly 3 blocks)
        byte[] input = new byte[48];
        Arrays.fill(input, (byte)0x42);

        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(input);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("CBC mode encryption/decryption failed", input, decrypted);
    }

    @Test
    public void testCBCModeIncremental() throws Exception {
        // Generate key and IV
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Test data (exactly 3 blocks)
        byte[] input = new byte[48];
        Arrays.fill(input, (byte)0x42);

        // Encrypt incrementally
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();
        
        // First block
        byte[] block1 = cipher.update(input, 0, 16);
        if (block1 != null) encryptedStream.write(block1);
        
        // Second block
        byte[] block2 = cipher.update(input, 16, 16);
        if (block2 != null) encryptedStream.write(block2);
        
        // Final block
        byte[] finalBlock = cipher.doFinal(input, 32, 16);
        encryptedStream.write(finalBlock);
        
        byte[] encrypted = encryptedStream.toByteArray();

        // Decrypt incrementally
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        
        // Process all but the last block
        int blockSize = 16;
        int fullBlocks = encrypted.length / blockSize - 1;
        
        for (int i = 0; i < fullBlocks; i++) {
            byte[] decryptedBlock = cipher.update(encrypted, i * blockSize, blockSize);
            if (decryptedBlock != null) decryptedStream.write(decryptedBlock);
        }
        
        // Process the last block
        byte[] lastBlock = cipher.doFinal(encrypted, fullBlocks * blockSize, blockSize);
        decryptedStream.write(lastBlock);
        
        byte[] decrypted = decryptedStream.toByteArray();

        // Verify
        assertArrayEquals("CBC mode incremental encryption/decryption failed", input, decrypted);
    }

    @Test
    public void testInvalidBlockSize() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING", HiTls4jProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        // Try to encrypt data that's not a multiple of the block size
        byte[] input = new byte[20];  // Not a multiple of 16
        Arrays.fill(input, (byte)0x42);
        try {
            cipher.doFinal(input);
            fail("Expected exception");
        } catch (Exception e) {
            assertTrue("Expected exception", e instanceof IllegalBlockSizeException);
        }
    }

    @Test
    public void testCbcPkcs7Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("CBC mode with PKCS7 padding failed", testData, decrypted);
    }

    @Test
    public void testCbcPkcs5Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("CBC mode with PKCS5 padding failed", testData, decrypted);
    }

    @Test
    public void testCbcIso7816Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("CBC mode with ISO7816 padding failed", testData, decrypted);
    }

    @Test
    public void testCbcZerosPadding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        // For zeros padding, we need to trim trailing zeros
        int actualLength = testData.length;
        byte[] trimmedDecrypted = Arrays.copyOf(decrypted, actualLength);

        // Verify
        assertArrayEquals("CBC mode with zeros padding failed", testData, trimmedDecrypted);
    }

    @Test
    public void testEcbPkcs7Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("ECB mode with PKCS7 padding failed", testData, decrypted);
    }

    @Test
    public void testEcbPkcs5Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("ECB mode with PKCS5 padding failed", testData, decrypted);
    }

    @Test
    public void testEcbIso7816Padding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/ISO7816PADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        // Verify
        assertArrayEquals("ECB mode with ISO7816 padding failed", testData, decrypted);
    }

    @Test
    public void testEcbZerosPadding() throws Exception {
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        // Test data (not block aligned)
        byte[] testData = new byte[20];  // 20 bytes is not a multiple of 16
        Arrays.fill(testData, (byte)0x42);

        // Create cipher
        Cipher cipher = Cipher.getInstance("AES/ECB/ZEROSPADDING", HiTls4jProvider.PROVIDER_NAME);
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(testData);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);

        // For zeros padding, we need to trim trailing zeros
        int actualLength = testData.length;
        byte[] trimmedDecrypted = Arrays.copyOf(decrypted, actualLength);

        // Verify
        assertArrayEquals("ECB mode with zeros padding failed", testData, trimmedDecrypted);
    }
}
