package org.openhitls.crypto.jce.signer;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.*;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

public class SM2JceTest {
    private static final byte[] TEST_DATA = "Hello, SM2!".getBytes();

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testKeyPairGeneration() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SM2", "HITLS4J");
        KeyPair keyPair = keyGen.generateKeyPair();
        
        assertNotNull("KeyPair should not be null", keyPair);
        assertNotNull("Public key should not be null", keyPair.getPublic());
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertEquals("Public key algorithm should be SM2", "SM2", keyPair.getPublic().getAlgorithm());
        assertEquals("Private key algorithm should be SM2", "SM2", keyPair.getPrivate().getAlgorithm());
    }

    @Test
    public void testEncryptionDecryption() throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SM2", "HITLS4J");
        KeyPair keyPair = keyGen.generateKeyPair();

        // Initialize cipher for encryption
        Cipher encryptCipher = Cipher.getInstance("SM2", "HITLS4J");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Encrypt data
        byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);
        assertNotNull("Encrypted data should not be null", encryptedData);

        // Initialize cipher for decryption
        Cipher decryptCipher = Cipher.getInstance("SM2", "HITLS4J");
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Decrypt data
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);
        assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);
    }

    @Test
    public void testSignatureVerification() throws Exception {
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SM2", "HITLS4J");
        KeyPair keyPair = keyGen.generateKeyPair();

        // Create signature instance for signing
        Signature signer = Signature.getInstance("SM2", "HITLS4J");
        signer.initSign(keyPair.getPrivate());
        signer.update(TEST_DATA);
        byte[] signature = signer.sign();

        // Verify signature
        Signature verifier = Signature.getInstance("SM2", "HITLS4J");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(TEST_DATA);
        boolean verified = verifier.verify(signature);

        assertTrue("Signature verification should succeed", verified);
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
                        // Test key pair generation
                        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SM2", "HITLS4J");
                        KeyPair keyPair = keyGen.generateKeyPair();

                        // Test encryption/decryption
                        Cipher encryptCipher = Cipher.getInstance("SM2", "HITLS4J");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                        byte[] encryptedData = encryptCipher.doFinal(TEST_DATA);

                        Cipher decryptCipher = Cipher.getInstance("SM2", "HITLS4J");
                        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                        byte[] decryptedData = decryptCipher.doFinal(encryptedData);
                        if (!Arrays.equals(TEST_DATA, decryptedData)) {
                            throw new AssertionError("Decrypted data doesn't match in thread " + threadIndex);
                        }

                        // Test incremental encryption/decryption
                        encryptCipher = Cipher.getInstance("SM2", "HITLS4J");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                        byte[] part1 = encryptCipher.update(Arrays.copyOfRange(TEST_DATA, 0, TEST_DATA.length / 2));
                        byte[] part2 = encryptCipher.doFinal(Arrays.copyOfRange(TEST_DATA, TEST_DATA.length / 2, TEST_DATA.length));
                        byte[] incrementalEncrypted = new byte[part1.length + part2.length];
                        System.arraycopy(part1, 0, incrementalEncrypted, 0, part1.length);
                        System.arraycopy(part2, 0, incrementalEncrypted, part1.length, part2.length);

                        decryptCipher = Cipher.getInstance("SM2", "HITLS4J");
                        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                        byte[] incrementalDecrypted = decryptCipher.doFinal(incrementalEncrypted);
                        if (!Arrays.equals(TEST_DATA, incrementalDecrypted)) {
                            throw new AssertionError("Incremental decrypted data doesn't match in thread " + threadIndex);
                        }

                        // Test signing/verification
                        Signature signer = Signature.getInstance("SM2", "HITLS4J");
                        signer.initSign(keyPair.getPrivate());
                        signer.update(TEST_DATA);
                        byte[] signature = signer.sign();

                        Signature verifier = Signature.getInstance("SM2", "HITLS4J");
                        verifier.initVerify(keyPair.getPublic());
                        verifier.update(TEST_DATA);
                        if (!verifier.verify(signature)) {
                            throw new AssertionError("Signature verification failed in thread " + threadIndex);
                        }

                        // Test incremental signing/verification
                        signer = Signature.getInstance("SM2", "HITLS4J");
                        signer.initSign(keyPair.getPrivate());
                        signer.update(Arrays.copyOfRange(TEST_DATA, 0, TEST_DATA.length / 2));
                        signer.update(Arrays.copyOfRange(TEST_DATA, TEST_DATA.length / 2, TEST_DATA.length));
                        byte[] incrementalSignature = signer.sign();

                        verifier = Signature.getInstance("SM2", "HITLS4J");
                        verifier.initVerify(keyPair.getPublic());
                        verifier.update(Arrays.copyOfRange(TEST_DATA, 0, TEST_DATA.length / 2));
                        verifier.update(Arrays.copyOfRange(TEST_DATA, TEST_DATA.length / 2, TEST_DATA.length));
                        if (!verifier.verify(incrementalSignature)) {
                            throw new AssertionError("Incremental signature verification failed in thread " + threadIndex);
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
}
