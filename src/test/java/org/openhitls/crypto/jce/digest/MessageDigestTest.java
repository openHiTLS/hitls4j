package org.openhitls.crypto.jce.digest;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import java.security.MessageDigest;
import java.security.Security;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class MessageDigestTest extends BaseTest {
    private static final String[] DIGEST_ALGORITHMS = {
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SM3"
    };

    private static final int[] DIGEST_LENGTHS = {
        20, 28, 32, 48, 64,  // SHA1, SHA224, SHA256, SHA384, SHA512
        28, 32, 48, 64, 32   // SHA3-224, SHA3-256, SHA3-384, SHA3-512, SM3
    };

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testDigestSingleShot() throws Exception {
        for (int i = 0; i < DIGEST_ALGORITHMS.length; i++) {
            String algorithm = DIGEST_ALGORITHMS[i];
            int expectedLength = DIGEST_LENGTHS[i];

            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            String message = "Hello, " + algorithm + "!";
            byte[] hash = md.digest(message.getBytes(StandardCharsets.UTF_8));

            // Verify hash length
            assertEquals("Hash length should be " + expectedLength + " bytes for " + algorithm,
                    expectedLength, hash.length);
        }
    }

    @Test
    public void testDigestIncremental() throws Exception {
        for (String algorithm : DIGEST_ALGORITHMS) {
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            String part1 = "Hello, ";
            String part2 = algorithm + "!";

            // Incremental update
            md.update(part1.getBytes(StandardCharsets.UTF_8));
            md.update(part2.getBytes(StandardCharsets.UTF_8));
            byte[] incrementalHash = md.digest();

            // Compare with single-shot hash
            md.reset();
            byte[] singleHash = md.digest((part1 + part2).getBytes(StandardCharsets.UTF_8));

            assertArrayEquals("Incremental and single-shot hashes should match for " + algorithm,
                    singleHash, incrementalHash);
        }
    }

    @Test
    public void testEmptyMessage() throws Exception {
        for (String algorithm : DIGEST_ALGORITHMS) {
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            byte[] hash = md.digest(new byte[0]);
            assertEquals("Hash length should match algorithm spec for " + algorithm,
                    md.getDigestLength(), hash.length);
        }
    }

    @Test
    public void testReset() throws Exception {
        for (String algorithm : DIGEST_ALGORITHMS) {
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            String message = "Test message for " + algorithm;
            byte[] hash1 = md.digest(message.getBytes(StandardCharsets.UTF_8));

            // Get another hash after reset
            md.reset();
            byte[] hash2 = md.digest(message.getBytes(StandardCharsets.UTF_8));

            assertArrayEquals("Hashes should be identical after reset for " + algorithm,
                    hash1, hash2);
        }
    }

    @Test
    public void testMultiThread() throws Exception {
        for (String algorithm : DIGEST_ALGORITHMS) {
            final int threadCount = 4;
            final int iterationsPerThread = 100;
            final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            final CountDownLatch latch = new CountDownLatch(threadCount);
            final Exception[] threadExceptions = new Exception[threadCount];
            
            final String message = "Test message for multi-threaded " + algorithm;
            
            // Get expected hash
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            final byte[] expectedHash = md.digest(message.getBytes(StandardCharsets.UTF_8));

            for (int i = 0; i < threadCount; i++) {
                final int threadIndex = i;
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterationsPerThread; j++) {
                            // Test single-shot hash
                            MessageDigest threadMd = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
                            byte[] hash = threadMd.digest(message.getBytes(StandardCharsets.UTF_8));
                            assertArrayEquals("Hash mismatch in thread " + threadIndex + ", iteration " + j,
                                    expectedHash, hash);

                            // Test incremental hash
                            threadMd.reset();
                            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                            for (byte b : messageBytes) {
                                threadMd.update(b);
                            }
                            hash = threadMd.digest();
                            assertArrayEquals("Incremental hash mismatch in thread " + threadIndex + ", iteration " + j,
                                    expectedHash, hash);
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

            // Check for any exceptions in the threads
            for (int i = 0; i < threadCount; i++) {
                if (threadExceptions[i] != null) {
                    throw new AssertionError("Exception in thread " + i + " for " + algorithm,
                            threadExceptions[i]);
                }
            }
        }
    }
}
