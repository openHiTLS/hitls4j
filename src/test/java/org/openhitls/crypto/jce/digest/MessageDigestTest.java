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

    private static final String[][] DIGEST_VECTORS = {
        {"SHA-1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"SHA-224", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
        {"SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"SHA-384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                + "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
        {"SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2"
                + "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f"},
        {"SHA3-224", "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
        {"SHA3-256", "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
        {"SHA3-384", "abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4"
                + "b298d88cea927ac7f539f1edf228376d25"},
        {"SHA3-512", "abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
        {"SM3", "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"}
    };

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testKnownAnswerVectors() throws Exception {
        for (String[] vector : DIGEST_VECTORS) {
            String algorithm = vector[0];
            byte[] message = vector[1].getBytes(StandardCharsets.US_ASCII);
            byte[] expected = hex(vector[2]);

            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            assertArrayEquals("Known-answer digest mismatch for " + algorithm,
                    expected, md.digest(message));

            md.reset();
            for (byte b : message) {
                md.update(b);
            }
            assertArrayEquals("Byte-by-byte digest mismatch for " + algorithm,
                    expected, md.digest());
        }
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
    public void testDigestAutomaticallyResets() throws Exception {
        byte[] message = "automatic reset".getBytes(StandardCharsets.UTF_8);

        for (String algorithm : DIGEST_ALGORITHMS) {
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);

            byte[] firstHash = md.digest(message);
            byte[] secondHash = md.digest(message);

            assertArrayEquals("digest() should automatically reset for " + algorithm,
                    firstHash, secondHash);
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

    @Test
    public void testInvalidInputRange() throws Exception {
        for (String algorithm : DIGEST_ALGORITHMS) {
            MessageDigest md = MessageDigest.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            try {
                md.update(new byte[4], 3, 2);
                fail("Expected invalid input range exception for " + algorithm);
            } catch (IllegalArgumentException expected) {
                // Expected from the JCA facade before it reaches the provider SPI.
            }
        }
    }

    @Test
    public void testUnknownAlgorithmRejected() throws Exception {
        try {
            MessageDigest.getInstance("SHA-999", HiTls4jProvider.PROVIDER_NAME);
            fail("Expected NoSuchAlgorithmException");
        } catch (java.security.NoSuchAlgorithmException expected) {
            // Expected.
        }
    }

    private static byte[] hex(String hex) {
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex string");
            }
            bytes[i] = (byte) ((hi << 4) | lo);
        }
        return bytes;
    }
}
