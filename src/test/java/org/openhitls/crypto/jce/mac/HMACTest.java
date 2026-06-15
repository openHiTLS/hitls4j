package org.openhitls.crypto.jce.mac;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

public class HMACTest extends BaseTest {
    private static final String[] HMAC_ALGORITHMS = {
        "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", 
        "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512", "HMACSM3"
    };

    private static final int[] MAC_LENGTHS = {
        20, 28, 32, 48, 64,  // SHA1, SHA224, SHA256, SHA384, SHA512
        28, 32, 48, 64, 32   // SHA3-224, SHA3-256, SHA3-384, SHA3-512, SM3
    };

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testHMACSingleShot() throws Exception {
        for (int i = 0; i < HMAC_ALGORITHMS.length; i++) {
            String algorithm = HMAC_ALGORITHMS[i];
            int expectedLength = MAC_LENGTHS[i];

            byte[] key = ("TestKey123" + algorithm).getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac.init(keySpec);

            String message = "Hello, " + algorithm + "!";
            byte[] macResult = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Verify MAC length
            assertEquals("MAC length should be " + expectedLength + " bytes for " + algorithm,
                    expectedLength, macResult.length);
        }
    }

    @Test
    public void testHMACIncremental() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            byte[] key = ("TestKey123" + algorithm).getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            
            // Single-shot MAC
            Mac mac1 = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac1.init(keySpec);
            String message = "Hello, " + algorithm + "!";
            byte[] expectedMac = mac1.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // Incremental MAC
            Mac mac2 = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac2.init(keySpec);
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < messageBytes.length; i++) {
                mac2.update(messageBytes[i]);
            }
            byte[] incrementalMac = mac2.doFinal();

            // Compare results
            assertArrayEquals("Incremental and single-shot MACs should match for " + algorithm,
                    expectedMac, incrementalMac);
        }
    }

    @Test
    public void testEmptyMessage() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            byte[] key = ("TestKey123" + algorithm).getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac.init(keySpec);

            byte[] emptyMac = mac.doFinal(new byte[0]);
            // Just verify we get a non-null, non-empty result
            assertEquals("MAC length should match algorithm spec for " + algorithm,
                    mac.getMacLength(), emptyMac.length);
        }
    }

    @Test
    public void testReset() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            byte[] key = ("TestKey123" + algorithm).getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac.init(keySpec);

            String message = "Test message for " + algorithm;
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

            // First MAC
            mac.update(messageBytes);
            byte[] firstMac = mac.doFinal();

            // Second MAC after reset
            mac.reset();
            mac.update(messageBytes);
            byte[] secondMac = mac.doFinal();

            // Compare results
            assertArrayEquals("MACs should be identical after reset for " + algorithm,
                    firstMac, secondMac);
        }
    }

    @Test
    public void testMultiThread() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            final int threadCount = 4;
            final int iterationsPerThread = 100;
            final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            final CountDownLatch latch = new CountDownLatch(threadCount);
            final Exception[] threadExceptions = new Exception[threadCount];
            
            final String message = "Test message for multi-threaded " + algorithm;
            final byte[] key = ("TestKey123" + algorithm).getBytes(StandardCharsets.UTF_8);
            final SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);

            // Get expected MAC
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac.init(keySpec);
            final byte[] expectedMac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));

            for (int i = 0; i < threadCount; i++) {
                final int threadIndex = i;
                executor.submit(() -> {
                    try {
                        for (int j = 0; j < iterationsPerThread; j++) {
                            // Test single-shot MAC
                            Mac threadMac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
                            threadMac.init(keySpec);
                            byte[] threadMacResult = threadMac.doFinal(message.getBytes(StandardCharsets.UTF_8));
                            assertArrayEquals("MAC mismatch in thread " + threadIndex + ", iteration " + j,
                                    expectedMac, threadMacResult);

                            // Test incremental MAC
                            threadMac.reset();
                            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                            for (byte b : messageBytes) {
                                threadMac.update(b);
                            }
                            threadMacResult = threadMac.doFinal();
                            assertArrayEquals("Incremental MAC mismatch in thread " + threadIndex + ", iteration " + j,
                                    expectedMac, threadMacResult);
                        }
                    } catch (Exception e) {
                        threadExceptions[threadIndex] = e;
                    } finally {
                        latch.countDown();
                    }
                });
            }

            latch.await();
            executor.shutdown();

            // Check for any exceptions in the threads
            for (int i = 0; i < threadCount; i++) {
                if (threadExceptions[i] != null) {
                    throw new AssertionError("Exception in thread " + i + " for " + algorithm, threadExceptions[i]);
                }
            }
        }
    }
}
