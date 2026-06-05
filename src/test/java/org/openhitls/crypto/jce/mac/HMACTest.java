package org.openhitls.crypto.jce.mac;

import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class HMACTest extends BaseTest {
    private static final String[] HMAC_ALGORITHMS = {
        "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", 
        "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512", "HMACSM3"
    };

    private static final int[] MAC_LENGTHS = {
        20, 28, 32, 48, 64,  // SHA1, SHA224, SHA256, SHA384, SHA512
        28, 32, 48, 64, 32   // SHA3-224, SHA3-256, SHA3-384, SHA3-512, SM3
    };

    private static final String[][] HMAC_VECTORS = {
        {"HMACSHA1", "b617318655057264e28bc0b6fb378c8ef146be00"},
        {"HMACSHA224", "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"},
        {"HMACSHA256", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
        {"HMACSHA384", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9"
                + "ea9076ede7f4af152e8b2fa9cb6"},
        {"HMACSHA512", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
        {"HMACSHA3-224", "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7"},
        {"HMACSHA3-256", "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"},
        {"HMACSHA3-384", "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a"
                + "20d370b47743130e26ac7e3d532886bd"},
        {"HMACSHA3-512", "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba"
                + "47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"},
        {"HMACSM3", "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"}
    };

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testKnownAnswerVectors() throws Exception {
        byte[] key = repeatedByte(0x0b, 20);
        byte[] message = "Hi There".getBytes(StandardCharsets.US_ASCII);

        for (String[] vector : HMAC_VECTORS) {
            String algorithm = vector[0];
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            byte[] expected = hex(vector[1]);

            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            mac.init(keySpec);
            assertArrayEquals("Known-answer HMAC mismatch for " + algorithm,
                    expected, mac.doFinal(message));

            mac.reset();
            for (byte b : message) {
                mac.update(b);
            }
            assertArrayEquals("Byte-by-byte HMAC mismatch for " + algorithm,
                    expected, mac.doFinal());
        }
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

    @Test
    public void testRejectsUseBeforeInit() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            try {
                mac.doFinal(new byte[] {1, 2, 3});
                fail("Expected IllegalStateException before init for " + algorithm);
            } catch (IllegalStateException expected) {
                // Expected.
            }

            try {
                mac.update((byte) 1);
                fail("Expected IllegalStateException before init for " + algorithm);
            } catch (IllegalStateException expected) {
                // Expected.
            }
        }
    }

    @Test
    public void testRejectsWrongKeyAlgorithm() throws Exception {
        for (String algorithm : HMAC_ALGORITHMS) {
            Mac mac = Mac.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            try {
                mac.init(new SecretKeySpec(new byte[] {1, 2, 3, 4}, "AES"));
                fail("Expected InvalidKeyException for " + algorithm);
            } catch (InvalidKeyException expected) {
                // Expected.
            }
        }
    }

    @Test
    public void testUnknownAlgorithmRejected() throws Exception {
        try {
            Mac.getInstance("HMACSHA999", HiTls4jProvider.PROVIDER_NAME);
            fail("Expected NoSuchAlgorithmException");
        } catch (java.security.NoSuchAlgorithmException expected) {
            // Expected.
        }
    }

    private static byte[] repeatedByte(int value, int count) {
        byte[] bytes = new byte[count];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) value;
        }
        return bytes;
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
