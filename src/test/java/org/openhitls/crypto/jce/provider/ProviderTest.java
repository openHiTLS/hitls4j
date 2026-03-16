package org.openhitls.crypto.jce.provider;

import com.sun.jna.Library;
import com.sun.jna.Native;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.crypto.BaseTest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SDFP provider test scenario for provider loading and usage via HiTLS4J.
 *
 * This is an optional test scenario. It is skipped unless both the SDFP provider
 * and the SDF backend library can be resolved.
 *
 * Root directory mode:
 * mvn -Dtest=ProviderTest test \
 *   -Dopenhitls.root=/path/to/openhitls \
 *   -Dsdfp.root=/path/to/sdfp \
 *   -Dsdf.root=/path/to/sdf
 *
 * By default, root directory mode expects non-ASan build outputs:
 * - SDFP provider: ${sdfp.root}/build-noasan/libSDFProv.so
 * - SDF backend: ${sdf.root}/build-noasan/libsdf_openhitls.so
 *
 * Direct path mode:
 * mvn -Dtest=ProviderTest test \
 *   -Dopenhitls.root=/path/to/openhitls \
 *   -Dsdfp.provider.dir=/path/to/sdfp/build-noasan \
 *   -Dsdfp.provider.name=SDFProv \
 *   -Dsdf.lib.path=/path/to/libsdf_openhitls.so
 *
 * Legacy direct provider aliases are also accepted:
 * -Dhitls.provider.path=/path/to/providers
 * -Dhitls.provider.name=SDFProv
 *
 * The same values can be supplied through environment variables:
 * OPENHITLS_ROOT, SDFP_ROOT, SDF_ROOT, SDFP_PROVIDER_DIR, SDFP_PROVIDER_NAME,
 * and SDF_LIB_PATH.
 *
 * The SDF backend path is test setup, not a HiTLS4J provider API parameter.
 * ProviderTest sets SDF_LIB_PATH before loading SDFP. HiTLS4J's
 * ProviderConfig.loadProvider(...) API does not special-case SDFP parameters.
 *
 * Use one consistent openHiTLS build across HiTLS4J, SDFP, and the SDF backend
 * where possible. Mixing shared libraries built against different openHiTLS
 * trees can cause provider loading or symbol resolution failures.
 */
public class ProviderTest extends BaseTest {

    private static final String PROVIDER_PATH_PROP = "hitls.provider.path";
    private static final String PROVIDER_NAME_PROP = "hitls.provider.name";
    private static final String SDFP_ROOT_PROP = "sdfp.root";
    private static final String SDFP_PROVIDER_DIR_PROP = "sdfp.provider.dir";
    private static final String SDFP_PROVIDER_NAME_PROP = "sdfp.provider.name";
    private static final String SDF_ROOT_PROP = "sdf.root";
    private static final String SDF_LIB_PATH_PROP = "sdf.lib.path";
    private static final String SDF_LIB_PATH_ENV = "SDF_LIB_PATH";
    private static final String DEFAULT_PROVIDER_NAME = "SDFProv";
    private static final String DEFAULT_BUILD_DIR = "build-noasan";

    private interface LibC extends Library {
        int setenv(String name, String value, int overwrite);
    }

    private static boolean providerLoaded = false;
    private static String providerPath;
    private static String providerName;
    private static String sdfLibPath;

    @BeforeClass
    public static void setUpProvider() {
        providerPath = resolveProviderPath();
        providerName = resolveProviderName();
        sdfLibPath = resolveSdfLibPath();

        if (!isProviderConfigured()) {
            System.out.println("Provider test skipped: set -D" + SDFP_ROOT_PROP
                + " and -D" + SDF_ROOT_PROP + ", or set -D" + PROVIDER_PATH_PROP
                + " and -D" + SDF_LIB_PATH_PROP + " to enable");
            return;
        }

        assertProviderFilesExist();
        providerLoaded = loadConfiguredProvider();
    }

    @AfterClass
    public static void tearDownProvider() {
        if (providerLoaded) {
            ProviderConfig.unloadProvider();
            System.out.println("Provider unloaded");
        }
    }

    private void assumeProviderLoaded() {
        org.junit.Assume.assumeTrue(
            "Provider not loaded, skipping test", providerLoaded);
    }

    private static boolean isProviderConfigured() {
        return providerPath != null && providerName != null && sdfLibPath != null;
    }

    private static String resolveProviderPath() {
        String directPath = firstNonBlank(
            System.getProperty(PROVIDER_PATH_PROP),
            System.getProperty(SDFP_PROVIDER_DIR_PROP),
            System.getenv("SDFP_PROVIDER_DIR"));
        if (directPath != null) {
            return directPath;
        }

        String sdfpRoot = firstNonBlank(System.getProperty(SDFP_ROOT_PROP), System.getenv("SDFP_ROOT"));
        if (sdfpRoot == null) {
            return null;
        }
        return new File(sdfpRoot, DEFAULT_BUILD_DIR).getPath();
    }

    private static String resolveProviderName() {
        return firstNonBlank(
            System.getProperty(PROVIDER_NAME_PROP),
            System.getProperty(SDFP_PROVIDER_NAME_PROP),
            System.getenv("SDFP_PROVIDER_NAME"),
            DEFAULT_PROVIDER_NAME);
    }

    private static String resolveSdfLibPath() {
        String directPath = firstNonBlank(System.getProperty(SDF_LIB_PATH_PROP), System.getenv(SDF_LIB_PATH_ENV));
        if (directPath != null) {
            return directPath;
        }

        String sdfRoot = firstNonBlank(System.getProperty(SDF_ROOT_PROP), System.getenv("SDF_ROOT"));
        if (sdfRoot == null) {
            return null;
        }
        return new File(new File(sdfRoot, DEFAULT_BUILD_DIR), "libsdf_openhitls.so").getPath();
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            String trimmed = trimToNull(value);
            if (trimmed != null) {
                return trimmed;
            }
        }
        return null;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static void assertProviderFilesExist() {
        File providerDir = new File(providerPath);
        assertTrue("Provider directory should exist: " + providerPath, providerDir.isDirectory());
        File providerFile = new File(providerDir, "lib" + providerName + ".so");
        assertTrue("Provider library should exist: " + providerFile.getAbsolutePath(), providerFile.isFile());
        File sdfLib = new File(sdfLibPath);
        assertTrue("SDF library should exist: " + sdfLibPath, sdfLib.isFile());
    }

    private static boolean loadConfiguredProvider() {
        setSdfLibPathForProvider();
        ProviderConfig.loadProvider(providerPath, providerName);
        System.out.println("Provider loaded: true"
            + " (path=" + providerPath + ", name=" + providerName + ", sdfLib=" + sdfLibPath + ")");
        return true;
    }

    private static void setSdfLibPathForProvider() {
        LibC libc = Native.load("c", LibC.class);
        int ret = libc.setenv(SDF_LIB_PATH_ENV, sdfLibPath, 1);
        if (ret != 0) {
            throw new IllegalStateException("Failed to set " + SDF_LIB_PATH_ENV + " for SDFP provider");
        }
    }

    // ==================== SM3 Message Digest Tests ====================

    @Test
    public void testProviderDigestSM3() throws Exception {
        assumeProviderLoaded();

        MessageDigest md = MessageDigest.getInstance("SM3", HiTls4jProvider.PROVIDER_NAME);
        byte[] hash = md.digest("Hello, SDF Provider!".getBytes(StandardCharsets.UTF_8));

        assertNotNull("Hash should not be null", hash);
        assertEquals("SM3 hash should be 32 bytes", 32, hash.length);

        // Test known SM3 vector for "abc"
        byte[] expected = hexToBytes("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        md = MessageDigest.getInstance("SM3", HiTls4jProvider.PROVIDER_NAME);
        byte[] result = md.digest("abc".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals("SM3 hash for 'abc' should match known vector", expected, result);
    }

    @Test
    public void testProviderDigestSM3Consistency() throws Exception {
        assumeProviderLoaded();

        String message = "Consistent SM3 hashing test";
        MessageDigest md = MessageDigest.getInstance("SM3", HiTls4jProvider.PROVIDER_NAME);

        byte[] hash1 = md.digest(message.getBytes(StandardCharsets.UTF_8));
        md.reset();
        byte[] hash2 = md.digest(message.getBytes(StandardCharsets.UTF_8));

        assertArrayEquals("Same input should produce same hash", hash1, hash2);
    }

    // ==================== SM4 Symmetric Cipher Tests ====================

    @Test
    public void testProviderSm4Ecb() throws Exception {
        assumeProviderLoaded();

        // Test with known vector
        byte[] keyBytes = hexToBytes("0123456789abcdeffedcba9876543210");
        byte[] plaintext = hexToBytes("0123456789abcdeffedcba9876543210");
        byte[] expected = hexToBytes("681edf34d206965e86b3e94f536e4246");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", HiTls4jProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertNotNull("Ciphertext should not be null", ciphertext);
        assertArrayEquals("SM4 ECB known vector should match", expected, ciphertext);

        // Verify round-trip: encrypt then decrypt should return original
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted text should match original", plaintext, decrypted);
    }

    @Test
    public void testProviderSm4Cbc() throws Exception {
        assumeProviderLoaded();

        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        new SecureRandom().nextBytes(ivBytes);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // Note: SDF provider does not implement padding at native level
        // For NoPadding mode with block-aligned data, encryption/decryption works
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", HiTls4jProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        // Use block-aligned plaintext (32 bytes = 2 blocks of 16 bytes)
        byte[] plaintext = new byte[32];
        new SecureRandom().nextBytes(plaintext);

        byte[] ciphertext = cipher.doFinal(plaintext);

        assertNotNull("Ciphertext should not be null", ciphertext);
        assertEquals("Ciphertext should be same length as plaintext for NoPadding", plaintext.length, ciphertext.length);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted text should match original", plaintext, decrypted);
    }

    // ==================== SM2 Signature Tests ====================

    @Test
    public void testProviderSm2Signature() throws Exception {
        assumeProviderLoaded();

        // Generate SM2 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // Sign
        Signature signer = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        byte[] data = "Hello, SM2 with SDF Provider!".getBytes(StandardCharsets.UTF_8);
        signer.update(data);
        byte[] signature = signer.sign();

        assertNotNull("Signature should not be null", signature);
        assertTrue("Signature should have content", signature.length > 0);

        // Verify
        Signature verifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        assertTrue("SM2 signature should verify", verifier.verify(signature));
    }

    @Test
    public void testProviderSm2SignatureMultipleMessages() throws Exception {
        assumeProviderLoaded();

        // Generate SM2 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        String[] messages = {
            "Test message 1",
            "Another test message with more content",
            "SM2签名测试"
        };

        for (String msg : messages) {
            byte[] data = msg.getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            assertTrue("SM2 signature should verify for: " + msg, verifier.verify(signature));
        }
    }

    // ==================== SM2 Encryption Tests ====================

    @Test
    public void testProviderSm2Encrypt() throws Exception {
        assumeProviderLoaded();

        // Generate SM2 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // Encrypt
        Cipher cipher = Cipher.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] plaintext = "Hello, SM2 Encryption!".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = cipher.doFinal(plaintext);

        assertNotNull("Ciphertext should not be null", ciphertext);
        assertTrue("Ciphertext should have content", ciphertext.length > 0);

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted text should match original", plaintext, decrypted);
    }

    // ==================== Provider Lifecycle Tests ====================

    @Test
    public void testDuplicateProviderLoadRejectedKeepsExistingProviderActive() throws Exception {
        assumeProviderLoaded();

        boolean loadFailed = false;
        try {
            ProviderConfig.loadProvider(providerPath, providerName);
        } catch (IllegalStateException expected) {
            loadFailed = true;
        }
        assertTrue("Duplicate provider load should fail while provider is active", loadFailed);

        assertSm4CtrUnsupportedByConfiguredProvider();
    }

    private void assertSm4CtrUnsupportedByConfiguredProvider() throws Exception {
        byte[] keyBytes = hexToBytes("0123456789abcdeffedcba9876543210");
        byte[] ivBytes = hexToBytes("000102030405060708090a0b0c0d0e0f");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding", HiTls4jProvider.PROVIDER_NAME);

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
            fail("SM4 CTR should remain unsupported while SDFP provider is active");
        } catch (InvalidKeyException expected) {
            // SDFP currently exposes SM4 ECB/CBC/GCM only. If this succeeds,
            // the rejected duplicate load dropped back to the default provider.
        }
    }

    // Helper method to convert hex string to byte array
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
