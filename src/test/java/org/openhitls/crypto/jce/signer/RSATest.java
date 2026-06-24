package org.openhitls.crypto.jce.signer;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.openhitls.crypto.jce.key.RSAPrivateKeyImpl;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import java.security.Security;
import java.security.SignatureException;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.asymmetric.RSAImpl;

public class RSATest {
    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testRSAKeyPairGeneration() throws Exception {
        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Verify keys are not null
        assertNotNull("Public key should not be null", publicKey);
        assertNotNull("Private key should not be null", privateKey);

        // Test signing and verification
        byte[] data = "Test data for RSA signing".getBytes();

        // Create and initialize signature for signing
        Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();

        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean verified = verifier.verify(signature);

        assertTrue("Signature verification failed", verified);
    }

    @Test
    public void testRSAWithDifferentMessageLengths() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String[] testMessages = {
            "",
            "Short message",
            "Medium length message for RSA testing",
            "A longer message that spans multiple blocks to test RSA signing and verification with larger data sizes"
        };

        for (String message : testMessages) {
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            byte[] signature = sign("SHA256withRSA", keyPair.getPrivate(), data);
            assertTrue("Signature verification failed for message: " + message,
                    verify("SHA256withRSA", keyPair.getPublic(), data, signature));
        }
    }

    @Test
    public void testRSASignatureWithDifferentHashAlgorithms() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "Test data for RSA signing with different hash algorithms".getBytes(StandardCharsets.UTF_8);
        String[] algorithms = {
            "SHA1withRSA",
            "SHA224withRSA",
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SM3withRSA"
        };

        for (String algorithm : algorithms) {
            byte[] signature = sign(algorithm, keyPair.getPrivate(), data);
            assertTrue("Signature verification failed for algorithm: " + algorithm,
                    verify(algorithm, keyPair.getPublic(), data, signature));
        }
    }

    @Test
    public void testSHA224WithRSAOidAlias() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "SHA224withRSA OID alias".getBytes(StandardCharsets.UTF_8);
        String sha224WithRsaOid = "1.2.840.113549.1.1.14";

        byte[] signature = sign(sha224WithRsaOid, keyPair.getPrivate(), data);
        assertTrue("SHA224withRSA OID alias should verify",
                verify(sha224WithRsaOid, keyPair.getPublic(), data, signature));
    }

    @Test
    public void testRSARejectsTamperedSignatureAndData() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "Original test data".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", keyPair.getPrivate(), data);

        byte[] tamperedSignature = signature.clone();
        tamperedSignature[0] ^= 0x01;
        assertFalse("Tampered signature should not verify",
                verify("SHA256withRSA", keyPair.getPublic(), data, tamperedSignature));

        byte[] tamperedData = data.clone();
        tamperedData[0] ^= 0x01;
        assertFalse("Signature should not verify with tampered data",
                verify("SHA256withRSA", keyPair.getPublic(), tamperedData, signature));
    }

    @Test
    public void testRSASignatureUpdatesAreAccumulated() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] prefix = "authenticated-prefix:".getBytes(StandardCharsets.UTF_8);
        byte[] suffix = "authenticated-suffix".getBytes(StandardCharsets.UTF_8);
        byte[] message = concat(prefix, suffix);

        String[] algorithms = {"SHA256withRSA", "SHA256withRSA/PSS"};
        for (String algorithm : algorithms) {
            byte[] signature = signInTwoUpdates(algorithm, keyPair.getPrivate(), prefix, suffix);

            assertTrue("Split update signature should verify full message for " + algorithm,
                    verify(algorithm, keyPair.getPublic(), message, signature));
            assertTrue("Split update signature should verify split message for " + algorithm,
                    verifyInTwoUpdatesOrFalse(algorithm, keyPair.getPublic(), prefix, suffix, signature));
        }
    }

    @Test
    public void testRSASignatureDoesNotIgnoreEarlierUpdateBlocks() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] attackerControlledPrefix = "attacker-controlled-prefix:".getBytes(StandardCharsets.UTF_8);
        byte[] signedSuffix = "signed-suffix".getBytes(StandardCharsets.UTF_8);

        String[] algorithms = {"SHA256withRSA", "SHA256withRSA/PSS"};
        for (String algorithm : algorithms) {
            byte[] suffixOnlySignature = sign(algorithm, keyPair.getPrivate(), signedSuffix);

            assertFalse("A suffix-only signature must not verify prefix + suffix for " + algorithm,
                    verifyInTwoUpdatesOrFalse(algorithm, keyPair.getPublic(),
                            attackerControlledPrefix, signedSuffix, suffixOnlySignature));
        }
    }

    @Test
    public void testRSARequiresInitialization() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        byte[] data = "data".getBytes(StandardCharsets.UTF_8);

        try {
            signature.update(data);
            fail("Expected SignatureException before init");
        } catch (SignatureException expected) {
            // Expected.
        }

        try {
            signature.sign();
            fail("Expected SignatureException before initSign");
        } catch (SignatureException expected) {
            // Expected.
        }

        try {
            signature.verify(new byte[256]);
            fail("Expected SignatureException before initVerify");
        } catch (SignatureException expected) {
            // Expected.
        }
    }

    @Test
    public void testRSAFailedInitPreservesPreviousState() throws Exception {
        KeyPair rsaKeyPair = generateKeyPair();
        KeyPair ecKeyPair = generateEcKeyPair();
        byte[] data = "RSA state after failed init".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(rsaKeyPair.getPrivate());
        signer.update(data);
        try {
            signer.initVerify(ecKeyPair.getPublic());
            fail("Expected InvalidKeyException for EC public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        byte[] preservedSignature = signer.sign();
        assertTrue("Failed initVerify must leave the previous signing state usable",
                verify("SHA256withRSA", rsaKeyPair.getPublic(), data, preservedSignature));

        byte[] signature = sign("SHA256withRSA", rsaKeyPair.getPrivate(), data);
        Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(rsaKeyPair.getPublic());
        verifier.update(data);
        try {
            verifier.initSign(ecKeyPair.getPrivate());
            fail("Expected InvalidKeyException for EC private key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        assertTrue("Failed initSign must leave the previous verification state usable",
                verifier.verify(signature));
    }

    @Test
    public void testRSASignClearsBufferedMessageBytes() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "sensitive rsa signing payload that grows the internal buffer".getBytes(StandardCharsets.UTF_8);
        RSASigner signer = new RSASigner.SHA256withRSA();

        signer.engineInitSign(keyPair.getPrivate());
        signer.engineUpdate(data, 0, data.length);

        byte[] signature = signer.engineSign();

        assertNotNull(signature);
        assertMessageBufferCleared(signer);
    }

    @Test
    public void testRSAVerifyClearsBufferedMessageBytes() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "sensitive rsa verification payload that grows the internal buffer".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", keyPair.getPrivate(), data);
        RSASigner verifier = new RSASigner.SHA256withRSA();

        verifier.engineInitVerify(keyPair.getPublic());
        verifier.engineUpdate(data, 0, data.length);

        assertTrue(verifier.engineVerify(signature));
        assertMessageBufferCleared(verifier);
    }

    @Test
    public void testRSAVerifyClearsBufferedMessageBytesWhenSignatureIsNull() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "sensitive rsa verification payload before null signature".getBytes(StandardCharsets.UTF_8);
        RSASigner verifier = new RSASigner.SHA256withRSA();

        verifier.engineInitVerify(keyPair.getPublic());
        verifier.engineUpdate(data, 0, data.length);

        try {
            verifier.engineVerify(null);
            fail("Expected null signature to be rejected");
        } catch (SignatureException expected) {
            // expected
        }
        assertMessageBufferCleared(verifier);
    }

    @Test
    public void testRSAReinitClearsPreviousBufferedMessageBytes() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "sensitive rsa payload buffered before reinitialization".getBytes(StandardCharsets.UTF_8);
        RSASigner signer = new RSASigner.SHA256withRSA();

        signer.engineInitSign(keyPair.getPrivate());
        signer.engineUpdate(data, 0, data.length);
        RSASigner.MessageBufferStatus previousBuffer = signer.messageBufferStatus();

        signer.engineInitVerify(keyPair.getPublic());

        assertMessageBufferCleared(previousBuffer);
    }

    @Test
    public void testLowLevelRSAImplRequiresPublicExponentWhenSettingKeys() throws Exception {
        byte[] modulus = new byte[] {0x01};
        byte[] privateExponent = new byte[] {0x01};

        try {
            RSAImpl.class.getConstructor(byte[].class, byte[].class);
            fail("Expected exponent-less RSAImpl constructor to be removed");
        } catch (NoSuchMethodException expected) {
            // Expected.
        }

        try {
            RSAImpl.class.getMethod("setKeys", byte[].class, byte[].class);
            fail("Expected exponent-less RSAImpl.setKeys to be removed");
        } catch (NoSuchMethodException expected) {
            // Expected.
        }

        RSAImpl rsa = new RSAImpl();
        try {
            rsa.setKeys(modulus, privateExponent, null);
            fail("Expected null public exponent to be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("public exponent"));
        }

        try {
            rsa.setKeys(modulus, privateExponent, new byte[0]);
            fail("Expected empty public exponent to be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("public exponent"));
        }
    }

    @Test
    public void testNativeRSASetKeysRequiresPublicExponent() {
        byte[] modulus = new byte[] {0x01};
        byte[] privateExponent = new byte[] {0x01};
        long ctx = CryptoNative.rsaCreateContext();
        try {
            try {
                CryptoNative.rsaSetKeys(ctx, modulus, privateExponent, null);
                fail("Expected native rsaSetKeys to reject null public exponent");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("public exponent"));
            }

            try {
                CryptoNative.rsaSetKeys(ctx, modulus, privateExponent, new byte[0]);
                fail("Expected native rsaSetKeys to reject empty public exponent");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("public exponent"));
            }
        } finally {
            CryptoNative.rsaFreeContext(ctx);
        }
    }

    @Test
    public void testInitVerifyRejectsPublicKeyWithoutExponent() throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);

        try {
            verifier.initVerify(new MissingExponentRSAPublicKey(BigInteger.valueOf(3233)));
            fail("Expected InvalidKeyException for RSA public key without exponent");
        } catch (InvalidKeyException expected) {
            assertTrue("Failure should identify the missing public exponent",
                    expected.getMessage().contains("public exponent"));
        }
    }

    @Test
    public void testRSAKeyFactoryRoundTrip() throws Exception {
        KeyPair keyPair = generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);

        PublicKey restoredPublic = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
        PrivateKey restoredPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

        byte[] data = "RSA key factory round trip".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", restoredPrivate, data);
        assertTrue("Restored RSA keys should sign and verify",
                verify("SHA256withRSA", restoredPublic, data, signature));
    }

    @Test
    public void testRSAPrivateKeyDecodesPkcs8WithAttributes() throws Exception {
        KeyPair keyPair = generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        byte[] withAttributes = appendEmptyAttributesToPkcs8(keyPair.getPrivate().getEncoded());

        PrivateKey restoredPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(withAttributes));

        byte[] data = "RSA PKCS#8 attributes".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", restoredPrivate, data);
        assertTrue("RSA private key with PKCS#8 attributes should sign and verify",
                verify("SHA256withRSA", keyPair.getPublic(), data, signature));
    }

    @Test
    public void testRSAKeyFactoryDecodesPemKeys() throws Exception {
        KeyPair keyPair = generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);

        PublicKey restoredPublic = keyFactory.generatePublic(new X509EncodedKeySpec(
                toPem("PUBLIC KEY", keyPair.getPublic().getEncoded())));
        PrivateKey restoredPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(
                toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded())));

        byte[] data = "RSA PEM key factory decode".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", restoredPrivate, data);
        assertTrue("PEM-decoded RSA keys should sign and verify",
                verify("SHA256withRSA", restoredPublic, data, signature));
    }

    @Test
    public void testRSAPrivateCrtKeyEncodingRoundTrip() throws Exception {
        KeyPair keyPair = generateKeyPair();
        assertTrue("Generated RSA private key should expose CRT parameters",
                keyPair.getPrivate() instanceof RSAPrivateCrtKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPrivateCrtKeySpec crtSpec = keyFactory.getKeySpec(crtKey, RSAPrivateCrtKeySpec.class);
        PrivateKey restoredPrivate = keyFactory.generatePrivate(crtSpec);

        assertNotNull("CRT RSA private key should have PKCS#8 encoding", restoredPrivate.getEncoded());
        PrivateKey reparsedPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(restoredPrivate.getEncoded()));

        byte[] data = "RSA CRT private key encoding".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", reparsedPrivate, data);
        assertTrue("Reparsed CRT RSA private key should sign and verify",
                verify("SHA256withRSA", keyPair.getPublic(), data, signature));
    }

    @Test
    public void testTranslateNonCrtPrivateKeyPreservesPublicExponent() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        PrivateKey nonCrtPrivate = new RSAPrivateKeyImpl(privateKey.getModulus(),
                privateKey.getPrivateExponent(), privateKey.getPublicExponent());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        Key translated = keyFactory.translateKey(nonCrtPrivate);

        assertTrue("Translated RSA private key should preserve provider key type",
                translated instanceof RSAPrivateKeyImpl);
        assertEquals("Translated RSA private key should preserve public exponent",
                privateKey.getPublicExponent(), ((RSAPrivateKeyImpl) translated).getPublicExponent());
        assertNotNull("Translated RSA private key should remain PKCS#8 encodable",
                ((PrivateKey) translated).getEncoded());

        byte[] data = "RSA translated non-CRT private key".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", (PrivateKey) translated, data);
        assertTrue("Translated non-CRT RSA private key should sign with preserved public exponent",
                verify("SHA256withRSA", keyPair.getPublic(), data, signature));
    }

    @Test
    public void testNonCrtPrivateKeyWithPublicExponentEncodingRoundTrip() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        PrivateKey nonCrtPrivate = new RSAPrivateKeyImpl(privateKey.getModulus(),
                privateKey.getPrivateExponent(), privateKey.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);

        byte[] encoded = nonCrtPrivate.getEncoded();
        assertNotNull("Non-CRT RSA private key with public exponent should be PKCS#8 encodable", encoded);

        PrivateKey reparsedPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        assertFalse("Reparsed no-CRT RSA private key should not expose CRT parameters",
                reparsedPrivate instanceof RSAPrivateCrtKey);
        assertTrue("Reparsed no-CRT RSA private key should preserve provider key type",
                reparsedPrivate instanceof RSAPrivateKeyImpl);
        assertEquals("Reparsed no-CRT RSA private key should preserve public exponent",
                privateKey.getPublicExponent(), ((RSAPrivateKeyImpl) reparsedPrivate).getPublicExponent());

        byte[] data = "RSA no-CRT private key encoding".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", reparsedPrivate, data);
        assertTrue("Reparsed no-CRT RSA private key should sign and verify",
                verify("SHA256withRSA", keyPair.getPublic(), data, signature));
    }

    @Test
    public void testMinimalRSAPrivateKeyDoesNotGuessPublicExponent() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);

        PrivateKey minimalPrivate = keyFactory.generatePrivate(
                new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent()));

        assertTrue("Minimal RSA private key should preserve an unknown public exponent",
                minimalPrivate instanceof RSAPrivateKeyImpl);
        assertNull("Minimal RSA private key should not default public exponent to 65537",
                ((RSAPrivateKeyImpl) minimalPrivate).getPublicExponent());
        assertNull("RSA private key without public exponent should not advertise PKCS#8 format",
                minimalPrivate.getFormat());
        assertNull("RSA private key without public exponent should not provide PKCS#8 encoding",
                minimalPrivate.getEncoded());
    }

    @Test
    public void testMinimalRSAPrivateKeySigningRejectedAtInit() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);

        PrivateKey minimalPrivate = keyFactory.generatePrivate(
                new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent()));
        Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);

        try {
            signer.initSign(minimalPrivate);
            fail("Expected RSA signing init to reject private key without public exponent");
        } catch (InvalidKeyException expected) {
            assertTrue("Failure should identify the missing public exponent",
                    expected.getMessage().contains("public exponent"));
        }
    }

    @Test
    public void testInvalidRsaPublicKeySemanticValidationComesFromOpenHiTLS() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        PublicKey invalidPublic = keyFactory.generatePublic(
                new RSAPublicKeySpec(BigInteger.valueOf(3233), BigInteger.valueOf(2)));

        try {
            invalidPublic.getEncoded();
            fail("Expected OpenHiTLS to reject RSA public key encoding with an even public exponent");
        } catch (IllegalStateException expected) {
            assertTrue("Encoding failure should preserve the native OpenHiTLS error",
                    expected.getCause() instanceof IllegalStateException);
            assertTrue("Encoding failure should come from the native RSA public key setup",
                    expected.getCause().getMessage().contains("Failed to set RSA public key"));
        }
    }

    @Test
    public void testJdkMinimalRSAPrivateKeyImportRejectsMissingPublicExponent() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        assertEquals(BigInteger.valueOf(3), publicKey.getPublicExponent());

        KeyFactory jdkKeyFactory = KeyFactory.getInstance("RSA");
        PrivateKey minimalPrivate = jdkKeyFactory.generatePrivate(
                new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent()));
        assertFalse("JDK minimal RSA private key should not expose CRT parameters",
                minimalPrivate instanceof RSAPrivateCrtKey);
        assertNotNull("JDK minimal RSA private key should provide PKCS#8 input for import",
                minimalPrivate.getEncoded());

        KeyFactory hitlsKeyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        try {
            hitlsKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(minimalPrivate.getEncoded()));
            fail("Expected exponent-less PKCS#8 RSA private key import to fail");
        } catch (java.security.spec.InvalidKeySpecException expected) {
            assertTrue("Failure should come from RSA private key decoding",
                    expected.getMessage().contains("Invalid PKCS#8 RSA private key"));
        }
    }

    @Test
    public void testRSASignatureWithNonDefaultPublicExponentAfterImport() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)), new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        PublicKey restoredPublic = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
        PrivateKey restoredPrivate = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));

        byte[] data = "RSA non-default public exponent".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign("SHA256withRSA", restoredPrivate, data);

        assertTrue("Imported non-65537 RSA key should verify with its real public exponent",
                verify("SHA256withRSA", restoredPublic, data, signature));
    }

    // @Test
    // public void testRSAWithDifferentMessageLengths() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();

    //     // Test messages of different lengths
    //     String[] testMessages = {
    //         "", // Empty message
    //         "Short message",
    //         "Medium length message for RSA testing",
    //         "A longer message that spans multiple blocks to test RSA signing and verification with larger data sizes"
    //     };

    //     for (String message : testMessages) {
    //         byte[] data = message.getBytes();

    //         // Sign
    //         Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //         signer.initSign(keyPair.getPrivate());
    //         signer.update(data);
    //         byte[] signature = signer.sign();

    //         // Verify
    //         Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //         verifier.initVerify(keyPair.getPublic());
    //         verifier.update(data);
    //         boolean verified = verifier.verify(signature);

    //         assertTrue("Signature verification failed for message: " + message, verified);
    //     }
    // }

    // @Test
    // public void testRSASignatureConsistency() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();
    //     byte[] data = "Test data for RSA signature consistency".getBytes();

    //     // Sign the same data multiple times
    //     Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     signer.initSign(keyPair.getPrivate());

    //     // Sign multiple times and verify each signature
    //     for (int i = 0; i < 5; i++) {
    //         signer.update(data);
    //         byte[] signature = signer.sign();

    //         Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //         verifier.initVerify(keyPair.getPublic());
    //         verifier.update(data);
    //         boolean verified = verifier.verify(signature);

    //         assertTrue("Signature verification failed on iteration " + i, verified);
    //     }
    // }

    // @Test
    // public void testRSAWithDifferentKeySizes() throws Exception {
    //     int[] keySizes = {1024, 2048, 3072, 4096};
    //     for (int keySize : keySizes) {
    //         // Initialize the key pair generator
    //         KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //         keyGen.initialize(keySize, new SecureRandom());

    //         // Generate key pair
    //         KeyPair keyPair = keyGen.generateKeyPair();
    //         RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    //         RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    //         // Verify key size
    //         assertEquals("Generated key size does not match requested size",
    //                     keySize, publicKey.getModulus().bitLength());

    //         // Test signing and verification
    //         byte[] data = "Test data for RSA with different key sizes".getBytes();
        
    //         // Sign
    //         Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //         signer.initSign(privateKey);
    //         signer.update(data);
    //         byte[] signature = signer.sign();

    //         // Verify
    //         Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //         verifier.initVerify(publicKey);
    //             verifier.update(data);
    //             boolean verified = verifier.verify(signature);
    //             assertTrue("Signature verification failed for key size: " + keySize, verified);
    //     }
    // }

    // @Test
    // public void testRSAInvalidSignature() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();
    //     byte[] data = "Test data for RSA invalid signature".getBytes();

    //     // Sign the data
    //     Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(data);
    //     byte[] signature = signer.sign();

    //     // Modify the signature
    //     signature[0] ^= 0xFF; // Flip bits in the first byte

    //     // Verify the modified signature
    //     Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     verifier.initVerify(keyPair.getPublic());
    //     verifier.update(data);
    //     boolean verified = verifier.verify(signature);

    //     assertFalse("Modified signature should not verify", verified);
    // }

    // @Test
    // public void testRSASignatureWithDifferentData() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();

    //     // Sign original data
    //     byte[] originalData = "Original test data".getBytes();
    //     Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(originalData);
    //     byte[] signature = signer.sign();

    //     // Try to verify with different data
    //     byte[] differentData = "Different test data".getBytes();
    //     Signature verifier = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     verifier.initVerify(keyPair.getPublic());
    //     verifier.update(differentData);
    //     boolean verified = verifier.verify(signature);

    //     assertFalse("Signature should not verify with different data", verified);
    // }

    // @Test
    // public void testRSASignatureWithDifferentHashAlgorithms() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();
    //     byte[] data = "Test data for RSA signing with different hash algorithms".getBytes();

    //     // Test different hash algorithms
    //     String[] hashAlgorithms = {
    //         "SHA224withRSA",
    //         "SHA256withRSA",
    //         "SHA384withRSA",
    //         "SHA512withRSA",
    //         "SM3withRSA"
    //     };

    //     for (String algorithm : hashAlgorithms) {
    //         // Create and initialize signature for signing
    //         Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
    //         signer.initSign(keyPair.getPrivate());
    //         signer.update(data);
    //         byte[] signature = signer.sign();

    //         // Verify the signature
    //         Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
    //         verifier.initVerify(keyPair.getPublic());
    //         verifier.update(data);
    //         boolean verified = verifier.verify(signature);

    //         assertTrue("Signature verification failed for algorithm: " + algorithm, verified);
    //     }
    // }

    // @Test
    // public void testRSASignatureWithDifferentHashAlgorithmsAndMessageLengths() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();

    //     // Test messages of different lengths
    //     String[] testMessages = {
    //         "", // Empty message
    //         "Short message",
    //         "Medium length message for RSA testing",
    //         "A longer message that spans multiple blocks to test RSA signing and verification with larger data sizes"
    //     };

    //     String[] hashAlgorithms = {
    //         "SHA224withRSA",
    //         "SHA256withRSA",
    //         "SHA384withRSA",
    //         "SHA512withRSA",
    //         "SM3withRSA"
    //     };

    //     for (String algorithm : hashAlgorithms) {
    //         for (String message : testMessages) {
    //             byte[] data = message.getBytes();

    //             // Sign
    //             Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
    //             signer.initSign(keyPair.getPrivate());
    //             signer.update(data);
    //             byte[] signature = signer.sign();

    //             // Verify
    //             Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
    //             verifier.initVerify(keyPair.getPublic());
    //             verifier.update(data);
    //             boolean verified = verifier.verify(signature);

    //             assertTrue(String.format("Signature verification failed for algorithm: %s, message: %s", 
    //                 algorithm, message.isEmpty() ? "empty" : message), verified);
    //         }
    //     }
    // }

    // @Test
    // public void testRSASignatureVerificationWithWrongAlgorithm() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();
    //     byte[] data = "Test data for RSA signing with different hash algorithms".getBytes();

    //     // Sign with SHA256
    //     Signature signer = Signature.getInstance("SHA256withRSA", HiTls4jProvider.PROVIDER_NAME);
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(data);
    //     byte[] signature = signer.sign();

    //     // Try to verify with different algorithms
    //     String[] otherAlgorithms = {
    //         "SHA224withRSA",
    //         "SHA384withRSA",
    //         "SHA512withRSA",
    //         "SM3withRSA"
    //     };

    //     for (String algorithm : otherAlgorithms) {
    //         Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
    //         verifier.initVerify(keyPair.getPublic());
    //         verifier.update(data);
    //         boolean verified = verifier.verify(signature);

    //         assertFalse("Signature should not verify with wrong algorithm: " + algorithm, verified);
    //     }
    // }

    @Test
    public void testRSAPSSSignature() throws Exception {
        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();
        byte[] data = "Test data for RSA PSS signing".getBytes();

        // Test different hash algorithms with PSS
        String[] hashAlgorithms = {
            "SHA224withRSA/PSS",
            "SHA256withRSA/PSS",
            "SHA384withRSA/PSS",
            "SHA512withRSA/PSS"
        };

        for (String algorithm : hashAlgorithms) {
            // Sign with PSS
            Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();

            // Verify the PSS signature
            Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean verified = verifier.verify(signature);

            assertTrue("PSS signature verification failed for algorithm: " + algorithm, verified);
        }
    }

    @Test
    public void testUnsupportedSM3RSAPSSIsNotRegistered() throws Exception {
        try {
            Signature.getInstance("SM3withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
            fail("SM3withRSA/PSS should not be registered because native PSS parameters reject SM3");
        } catch (NoSuchAlgorithmException expected) {
            // Expected.
        }
    }

    @Test
    public void testRSAPSSDoesNotUsePKCS1Padding() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "RSA PSS must not fall back to PKCS#1 v1.5".getBytes(StandardCharsets.UTF_8);

        byte[] pssSignature = sign("SHA256withRSA/PSS", keyPair.getPrivate(), data);
        assertTrue("PSS signature should verify with PSS",
                verify("SHA256withRSA/PSS", keyPair.getPublic(), data, pssSignature));
        assertFalse("PSS signature should not verify with PKCS#1 padding",
                verifyOrFalse("SHA256withRSA", keyPair.getPublic(), data, pssSignature));

        byte[] pkcs1Signature = sign("SHA256withRSA", keyPair.getPrivate(), data);
        assertTrue("PKCS#1 signature should verify with PKCS#1 padding",
                verify("SHA256withRSA", keyPair.getPublic(), data, pkcs1Signature));
        assertFalse("PKCS#1 signature should not verify with PSS",
                verifyOrFalse("SHA256withRSA/PSS", keyPair.getPublic(), data, pkcs1Signature));
    }

    @Test
    public void testRSAPSSSignatureWithCustomParameters() throws Exception {
        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();
        byte[] data = "Test data for RSA PSS signing with custom parameters".getBytes();

        // Test different PSS parameter combinations
        String[] hashAlgorithms = {"SHA256", "SHA384", "SHA512"};
        int[] saltLengths = {32}; // Fixed salt length to match test suite

        for (String hashAlg : hashAlgorithms) {
            for (int saltLen : saltLengths) {
                // Create PSS parameter spec with custom values
                RSAPadding.PSSParameterSpec pssParams = new RSAPadding.PSSParameterSpec(
                    hashAlg,    // Hash algorithm
                    hashAlg,    // MGF1 hash algorithm
                    saltLen,    // Salt length
                    1           // Trailer field
                );

                // Sign with PSS using custom parameters
                Signature signer = Signature.getInstance(hashAlg + "withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
                signer.setParameter(pssParams);
                signer.initSign(keyPair.getPrivate());
                signer.update(data);
                byte[] signature = signer.sign();
                // Verify with same parameters
                Signature verifier = Signature.getInstance(hashAlg + "withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
                verifier.setParameter(pssParams);
                verifier.initVerify(keyPair.getPublic());
                verifier.update(data);
                boolean verified = verifier.verify(signature);

                assertTrue(String.format("PSS signature verification failed for hash: %s, salt length: %d",
                    hashAlg, saltLen), verified);
            }
        }
    }

    @Test
    public void testRSAPSSSignatureWithDifferentMessageLengths() throws Exception {
        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();

        // Test messages of different lengths
        String[] testMessages = {
            "", // Empty message
            "Short message",
            "Medium length message for RSA PSS testing",
            "A longer message that spans multiple blocks to test RSA PSS signing and verification with larger data sizes"
        };

        // Use SHA256 with PSS and custom parameters
        RSAPadding.PSSParameterSpec pssParams = new RSAPadding.PSSParameterSpec(
            "SHA256",  // Hash algorithm
            "SHA256",  // MGF1 hash algorithm
            32,        // Salt length
            1          // Trailer field
        );

        for (String message : testMessages) {
            byte[] data = message.getBytes();

            // Sign
            Signature signer = Signature.getInstance("SHA256withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
            signer.setParameter(pssParams);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();

            // Verify
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
            verifier.setParameter(pssParams);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean verified = verifier.verify(signature);

            assertTrue("PSS signature verification failed for message: " + 
                (message.isEmpty() ? "empty" : message), verified);
        }
    }

    // @Test
    // public void testRSAPSSSignatureWithInvalidParameters() throws Exception {
    //     // Initialize the key pair generator
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
    //     keyGen.initialize(2048, new SecureRandom());

    //     // Generate key pair
    //     KeyPair keyPair = keyGen.generateKeyPair();
    //     byte[] data = "Test data for RSA PSS signing".getBytes();

    //     // Test with invalid salt length (too large for key size)
    //     RSAPadding.PSSParameterSpec invalidSaltParams = new RSAPadding.PSSParameterSpec(
    //         "SHA256",  // Hash algorithm
    //         "SHA256",  // MGF1 hash algorithm
    //         300,       // Invalid salt length (too large)
    //         1          // Trailer field
    //     );

    //     Signature signer = Signature.getInstance("SHA256withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
    //     signer.setParameter(invalidSaltParams);
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(data);

    //     try {
    //         signer.sign();
    //         fail("Should throw SignatureException for invalid salt length");
    //     } catch (SignatureException e) {
    //         // Expected exception
    //     }

    //     // Test with mismatched hash algorithms
    //     RSAPadding.PSSParameterSpec mismatchedParams = new RSAPadding.PSSParameterSpec(
    //         "SHA256",  // Hash algorithm
    //         "SHA512",  // Different MGF1 hash algorithm
    //         32,        // Salt length
    //         1          // Trailer field
    //     );

    //     // Sign with one set of parameters
    //     signer = Signature.getInstance("SHA256withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
    //     signer.setParameter(new RSAPadding.PSSParameterSpec(
    //         "SHA256",  // Hash algorithm
    //         "SHA256",  // MGF1 hash algorithm
    //         32,        // Salt length
    //         1          // Trailer field
    //     ));
    //     signer.initSign(keyPair.getPrivate());
    //     signer.update(data);
    //     byte[] signature = signer.sign();

    //     // Try to verify with different parameters
    //     Signature verifier = Signature.getInstance("SHA256withRSA/PSS", HiTls4jProvider.PROVIDER_NAME);
    //     verifier.setParameter(mismatchedParams);
    //     verifier.initVerify(keyPair.getPublic());
    //     verifier.update(data);
    //     boolean verified = verifier.verify(signature);

    //     assertFalse("Signature should not verify with mismatched parameters", verified);
    // }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(256, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static byte[] sign(String algorithm, PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    private static byte[] signInTwoUpdates(String algorithm, PrivateKey privateKey, byte[] first, byte[] second)
            throws Exception {
        Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(first);
        signer.update(second);
        return signer.sign();
    }

    private static boolean verify(String algorithm, PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static boolean verifyInTwoUpdatesOrFalse(String algorithm, PublicKey publicKey, byte[] first,
            byte[] second, byte[] signature) throws Exception {
        try {
            Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(first);
            verifier.update(second);
            return verifier.verify(signature);
        } catch (SignatureException expected) {
            return false;
        }
    }

    private static boolean verifyOrFalse(String algorithm, PublicKey publicKey, byte[] data, byte[] signature)
            throws Exception {
        try {
            return verify(algorithm, publicKey, data, signature);
        } catch (SignatureException expected) {
            return false;
        }
    }

    private static void assertMessageBufferCleared(RSASigner signer) {
        assertMessageBufferCleared(signer.messageBufferStatus());
    }

    private static void assertMessageBufferCleared(RSASigner.MessageBufferStatus messageBuffer) {
        assertNotNull("Message buffer should exist", messageBuffer);
        assertTrue("Message buffer should be cleared", messageBuffer.isCleared());
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static byte[] toPem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] appendEmptyAttributesToPkcs8(byte[] pkcs8) {
        if (pkcs8.length < 2 || pkcs8[0] != 0x30) {
            throw new IllegalArgumentException("Expected DER SEQUENCE");
        }
        int[] lengthInfo = readDerLength(pkcs8, 1);
        int lengthOffset = lengthInfo[0];
        int lengthBytes = lengthInfo[1];
        int contentLength = lengthInfo[2];
        int contentOffset = lengthOffset + lengthBytes;
        if (contentOffset + contentLength != pkcs8.length) {
            throw new IllegalArgumentException("Invalid DER SEQUENCE length");
        }

        byte[] attributes = {(byte) 0xa0, 0x00};
        byte[] newLength = encodeDerLength(contentLength + attributes.length);
        byte[] result = new byte[1 + newLength.length + contentLength + attributes.length];
        result[0] = 0x30;
        System.arraycopy(newLength, 0, result, 1, newLength.length);
        System.arraycopy(pkcs8, contentOffset, result, 1 + newLength.length, contentLength);
        System.arraycopy(attributes, 0, result, 1 + newLength.length + contentLength, attributes.length);
        return result;
    }

    private static int[] readDerLength(byte[] der, int offset) {
        int first = der[offset] & 0xff;
        if ((first & 0x80) == 0) {
            return new int[] {offset, 1, first};
        }
        int lengthBytes = first & 0x7f;
        if (lengthBytes == 0 || lengthBytes > 4 || offset + lengthBytes >= der.length) {
            throw new IllegalArgumentException("Invalid DER length");
        }
        int length = 0;
        for (int i = 0; i < lengthBytes; i++) {
            length = (length << 8) | (der[offset + 1 + i] & 0xff);
        }
        return new int[] {offset, 1 + lengthBytes, length};
    }

    private static byte[] encodeDerLength(int length) {
        if (length < 0x80) {
            return new byte[] {(byte) length};
        }
        int bytes = 0;
        for (int value = length; value > 0; value >>= 8) {
            bytes++;
        }
        byte[] result = new byte[1 + bytes];
        result[0] = (byte) (0x80 | bytes);
        for (int i = bytes; i > 0; i--) {
            result[i] = (byte) (length & 0xff);
            length >>= 8;
        }
        return result;
    }

    private static final class MissingExponentRSAPublicKey implements RSAPublicKey {
        private static final long serialVersionUID = 1L;

        private final BigInteger modulus;

        private MissingExponentRSAPublicKey(BigInteger modulus) {
            this.modulus = modulus;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }

        @Override
        public BigInteger getPublicExponent() {
            return null;
        }

        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }
}
