package org.openhitls.crypto.jce.signer;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAParameterSpec;
import java.nio.charset.StandardCharsets;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import java.security.Security;

public class DSATest {
    // Test vectors for 1024-bit DSA parameters
    private static final BigInteger P = new BigInteger(
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447" +
        "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88" +
        "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C" +
        "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779", 16);

    private static final BigInteger Q = new BigInteger(
        "996F967F6C8E388D9E28D01E205FBA957A5698B1", 16);

    private static final BigInteger G = new BigInteger(
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D" +
        "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD" +
        "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4" +
        "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD", 16);

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testDSAKeyPairGeneration() throws Exception {
        // Create DSA parameter specification
        DSAParameterSpec paramSpec = new DSAParameterSpec(P, Q, G);

        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(paramSpec, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Verify keys are not null
        assertNotNull("Public key should not be null", publicKey);
        assertNotNull("Private key should not be null", privateKey);

        // Test signing and verification
        byte[] data = "Test data for DSA signing".getBytes();

        // Create and initialize signature for signing
        Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();

        // Verify the signature
        Signature verifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean verified = verifier.verify(signature);

        assertTrue("Signature verification failed", verified);
    }

    @Test
    public void testDSAWithDifferentMessageLengths() throws Exception {
        // Create DSA parameter specification
        DSAParameterSpec paramSpec = new DSAParameterSpec(P, Q, G);

        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(paramSpec, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();

        // Test messages of different lengths
        String[] testMessages = {
            "", // Empty message
            "Short message",
            "Medium length message for DSA testing",
            "A longer message that spans multiple blocks to test DSA signing and verification with larger data sizes"
        };

        for (String message : testMessages) {
            byte[] data = message.getBytes();

            // Sign
            Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();

            // Verify
            Signature verifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean verified = verifier.verify(signature);

            assertTrue("Signature verification failed for message: " + message, verified);
        }
    }

    @Test
    public void testDSASignatureConsistency() throws Exception {
        // Create DSA parameter specification
        DSAParameterSpec paramSpec = new DSAParameterSpec(P, Q, G);

        // Initialize the key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(paramSpec, new SecureRandom());

        // Generate key pair
        KeyPair keyPair = keyGen.generateKeyPair();
        byte[] data = "Test data for DSA signature consistency".getBytes();

        // Sign the same data multiple times
        Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());

        // Sign multiple times and verify each signature
        for (int i = 0; i < 5; i++) {
            signer.update(data);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean verified = verifier.verify(signature);

            assertTrue("Signature verification failed on iteration " + i, verified);
        }
    }

    @Test
    public void testDSASignResetsBufferForReuse() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] previous = "previous-message".getBytes(StandardCharsets.UTF_8);
        byte[] current = "current-message".getBytes(StandardCharsets.UTF_8);
        byte[] combined = concat(previous, current);

        Signature reusedSigner = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        reusedSigner.initSign(keyPair.getPrivate());
        reusedSigner.update(previous);
        byte[] previousSignature = reusedSigner.sign();
        reusedSigner.update(current);
        byte[] currentSignature = reusedSigner.sign();

        assertTrue(verify(keyPair.getPublic(), previous, previousSignature));
        assertTrue("Reused signer should sign only the new message",
                verify(keyPair.getPublic(), current, currentSignature));
        assertFalse("Reused signer must not sign previous || current",
                verify(keyPair.getPublic(), combined, currentSignature));
    }

    @Test
    public void testDSAVerifyResetsBufferForReuse() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] previous = "previous-message".getBytes(StandardCharsets.UTF_8);
        byte[] current = "current-message".getBytes(StandardCharsets.UTF_8);
        byte[] combined = concat(previous, current);

        byte[] previousSignature = sign(keyPair.getPrivate(), previous);
        byte[] currentSignature = sign(keyPair.getPrivate(), current);
        byte[] combinedSignature = sign(keyPair.getPrivate(), combined);

        assertFalse(verify(keyPair.getPublic(), current, combinedSignature));

        Signature reusedVerifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        reusedVerifier.initVerify(keyPair.getPublic());
        reusedVerifier.update(previous);
        assertTrue(reusedVerifier.verify(previousSignature));

        reusedVerifier.update(current);
        assertFalse("Reused verifier must not verify previous || current",
                reusedVerifier.verify(combinedSignature));

        reusedVerifier.update(current);
        assertTrue("Reused verifier should verify only the new message",
                reusedVerifier.verify(currentSignature));
    }

    @Test
    public void testDSARejectsTamperedSignatureAndData() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "Original DSA test data".getBytes(StandardCharsets.UTF_8);
        byte[] signature = sign(keyPair.getPrivate(), data);

        byte[] tamperedSignature = signature.clone();
        tamperedSignature[0] ^= 0x01;
        assertFalse("Tampered DSA signature should not verify",
                verify(keyPair.getPublic(), data, tamperedSignature));

        byte[] tamperedData = data.clone();
        tamperedData[0] ^= 0x01;
        assertFalse("DSA signature should not verify with tampered data",
                verify(keyPair.getPublic(), tamperedData, signature));
    }

    @Test
    public void testDSADigestAlgorithmsAreDistinct() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "DSA digest mismatch test".getBytes(StandardCharsets.UTF_8);

        byte[] sha512Signature = sign("SHA512withDSA", keyPair.getPrivate(), data);
        assertTrue(verify("SHA512withDSA", keyPair.getPublic(), data, sha512Signature));
        assertFalse("SHA256withDSA must not accept a SHA512withDSA signature",
                verify("SHA256withDSA", keyPair.getPublic(), data, sha512Signature));

        byte[] sha256Signature = sign("SHA256withDSA", keyPair.getPrivate(), data);
        assertTrue(verify("SHA256withDSA", keyPair.getPublic(), data, sha256Signature));
        assertFalse("SHA384withDSA must not accept a SHA256withDSA signature",
                verify("SHA384withDSA", keyPair.getPublic(), data, sha256Signature));
    }

    @Test
    public void testRegisteredDSADigestAlgorithmsSignAndVerify() throws Exception {
        KeyPair keyPair = generateKeyPair();
        byte[] data = "DSA registered digest test".getBytes(StandardCharsets.UTF_8);
        String[] algorithms = {
                "DSA",
                "SHA1withDSA",
                "SHA224withDSA",
                "SHA256withDSA",
                "SHA384withDSA",
                "SHA512withDSA"
        };

        for (String algorithm : algorithms) {
            byte[] signature = sign(algorithm, keyPair.getPrivate(), data);
            assertTrue(algorithm + " signature should verify with the same algorithm",
                    verify(algorithm, keyPair.getPublic(), data, signature));
        }
    }

    @Test
    public void testDSARequiresInitialization() throws Exception {
        Signature signature = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
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
            signature.verify(new byte[40]);
            fail("Expected SignatureException before initVerify");
        } catch (SignatureException expected) {
            // Expected.
        }
    }

    @Test
    public void testDSAFailedInitPreservesPreviousState() throws Exception {
        KeyPair dsaKeyPair = generateKeyPair();
        KeyPair rsaKeyPair = generateRsaKeyPair();
        byte[] data = "DSA state after failed init".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(dsaKeyPair.getPrivate());
        signer.update(data);
        try {
            signer.initSign(rsaKeyPair.getPrivate());
            fail("Expected InvalidKeyException for RSA private key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        byte[] preservedSignature = signer.sign();
        assertTrue("Failed initSign must leave the previous signing state usable",
                verify(dsaKeyPair.getPublic(), data, preservedSignature));

        byte[] signature = sign(dsaKeyPair.getPrivate(), data);
        Signature verifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(dsaKeyPair.getPublic());
        verifier.update(data);
        try {
            verifier.initVerify(rsaKeyPair.getPublic());
            fail("Expected InvalidKeyException for RSA public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        assertTrue("Failed initVerify must leave the previous verification state usable",
                verifier.verify(signature));
    }

    private static KeyPair generateKeyPair() throws Exception {
        DSAParameterSpec paramSpec = new DSAParameterSpec(P, Q, G);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(paramSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    private static byte[] sign(String algorithm, PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    private static boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static boolean verify(String algorithm, PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }
} 
