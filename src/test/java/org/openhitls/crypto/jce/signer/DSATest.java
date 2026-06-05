package org.openhitls.crypto.jce.signer;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
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

    private static KeyPair generateKeyPair() throws Exception {
        DSAParameterSpec paramSpec = new DSAParameterSpec(P, Q, G);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(paramSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("DSA", HiTls4jProvider.PROVIDER_NAME);
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
} 
