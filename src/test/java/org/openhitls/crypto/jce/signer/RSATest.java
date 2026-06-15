package org.openhitls.crypto.jce.signer;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import java.security.Security;
import java.security.SignatureException;

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
            "SHA512withRSA/PSS",
            "SM3withRSA/PSS"
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
} 