package org.openhitls.crypto.jce.pqc;

import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;
import org.openhitls.crypto.jce.spec.SLHDSAPrivateKeySpec;
import org.openhitls.crypto.jce.spec.SLHDSAPublicKeySpec;
import org.openhitls.crypto.jce.spec.SLHDSASignatureParameterSpec;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import org.junit.Test;

public class SLHDSATest extends BaseTest {

    private static final String[] SUPPORTED_PARAMETERSETS = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };
    
    @Test
    public void testKeyGeneration() throws Exception {
        for (String parameterSet : SUPPORTED_PARAMETERSETS) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(new SLHDSAParameterSpec(parameterSet));
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            assertNotNull(publicKey);
            assertNotNull(privateKey);

            KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
            SLHDSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, SLHDSAPublicKeySpec.class);
            SLHDSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, SLHDSAPrivateKeySpec.class);
            assertNotNull(publicKeySpec);
            assertNotNull(privateKeySpec);
        }
    }

    @Test
    public void testSignatureGeneration() throws Exception {
        for (String parameterSet : SUPPORTED_PARAMETERSETS) {
            // generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(new SLHDSAParameterSpec(parameterSet));
            KeyPair keyPair = keyGen.generateKeyPair();

            // sign data
            byte[] data = "Hello, World!".getBytes();
            Signature signer = Signature.getInstance("SHA256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();
            
            // verify signature
            Signature verifier = Signature.getInstance("SHA256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean result = verifier.verify(signature);
            assertTrue(result);

            // verify signature with modified data
            data[0] ^= 0x01;
            verifier.update(data);
            result = verifier.verify(signature);
            assertFalse(result);
        }
    }

    @Test
    public void testSignatureVerification() throws Exception {
        for (String parameterSet : SUPPORTED_PARAMETERSETS) {
            // genearte keyPair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(new SLHDSAParameterSpec(parameterSet));
            KeyPair keyPair = keyGen.generateKeyPair();

            // sign data
            byte[] data = "Hello, World!".getBytes();
            Signature signer = Signature.getInstance("SHA384withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();

            // verify
            Signature verifier = Signature.getInstance("SHA384withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean result = verifier.verify(signature);
            assertTrue(result);

            // verify with another pulic key
            KeyPairGenerator keyGen1 = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
            keyGen1.initialize(new SLHDSAParameterSpec(parameterSet));
            KeyPair keyPair1 = keyGen1.generateKeyPair();
            Signature verifier1 = Signature.getInstance("SHA384withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
            verifier1.initVerify(keyPair1.getPublic());
            verifier1.update(data);
            assertFalse(verifier1.verify(signature));

            // verify with modified data
            data[0] ^= 0x01;
            verifier.update(data);
            assertFalse(verifier.verify(signature));
        }
    }

    @Test
    public void testSignatureAndVerificationWithDeterministic() throws Exception {
        // generate keyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new SLHDSAParameterSpec("SLH-DSA-SHA2-128s"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // sign data with deterministic signature
        byte[] data = "Hello, World!".getBytes();
        Signature signer = Signature.getInstance("SHAKE128withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(new SLHDSASignatureParameterSpec(true, false, null, null));
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // verify
        Signature verifier = Signature.getInstance("SHAKE128withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(new SLHDSASignatureParameterSpec(true, false, null, null));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean result = verifier.verify(signature);
        assertTrue(result);
    }

    @Test
    public void testSignatureAndVerificationWithPreHash() throws Exception {
        // generate keyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new SLHDSAParameterSpec("SLH-DSA-SHA2-128s"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // sign data with preHashed data
        byte[] data = "Hello, World!".getBytes();
        Signature signer = Signature.getInstance("SHAKE128withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(new SLHDSASignatureParameterSpec(false, true, null, null));
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // verify
        Signature verifier = Signature.getInstance("SHAKE128withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(new SLHDSASignatureParameterSpec(false, true, null, null));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean result = verifier.verify(signature);
        assertTrue(result);
    }

    @Test
    public void testSignatureAndVerificationWithContext() throws Exception {
        // generate keyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new SLHDSAParameterSpec("SLH-DSA-SHA2-128s"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // sign data with context
        byte[] data = "Hello, World!".getBytes();
        byte[] context = "this is context".getBytes();
        Signature signer = Signature.getInstance("SHAKE256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(new SLHDSASignatureParameterSpec(false, false, context, null));
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // verify
        Signature verifier = Signature.getInstance("SHAKE256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(new SLHDSASignatureParameterSpec(false, false, context, null));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean result = verifier.verify(signature);
        assertTrue(result);
    }

    @Test
    public void testSignatureAndVerificationWithAdditionalRandomness() throws Exception {
        // generate keyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(new SLHDSAParameterSpec("SLH-DSA-SHA2-128s"));
        KeyPair keyPair = keyGen.generateKeyPair();

        // sign data with additional randomness
        byte[] data = "Hello, World!".getBytes();
        SecureRandom secureRandom = new SecureRandom();
        byte[] additionalRandomness = new byte[16];
        secureRandom.nextBytes(additionalRandomness);

        Signature signer = Signature.getInstance("SHA512withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(new SLHDSASignatureParameterSpec(false, false, null, additionalRandomness));
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // verify
        Signature verifier = Signature.getInstance("SHA512withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(new SLHDSASignatureParameterSpec(false, false, null, additionalRandomness));
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean result = verifier.verify(signature);
        assertTrue(result);
    }

    /**
     * Converts a hex string to a byte array.
     * @param hexString the hex string to convert
     * @return the byte array
     * @throws IllegalArgumentException if the string is not a valid hex string
     */
    private static byte[] hexStringToByteArray(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                                + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }

    @Test
    public void testSignatureGenerationWithGivenKeyData() throws Exception {
        // get key byte array
        byte[] pubKey = hexStringToByteArray("0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C");
        byte[] privKey = hexStringToByteArray("173D04C938C1C36BF289C3C022D04B1463AE23C41AA546DA589774AC20B745C40D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C");
        
        // initialize public and private key
        SLHDSAParameterSpec slhdsaParameterSpec = new SLHDSAParameterSpec("SLH-DSA-SHA2-128s");
        SLHDSAPublicKeySpec publicKeySpec = new SLHDSAPublicKeySpec(pubKey, slhdsaParameterSpec);
        SLHDSAPrivateKeySpec privateKeySpec = new SLHDSAPrivateKeySpec(privKey, slhdsaParameterSpec);

        // generate public and private key
        KeyFactory keyFactory = KeyFactory.getInstance("SLH-DSA", HiTls4jProvider.PROVIDER_NAME);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        // sign data
        byte[] data = "Hello, World!".getBytes();
        Signature signer = Signature.getInstance("SHA256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        
        // verify the signature
        Signature verifier = Signature.getInstance("SHA256withSLHDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean result = verifier.verify(signature);
        assertTrue(result);
    }
}
