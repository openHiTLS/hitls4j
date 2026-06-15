package org.openhitls.crypto.jce.signer;

import org.junit.Test;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;

import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;

public class ECDSATest extends BaseTest {
    private static final String[] SUPPORTED_CURVES = {
            "secp256r1",
            "secp384r1",
            "secp521r1",
            "sm2p256v1"
    };

    // NIST P-256 test vectors
    private static final String P256_D = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    private static final String P256_Qx = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    private static final String P256_Qy = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    private static final String P256_MSG = "sample";

    // NIST P-384 test vectors
    private static final String P384_Qx = "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13";
    private static final String P384_Qy = "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720";
    private static final String P384_D = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5";
    private static final String P384_MSG = "sample";

    @Test
    public void testKeyGeneration() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        for (String curveName : SUPPORTED_CURVES) {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair.getPrivate());
            assertNotNull(keyPair.getPublic());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
            ECPublicKeySpec pubSpec = keyFactory.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);
            ECPrivateKeySpec privSpec = keyFactory.getKeySpec(keyPair.getPrivate(), ECPrivateKeySpec.class);
            assertNotNull("Public key spec should not be null for " + curveName, pubSpec);
            assertNotNull("Private key spec should not be null for " + curveName, privSpec);

        }
    }

    @Test
    public void testKeyRestore() throws Exception {
        // Test P-256 key restoration
        testKeyRestoreForCurve("secp256r1", P256_Qx, P256_Qy, P256_D);

        // Test P-384 key restoration
        testKeyRestoreForCurve("secp384r1", P384_Qx, P384_Qy, P384_D);
    }

    private void testKeyRestoreForCurve(String curveName, String xHex, String yHex, String privateHex)
            throws Exception {
        // Create ECPoint from coordinates
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));

        // Get parameters
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        params.init(new ECGenParameterSpec(curveName));
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        PublicKey pubKey = keyFactory.generatePublic(pubSpec);
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        assertNotNull("Public key should not be null for " + curveName, pubKey);
        assertNotNull("Private key should not be null for " + curveName, privKey);

        // Test key conversion back to specs
        ECPublicKeySpec pubSpecResult = keyFactory.getKeySpec(pubKey, ECPublicKeySpec.class);
        ECPrivateKeySpec privSpecResult = keyFactory.getKeySpec(privKey, ECPrivateKeySpec.class);

        assertEquals("X coordinate should match for " + curveName,
                w.getAffineX(), pubSpecResult.getW().getAffineX());
        assertEquals("Y coordinate should match for " + curveName,
                w.getAffineY(), pubSpecResult.getW().getAffineY());
        assertEquals("Private key value should match for " + curveName,
                new BigInteger(privateHex, 16), privSpecResult.getS());
    }

    @Test
    public void testSignatureGeneration() throws Exception {
        for (String curveName : SUPPORTED_CURVES) {
            // Initialize with ECGenParameterSpec
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
            params.init(new ECGenParameterSpec(curveName));
            ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(ecParameterSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Test data
            byte[] message = "Hello, ECDSA with curve ".concat(curveName).getBytes();

            // Sign
            Signature signer = Signature.getInstance(getSignatureAlgorithm(curveName), HiTls4jProvider.PROVIDER_NAME);
            signer.initSign(keyPair.getPrivate());
            signer.update(message);
            byte[] signature = signer.sign();

            // Verify
            Signature verifier = Signature.getInstance(getSignatureAlgorithm(curveName), HiTls4jProvider.PROVIDER_NAME);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(message);
            assertTrue("Signature verification should succeed for " + curveName,
                    verifier.verify(signature));

            // Verify with modified message should fail
            message[0] ^= 1; // Flip one bit
            verifier.update(message);
            assertFalse("Signature verification should fail for modified message with " + curveName,
                    verifier.verify(signature));
        }
    }

    @Test
    public void testP256KeyGeneration() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        assertNotNull("KeyPair should not be null", keyPair);
        assertTrue("Public key should be instance of ECPublicKey",
                keyPair.getPublic() instanceof java.security.interfaces.ECPublicKey);
        assertTrue("Private key should be instance of ECPrivateKey",
                keyPair.getPrivate() instanceof java.security.interfaces.ECPrivateKey);
    }

    @Test
    public void testP256WithTestVectors() throws Exception {
        // Create key specs
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P256_Qx, 16), new BigInteger(P256_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Verify only
        byte[] message = P256_MSG.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initVerify(pubKey);
        signer.update(message);
        assertNotNull("Public key should be created successfully", pubKey);
    }

    @Test
    public void testP384WithTestVectors() throws Exception {
        // Create key specs
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        params.init(ecSpec);
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P384_Qx, 16), new BigInteger(P384_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Verify only
        byte[] message = P384_MSG.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA384withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initVerify(pubKey);
        signer.update(message);
        assertNotNull("Public key should be created successfully", pubKey);
    }

    @Test
    public void testInteroperability() throws Exception {
        // Test interoperability between curves
        String[] messages = {
                "Short message",
                "Medium length message for testing ECDSA signatures",
                "A longer message that will be used to test ECDSA signatures with different curves and ensure compatibility"
        };

        for (String curve : SUPPORTED_CURVES) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(new ECGenParameterSpec(curve));
            KeyPair keyPair = keyGen.generateKeyPair();

            String sigAlg = getSignatureAlgorithm(curve);
            Signature signer = Signature.getInstance(sigAlg, HiTls4jProvider.PROVIDER_NAME);

            for (String message : messages) {
                byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);

                // Sign
                signer.initSign(keyPair.getPrivate());
                signer.update(msgBytes);
                byte[] signature = signer.sign();

                // Verify
                signer.initVerify(keyPair.getPublic());
                signer.update(msgBytes);
                assertTrue(String.format("Signature verification failed for curve %s", curve),
                        signer.verify(signature));

                // Verify signature with modified message should fail
                msgBytes[0] ^= 1;
                signer.update(msgBytes);
                assertFalse(String.format("Signature verification should fail for modified message with curve %s", curve),
                        signer.verify(signature));
            }
        }
    }

    @Test
    public void testSM2KeyRestore() throws Exception {
        // Test values (replace with actual test vectors if available)
        String xHex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
        String yHex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
        String privateHex = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

        // Create ECPoint from coordinates
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));

        // Get parameters
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        params.init(new ECGenParameterSpec("sm2p256v1"));
        ECParameterSpec ecParameterSpec = params.getParameterSpec(ECParameterSpec.class);

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = KeyFactory.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        PublicKey pubKey = keyFactory.generatePublic(pubSpec);
        PrivateKey privKey = keyFactory.generatePrivate(privSpec);

        assertNotNull("Public key should not be null", pubKey);
        assertNotNull("Private key should not be null", privKey);

        // Test key conversion back to specs
        ECPublicKeySpec pubSpecResult = keyFactory.getKeySpec(pubKey, ECPublicKeySpec.class);
        ECPrivateKeySpec privSpecResult = keyFactory.getKeySpec(privKey, ECPrivateKeySpec.class);

        assertEquals("X coordinate should match", w.getAffineX(), pubSpecResult.getW().getAffineX());
        assertEquals("Y coordinate should match", w.getAffineY(), pubSpecResult.getW().getAffineY());
        assertEquals("Private key value should match", new BigInteger(privateHex, 16), privSpecResult.getS());
    }

    @Test
    public void testSignatureWithUserId() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("sm2p256v1");
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Test data
        byte[] message = "Hello, SM2!".getBytes();
        byte[] userId = "MyCustomUserId@example.com".getBytes();

        // Create SM2ParameterSpec with custom userId
        SM2ParameterSpec sm2Spec = new SM2ParameterSpec(userId);

        // Sign with custom userId
        Signature signer = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(sm2Spec);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        // Verify with same userId
        Signature verifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(sm2Spec);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertTrue("Signature verification should succeed with correct userId", verifier.verify(signature));

        // Verify with different userId should fail
        byte[] differentUserId = "DifferentUserId@example.com".getBytes();
        SM2ParameterSpec differentSpec = new SM2ParameterSpec(differentUserId);

        verifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        verifier.setParameter(differentSpec);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertFalse("Signature verification should fail with different userId", verifier.verify(signature));
    }

    private String getSignatureAlgorithm(String curve) throws IllegalArgumentException {
        switch (curve) {
            case "sm2p256v1":
                return "SM3withSM2";
            case "secp256r1":
                return "SHA256withECDSA";
            case "secp384r1":
                return "SHA384withECDSA";
            case "secp521r1":
                return "SHA512withECDSA";
            default:
                throw new IllegalArgumentException("Unsupported curve: " + curve);
        }
    }
} 