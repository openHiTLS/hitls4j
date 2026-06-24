package org.openhitls.crypto.jce.signer;

import org.junit.Test;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;

import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;
import org.openhitls.crypto.jce.spec.SM2ParameterSpec;
import org.openhitls.crypto.jce.util.ECKeyEncoding;

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
        for (String curveName : SUPPORTED_CURVES) {
            KeyPairGenerator keyGen = getKeyPairGenerator(curveName);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            assertNotNull(keyPair.getPrivate());
            assertNotNull(keyPair.getPublic());
            KeyFactory keyFactory = getKeyFactory(curveName);
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

    @Test
    public void testRestoredVectorKeysCanSignAndVerify() throws Exception {
        testRestoredVectorKeySignVerify("secp256r1", P256_Qx, P256_Qy, P256_D, "SHA256withECDSA");
        testRestoredVectorKeySignVerify("secp384r1", P384_Qx, P384_Qy, P384_D, "SHA384withECDSA");
    }

    private void testRestoredVectorKeySignVerify(String curveName, String xHex, String yHex,
            String privateHex, String signatureAlgorithm) throws Exception {
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));
        ECParameterSpec ecParameterSpec = getCurveParameters(curveName);
        KeyFactory keyFactory = getKeyFactory(curveName);

        PublicKey pubKey = keyFactory.generatePublic(new ECPublicKeySpec(w, ecParameterSpec));
        PrivateKey privKey = keyFactory.generatePrivate(
                new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec));
        byte[] message = ("vector-key-signature-" + curveName).getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance(signatureAlgorithm, HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privKey);
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(signatureAlgorithm, HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(pubKey);
        verifier.update(message);
        assertTrue("Restored vector key signature should verify for " + curveName, verifier.verify(signature));

        message[0] ^= 0x01;
        verifier.initVerify(pubKey);
        verifier.update(message);
        assertFalse("Restored vector key signature should reject tampered data for " + curveName,
                verifier.verify(signature));
    }

    private void testKeyRestoreForCurve(String curveName, String xHex, String yHex, String privateHex)
            throws Exception {
        // Create ECPoint from coordinates
        ECPoint w = new ECPoint(new BigInteger(xHex, 16), new BigInteger(yHex, 16));

        // Get parameters
        ECParameterSpec ecParameterSpec = getCurveParameters(curveName);

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = getKeyFactory(curveName);
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
            ECParameterSpec ecParameterSpec = getCurveParameters(curveName);

            // Generate key pair
            KeyPairGenerator keyGen = getKeyPairGenerator(curveName);
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
    public void testExplicitECDSASignatureRegistration() throws Exception {
        KeyPairGenerator keyGen = getKeyPairGenerator("secp256r1");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();
        byte[] message = "explicit ECDSA signature registration".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }

    @Test
    public void testECDSASignResetsBufferForReuse() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] previous = "previous-message".getBytes(StandardCharsets.UTF_8);
        byte[] current = "current-message".getBytes(StandardCharsets.UTF_8);
        byte[] combined = concat(previous, current);

        Signature reusedSigner = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        reusedSigner.initSign(keyPair.getPrivate());
        reusedSigner.update(previous);
        byte[] previousSignature = reusedSigner.sign();
        reusedSigner.update(current);
        byte[] currentSignature = reusedSigner.sign();

        Signature previousVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        previousVerifier.initVerify(keyPair.getPublic());
        previousVerifier.update(previous);
        assertTrue(previousVerifier.verify(previousSignature));

        Signature currentVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        currentVerifier.initVerify(keyPair.getPublic());
        currentVerifier.update(current);
        assertTrue("Reused signer should sign only the new message",
                currentVerifier.verify(currentSignature));

        Signature combinedVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        combinedVerifier.initVerify(keyPair.getPublic());
        combinedVerifier.update(combined);
        assertFalse("Reused signer must not sign previous || current",
                combinedVerifier.verify(currentSignature));
    }

    @Test
    public void testECDSAVerifyResetsBufferForReuse() throws Exception {
        KeyPair keyPair = generateP256KeyPair();
        byte[] previous = "previous-message".getBytes(StandardCharsets.UTF_8);
        byte[] current = "current-message".getBytes(StandardCharsets.UTF_8);
        byte[] combined = concat(previous, current);

        byte[] previousSignature = signP256(keyPair.getPrivate(), previous);
        byte[] currentSignature = signP256(keyPair.getPrivate(), current);
        byte[] combinedSignature = signP256(keyPair.getPrivate(), combined);

        Signature freshVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        freshVerifier.initVerify(keyPair.getPublic());
        freshVerifier.update(current);
        assertFalse(freshVerifier.verify(combinedSignature));

        Signature reusedVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
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
    public void testP256KeyGeneration() throws Exception {
        KeyPairGenerator keyGen = getKeyPairGenerator("secp256r1");
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
        ECParameterSpec ecParameterSpec = getCurveParameters("secp256r1");

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P256_Qx, 16), new BigInteger(P256_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
        KeyFactory keyFactory = getKeyFactory("secp256r1");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        // Verify only
        byte[] message = P256_MSG.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initVerify(pubKey);
        signer.update(message);
        assertNotNull("Public key should be created successfully", pubKey);
    }

    @Test
    public void testStandardEncodedP256KeyImportAndExport() throws Exception {
        Provider platformProvider = getPlatformEcProvider();
        KeyPairGenerator platformKeyGen = KeyPairGenerator.getInstance("EC", platformProvider);
        platformKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair platformKeyPair = platformKeyGen.generateKeyPair();

        KeyFactory hitlsKeyFactory = KeyFactory.getInstance("ECDSA", HiTls4jProvider.PROVIDER_NAME);
        PublicKey hitlsPublicKey = hitlsKeyFactory.generatePublic(
                new X509EncodedKeySpec(platformKeyPair.getPublic().getEncoded()));
        PrivateKey hitlsPrivateKey = hitlsKeyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(platformKeyPair.getPrivate().getEncoded()));

        assertEquals("ECDSA", hitlsPublicKey.getAlgorithm());
        assertEquals("ECDSA", hitlsPrivateKey.getAlgorithm());

        byte[] message = "standard encoded P-256 import".getBytes(StandardCharsets.UTF_8);
        byte[] signature = signP256(hitlsPrivateKey, message);

        Signature verifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(hitlsPublicKey);
        verifier.update(message);
        assertTrue(verifier.verify(signature));

        X509EncodedKeySpec exportedPublicSpec = hitlsKeyFactory.getKeySpec(hitlsPublicKey, X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec exportedPrivateSpec = hitlsKeyFactory.getKeySpec(hitlsPrivateKey, PKCS8EncodedKeySpec.class);
        assertEquals(0x30, exportedPublicSpec.getEncoded()[0] & 0xff);
        assertEquals(0x30, exportedPrivateSpec.getEncoded()[0] & 0xff);

        KeyFactory platformKeyFactory = KeyFactory.getInstance("EC", platformProvider);
        assertNotNull(platformKeyFactory.generatePublic(exportedPublicSpec));
        assertNotNull(platformKeyFactory.generatePrivate(exportedPrivateSpec));
        assertNotNull(hitlsKeyFactory.generatePublic(exportedPublicSpec));
        assertNotNull(hitlsKeyFactory.generatePrivate(exportedPrivateSpec));
    }

    @Test
    public void testPkcs8PrivateKeyRejectsRawScalarPayload() throws Exception {
        KeyFactory keyFactory = getKeyFactory("secp256r1");
        byte[] rawScalarPkcs8 = hex(
                "303a020100301306072a8648ce3d020106082a8648ce3d0301070420"
                        + "0000000000000000000000000000000000000000000000000000000000000001");

        expectInvalidKeySpec(() -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(rawScalarPkcs8)));
    }

    @Test
    public void testECPublicKeySpecRejectsInvalidPublicPoints() throws Exception {
        ECParameterSpec params = getCurveParameters("secp256r1");
        KeyFactory keyFactory = getKeyFactory("secp256r1");

        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new ECPublicKeySpec(new ECPoint(BigInteger.ONE, BigInteger.ONE), params)));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new ECPublicKeySpec(new ECPoint(BigInteger.ONE.setBit(256), BigInteger.ONE), params)));
    }

    @Test
    public void testEncodedECPublicKeyRejectsInvalidPublicPoint() throws Exception {
        ECParameterSpec params = getCurveParameters("secp256r1");
        KeyFactory keyFactory = getKeyFactory("secp256r1");
        byte[] encoded = generateP256KeyPair().getPublic().getEncoded();
        byte[] invalidPoint = ECKeyEncoding.encodePublicPoint(new ECPoint(BigInteger.ONE, BigInteger.ONE), params);
        System.arraycopy(invalidPoint, 0, encoded, encoded.length - invalidPoint.length, invalidPoint.length);

        expectInvalidKeySpec(() -> keyFactory.generatePublic(new X509EncodedKeySpec(encoded)));
    }

    @Test
    public void testECPrivateKeySpecRejectsInvalidPrivateValues() throws Exception {
        ECParameterSpec params = getCurveParameters("secp256r1");
        KeyFactory keyFactory = getKeyFactory("secp256r1");

        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new ECPrivateKeySpec(BigInteger.ZERO, params)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new ECPrivateKeySpec(BigInteger.ONE.negate(), params)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new ECPrivateKeySpec(params.getOrder(), params)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new ECPrivateKeySpec(BigInteger.ONE.setBit(256), params)));
    }

    @Test
    public void testECPrivateKeySpecAcceptsPositiveHighBitPrivateValue() throws Exception {
        ECParameterSpec params = getCurveParameters("secp256r1");
        KeyFactory keyFactory = getKeyFactory("secp256r1");
        BigInteger highBitPrivateValue = BigInteger.ONE.shiftLeft(255);

        PrivateKey privateKey = keyFactory.generatePrivate(
                new ECPrivateKeySpec(highBitPrivateValue, params));

        assertEquals(highBitPrivateValue, ((java.security.interfaces.ECPrivateKey) privateKey).getS());
        assertNotNull(privateKey.getEncoded());

        PrivateKey reparsed = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
        assertEquals(highBitPrivateValue, ((java.security.interfaces.ECPrivateKey) reparsed).getS());
    }

    @Test
    public void testStandardEncodedECImportsRejectWrongCurveFamily() throws Exception {
        KeyFactory ecdsaFactory = KeyFactory.getInstance("ECDSA", HiTls4jProvider.PROVIDER_NAME);
        KeyFactory sm2Factory = KeyFactory.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);

        KeyPair p256KeyPair = generateP256KeyPair();
        X509EncodedKeySpec p256Public = ecdsaFactory.getKeySpec(p256KeyPair.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec p256Private = ecdsaFactory.getKeySpec(p256KeyPair.getPrivate(), PKCS8EncodedKeySpec.class);
        expectInvalidKeySpec(() -> sm2Factory.generatePublic(p256Public));
        expectInvalidKeySpec(() -> sm2Factory.generatePrivate(p256Private));

        KeyPair sm2KeyPair = generateSM2KeyPair();
        X509EncodedKeySpec sm2Public = sm2Factory.getKeySpec(sm2KeyPair.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec sm2Private = sm2Factory.getKeySpec(sm2KeyPair.getPrivate(), PKCS8EncodedKeySpec.class);
        expectInvalidKeySpec(() -> ecdsaFactory.generatePublic(sm2Public));
        expectInvalidKeySpec(() -> ecdsaFactory.generatePrivate(sm2Private));
    }

    @Test
    public void testECKeyFactoryGetKeySpecRejectsWrongCurveFamily() throws Exception {
        KeyFactory ecdsaFactory = KeyFactory.getInstance("ECDSA", HiTls4jProvider.PROVIDER_NAME);
        KeyFactory sm2Factory = KeyFactory.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);

        KeyPair p256KeyPair = generateP256KeyPair();
        expectInvalidKeySpec(() -> sm2Factory.getKeySpec(p256KeyPair.getPublic(), X509EncodedKeySpec.class));
        expectInvalidKeySpec(() -> sm2Factory.getKeySpec(p256KeyPair.getPublic(), ECPublicKeySpec.class));
        expectInvalidKeySpec(() -> sm2Factory.getKeySpec(p256KeyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        expectInvalidKeySpec(() -> sm2Factory.getKeySpec(p256KeyPair.getPrivate(), ECPrivateKeySpec.class));

        KeyPair sm2KeyPair = generateSM2KeyPair();
        expectInvalidKeySpec(() -> ecdsaFactory.getKeySpec(sm2KeyPair.getPublic(), X509EncodedKeySpec.class));
        expectInvalidKeySpec(() -> ecdsaFactory.getKeySpec(sm2KeyPair.getPublic(), ECPublicKeySpec.class));
        expectInvalidKeySpec(() -> ecdsaFactory.getKeySpec(sm2KeyPair.getPrivate(), PKCS8EncodedKeySpec.class));
        expectInvalidKeySpec(() -> ecdsaFactory.getKeySpec(sm2KeyPair.getPrivate(), ECPrivateKeySpec.class));
    }

    @Test
    public void testECKeyFactoryTranslateKeyRejectsWrongCurveFamily() throws Exception {
        KeyFactory ecdsaFactory = KeyFactory.getInstance("ECDSA", HiTls4jProvider.PROVIDER_NAME);
        KeyFactory sm2Factory = KeyFactory.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);

        KeyPair p256KeyPair = generateP256KeyPair();
        expectInvalidKey(() -> sm2Factory.translateKey(p256KeyPair.getPublic()));
        expectInvalidKey(() -> sm2Factory.translateKey(p256KeyPair.getPrivate()));

        KeyPair sm2KeyPair = generateSM2KeyPair();
        expectInvalidKey(() -> ecdsaFactory.translateKey(sm2KeyPair.getPublic()));
        expectInvalidKey(() -> ecdsaFactory.translateKey(sm2KeyPair.getPrivate()));
    }

    @Test
    public void testP384WithTestVectors() throws Exception {
        // Create key specs
        ECParameterSpec ecParameterSpec = getCurveParameters("secp384r1");

        // Create public key
        ECPoint w = new ECPoint(new BigInteger(P384_Qx, 16), new BigInteger(P384_Qy, 16));
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
        KeyFactory keyFactory = getKeyFactory("secp384r1");
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
            KeyPairGenerator keyGen = getKeyPairGenerator(curve);
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
        ECParameterSpec ecParameterSpec = getCurveParameters("sm2p256v1");

        // Create key specs
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecParameterSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(new BigInteger(privateHex, 16), ecParameterSpec);

        // Generate keys
        KeyFactory keyFactory = getKeyFactory("sm2p256v1");
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
        KeyPairGenerator keyGen = getKeyPairGenerator("sm2p256v1");
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

    @Test
    public void testSM2VerifyClearsNativeUserIdWhenParameterReset() throws Exception {
        KeyPair keyPair = generateSM2KeyPair();
        byte[] message = "SM2 verifier parameter reset".getBytes(StandardCharsets.UTF_8);
        SM2ParameterSpec customSpec = new SM2ParameterSpec("CustomDomainA".getBytes(StandardCharsets.UTF_8));
        byte[] customSignature = signSM2(keyPair.getPrivate(), message, customSpec);

        Signature freshDefaultVerifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        freshDefaultVerifier.initVerify(keyPair.getPublic());
        freshDefaultVerifier.update(message);
        assertFalse("Default verifier must reject a custom-userId signature",
                freshDefaultVerifier.verify(customSignature));

        Signature reusedVerifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        reusedVerifier.setParameter(customSpec);
        reusedVerifier.initVerify(keyPair.getPublic());
        reusedVerifier.update(message);
        assertTrue(reusedVerifier.verify(customSignature));

        reusedVerifier.setParameter((AlgorithmParameterSpec) null);
        reusedVerifier.update(message);
        assertFalse("Clearing parameters must reset the native SM2 userId to default",
                reusedVerifier.verify(customSignature));
    }

    @Test
    public void testSM2SignClearsNativeUserIdWhenParameterReset() throws Exception {
        KeyPair keyPair = generateSM2KeyPair();
        byte[] message = "SM2 signer parameter reset".getBytes(StandardCharsets.UTF_8);
        SM2ParameterSpec customSpec = new SM2ParameterSpec("CustomDomainA".getBytes(StandardCharsets.UTF_8));

        Signature reusedSigner = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        reusedSigner.setParameter(customSpec);
        reusedSigner.initSign(keyPair.getPrivate());
        reusedSigner.update(message);
        byte[] customSignature = reusedSigner.sign();

        Signature customVerifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        customVerifier.setParameter(customSpec);
        customVerifier.initVerify(keyPair.getPublic());
        customVerifier.update(message);
        assertTrue(customVerifier.verify(customSignature));

        reusedSigner.setParameter((AlgorithmParameterSpec) null);
        reusedSigner.update(message);
        byte[] defaultSignature = reusedSigner.sign();

        Signature freshDefaultVerifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        freshDefaultVerifier.initVerify(keyPair.getPublic());
        freshDefaultVerifier.update(message);
        assertTrue("Clearing parameters should make the reused signer use the default SM2 userId",
                freshDefaultVerifier.verify(defaultSignature));

        Signature freshCustomVerifier = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        freshCustomVerifier.setParameter(customSpec);
        freshCustomVerifier.initVerify(keyPair.getPublic());
        freshCustomVerifier.update(message);
        assertFalse("Clearing parameters must not leave the old custom userId active",
                freshCustomVerifier.verify(defaultSignature));
    }

    @Test
    public void testSetParameterClearsPreviousUserIdCopy() throws Exception {
        ECDSASigner.SM3withSM2 signer = new ECDSASigner.SM3withSM2();

        signer.engineSetParameter(new SM2ParameterSpec("CustomDomainA".getBytes(StandardCharsets.UTF_8)));
        byte[] previousUserId = getInternalUserId(signer);

        signer.engineSetParameter(new SM2ParameterSpec("CustomDomainB".getBytes(StandardCharsets.UTF_8)));

        assertArrayEquals(new byte[previousUserId.length], previousUserId);
    }

    @Test
    public void testClearParameterClearsPreviousUserIdCopy() throws Exception {
        ECDSASigner.SM3withSM2 signer = new ECDSASigner.SM3withSM2();

        signer.engineSetParameter(new SM2ParameterSpec("CustomDomainA".getBytes(StandardCharsets.UTF_8)));
        byte[] previousUserId = getInternalUserId(signer);

        signer.engineSetParameter((AlgorithmParameterSpec) null);

        assertArrayEquals(new byte[previousUserId.length], previousUserId);
        assertNull(getInternalUserId(signer));
    }

    @Test
    public void testECDSARejectsSM2ParameterSpec() throws Exception {
        SM2ParameterSpec sm2Spec = new SM2ParameterSpec("CustomDomainA".getBytes(StandardCharsets.UTF_8));

        for (String signatureAlgorithm : new String[]{
                "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"}) {
            Signature signature = Signature.getInstance(signatureAlgorithm, HiTls4jProvider.PROVIDER_NAME);
            try {
                signature.setParameter(sm2Spec);
                fail("Expected InvalidAlgorithmParameterException for " + signatureAlgorithm);
            } catch (InvalidAlgorithmParameterException expected) {
                // Expected.
            }
        }

        ECDSASigner.SHA256withECDSA signer = new ECDSASigner.SHA256withECDSA();
        try {
            signer.engineSetParameter(sm2Spec);
            fail("Expected InvalidAlgorithmParameterException for direct ECDSA signer use");
        } catch (InvalidAlgorithmParameterException expected) {
            // Expected.
        }
    }

    @Test
    public void testECDSARequiresInitialization() throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
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
            signature.verify(new byte[64]);
            fail("Expected SignatureException before initVerify");
        } catch (SignatureException expected) {
            // Expected.
        }
    }

    @Test
    public void testECDSARejectsWrongKeyTypes() throws Exception {
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);

        try {
            signature.initSign(rsaKeyPair.getPrivate());
            fail("Expected InvalidKeyException for RSA private key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }

        try {
            signature.initVerify(rsaKeyPair.getPublic());
            fail("Expected InvalidKeyException for RSA public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
    }

    @Test
    public void testECDSAFailedInitPreservesPreviousState() throws Exception {
        KeyPair ecKeyPair = generateP256KeyPair();
        KeyPair rsaKeyPair = generateRsaKeyPair();
        byte[] message = "ECDSA state after failed init".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(ecKeyPair.getPrivate());
        signer.update(message);
        expectInvalidKey(() -> signer.initSign(rsaKeyPair.getPrivate()));
        byte[] preservedSignature = signer.sign();

        Signature freshVerifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        freshVerifier.initVerify(ecKeyPair.getPublic());
        freshVerifier.update(message);
        assertTrue("Failed initSign must leave the previous signing state usable",
                freshVerifier.verify(preservedSignature));

        byte[] signature = signP256(ecKeyPair.getPrivate(), message);
        Signature verifier = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(ecKeyPair.getPublic());
        verifier.update(message);
        expectInvalidKey(() -> verifier.initVerify(rsaKeyPair.getPublic()));
        assertTrue("Failed initVerify must leave the previous verification state usable",
                verifier.verify(signature));
    }

    @Test
    public void testSignatureRejectsCurveFamilyCrossover() throws Exception {
        KeyPair nistKeyPair = generateP256KeyPair();
        KeyPair sm2KeyPair = generateSM2KeyPair();

        expectInvalidKey(() -> Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME)
                .initSign(nistKeyPair.getPrivate()));
        expectInvalidKey(() -> Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME)
                .initVerify(nistKeyPair.getPublic()));

        for (String signatureAlgorithm : new String[]{
                "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"}) {
            expectInvalidKey(() -> Signature.getInstance(signatureAlgorithm, HiTls4jProvider.PROVIDER_NAME)
                    .initSign(sm2KeyPair.getPrivate()));
            expectInvalidKey(() -> Signature.getInstance(signatureAlgorithm, HiTls4jProvider.PROVIDER_NAME)
                    .initVerify(sm2KeyPair.getPublic()));
        }
    }

    private KeyPair generateP256KeyPair() throws Exception {
        KeyPairGenerator keyGen = getKeyPairGenerator("secp256r1");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        return keyGen.generateKeyPair();
    }

    private KeyPair generateSM2KeyPair() throws Exception {
        KeyPairGenerator keyGen = getKeyPairGenerator("sm2p256v1");
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        return keyGen.generateKeyPair();
    }

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private byte[] signP256(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    private byte[] signSM2(PrivateKey privateKey, byte[] message, SM2ParameterSpec parameterSpec) throws Exception {
        Signature signer = Signature.getInstance("SM3withSM2", HiTls4jProvider.PROVIDER_NAME);
        signer.setParameter(parameterSpec);
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    private byte[] getInternalUserId(ECDSASigner signer) throws Exception {
        Field field = ECDSASigner.class.getDeclaredField("userId");
        field.setAccessible(true);
        return (byte[]) field.get(signer);
    }

    private byte[] concat(byte[] first, byte[] second) {
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }

    private byte[] hex(String value) {
        int length = value.length();
        byte[] out = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
        }
        return out;
    }

    private KeyPairGenerator getKeyPairGenerator(String curveName) throws Exception {
        return KeyPairGenerator.getInstance(getKeyAlgorithm(curveName), HiTls4jProvider.PROVIDER_NAME);
    }

    private KeyFactory getKeyFactory(String curveName) throws Exception {
        return KeyFactory.getInstance(getKeyAlgorithm(curveName), HiTls4jProvider.PROVIDER_NAME);
    }

    private ECParameterSpec getCurveParameters(String curveName) {
        return ECNamedCurveSpec.getNamedCurve(curveName);
    }

    private Provider getPlatformEcProvider() {
        for (Provider provider : Security.getProviders()) {
            if (!HiTls4jProvider.PROVIDER_NAME.equals(provider.getName())
                    && provider.getService("KeyPairGenerator", "EC") != null
                    && provider.getService("KeyFactory", "EC") != null) {
                return provider;
            }
        }
        throw new IllegalStateException("No platform EC provider available");
    }

    private void expectInvalidKeySpec(KeySpecOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected InvalidKeySpecException");
        } catch (InvalidKeySpecException expected) {
            // Expected.
        }
    }

    private void expectInvalidKey(InvalidKeyOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected InvalidKeyException");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
    }

    private interface KeySpecOperation {
        void run() throws Exception;
    }

    private interface InvalidKeyOperation {
        void run() throws Exception;
    }

    private String getKeyAlgorithm(String curveName) {
        switch (curveName) {
            case "sm2p256v1":
                return "SM2";
            case "secp256r1":
            case "secp384r1":
            case "secp521r1":
                return "ECDSA";
            default:
                throw new IllegalArgumentException("Unsupported curve: " + curveName);
        }
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
