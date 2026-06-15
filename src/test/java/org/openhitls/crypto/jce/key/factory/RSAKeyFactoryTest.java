package org.openhitls.crypto.jce.key.factory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.Key;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;
import org.openhitls.crypto.jce.key.RSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.RSAPublicKeyImpl;

public class RSAKeyFactoryTest {
    private static final BigInteger MODULUS = BigInteger.valueOf(3233);
    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final BigInteger PRIVATE_EXPONENT = BigInteger.valueOf(2753);
    private static final BigInteger PRIME_P = BigInteger.valueOf(61);
    private static final BigInteger PRIME_Q = BigInteger.valueOf(53);
    private static final BigInteger PRIME_EXPONENT_P = BigInteger.valueOf(53);
    private static final BigInteger PRIME_EXPONENT_Q = BigInteger.valueOf(49);
    private static final BigInteger CRT_COEFFICIENT = BigInteger.valueOf(38);

    private final ExposedRSAKeyFactory keyFactory = new ExposedRSAKeyFactory();

    @Test
    public void testGeneratePublicAcceptsValidPublicKeySpec() throws Exception {
        assertNotNull(keyFactory.generatePublic(
                new RSAPublicKeySpec(MODULUS, BigInteger.valueOf(17))));
    }

    @Test
    public void testGeneratePublicRejectsNullAndNegativePublicKeySpecs() throws Exception {
        expectInvalidKeySpec(() -> keyFactory.generatePublic(null));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new RSAPublicKeySpec(null, PUBLIC_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new RSAPublicKeySpec(MODULUS, null)));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new RSAPublicKeySpec(BigInteger.ZERO, PUBLIC_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new RSAPublicKeySpec(BigInteger.valueOf(-3233), PUBLIC_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePublic(
                new RSAPublicKeySpec(MODULUS, BigInteger.valueOf(-65537))));
    }

    @Test
    public void testGeneratePublicDefersRsaSemanticValidation() throws Exception {
        assertNotNull(keyFactory.generatePublic(
                new RSAPublicKeySpec(BigInteger.ONE, PUBLIC_EXPONENT)));
        assertNotNull(keyFactory.generatePublic(
                new RSAPublicKeySpec(MODULUS, BigInteger.ONE)));
        assertNotNull(keyFactory.generatePublic(
                new RSAPublicKeySpec(MODULUS, BigInteger.valueOf(2))));
    }

    @Test
    public void testGetPublicX509KeySpecWrapsEncodingFailure() throws Exception {
        expectInvalidKeySpec(() -> keyFactory.getKeySpec(new UnencodableRSAPublicKey(), X509EncodedKeySpec.class));
    }

    @Test
    public void testGeneratePrivateAcceptsValidPrivateKeySpec() throws Exception {
        assertNotNull(keyFactory.generatePrivate(
                new RSAPrivateKeySpec(MODULUS, PRIVATE_EXPONENT)));
    }

    @Test
    public void testGeneratePrivateRejectsNullAndNegativePrivateKeySpecs() throws Exception {
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(null));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(null, PRIVATE_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(MODULUS, null)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(BigInteger.ZERO, PRIVATE_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(MODULUS, BigInteger.ZERO)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(BigInteger.valueOf(-3233), PRIVATE_EXPONENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(
                new RSAPrivateKeySpec(MODULUS, BigInteger.valueOf(-2753))));
    }

    @Test
    public void testGeneratePrivateDefersRsaSemanticValidation() throws Exception {
        assertNotNull(keyFactory.generatePrivate(
                new RSAPrivateKeySpec(BigInteger.ONE, PRIVATE_EXPONENT)));
    }

    @Test
    public void testGeneratePrivateAcceptsValidPrivateCrtKeySpec() throws Exception {
        assertNotNull(keyFactory.generatePrivate(validCrtSpec(PUBLIC_EXPONENT, PRIME_P, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT)));
    }

    @Test
    public void testGeneratePrivateRejectsNullAndNegativePrivateCrtKeySpecs() throws Exception {
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(validCrtSpec(
                PUBLIC_EXPONENT, null, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(validCrtSpec(
                PUBLIC_EXPONENT, BigInteger.ZERO, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT)));
        expectInvalidKeySpec(() -> keyFactory.generatePrivate(validCrtSpec(
                PUBLIC_EXPONENT, PRIME_P, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, BigInteger.valueOf(-38))));
    }

    @Test
    public void testGeneratePrivateCrtDefersRsaSemanticValidation() throws Exception {
        assertNotNull(keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(
                BigInteger.ONE, PUBLIC_EXPONENT, PRIVATE_EXPONENT, PRIME_P, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT)));
        assertNotNull(keyFactory.generatePrivate(validCrtSpec(
                BigInteger.valueOf(2), PRIME_P, PRIME_Q,
                PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT)));
    }

    @Test
    public void testDirectRsaKeyEncodingRejectsNegativeComponents() {
        expectEncodingRejected(() -> new RSAPublicKeyImpl(
                BigInteger.valueOf(-3233), PUBLIC_EXPONENT).getEncoded());
        expectEncodingRejected(() -> new RSAPublicKeyImpl(
                MODULUS, BigInteger.valueOf(-65537)).getEncoded());
        expectEncodingRejected(() -> new RSAPrivateKeyImpl(
                BigInteger.valueOf(-3233), PRIVATE_EXPONENT, PUBLIC_EXPONENT).getEncoded());
        expectEncodingRejected(() -> new RSAPrivateKeyImpl(
                MODULUS, BigInteger.valueOf(-2753), PUBLIC_EXPONENT).getEncoded());
    }

    @Test
    public void testTranslatePrivateKeyPreservesKnownPublicExponent() throws Exception {
        RSAPrivateKeyImpl privateKey = new RSAPrivateKeyImpl(MODULUS, PRIVATE_EXPONENT, BigInteger.valueOf(17));

        Key translated = keyFactory.translateKey(privateKey);

        assertEquals(BigInteger.valueOf(17), ((RSAPrivateKeyImpl) translated).getPublicExponent());
    }

    @Test
    public void testTranslatePrivateKeyPreservesUnknownPublicExponent() throws Exception {
        RSAPrivateKeyImpl privateKey = new RSAPrivateKeyImpl(MODULUS, PRIVATE_EXPONENT);

        Key translated = keyFactory.translateKey(privateKey);

        assertNull(((RSAPrivateKeyImpl) translated).getPublicExponent());
    }

    @Test
    public void testRsaByteArrayConstructorsHandleLeadingZeros() {
        RSAPrivateKeyImpl privateKey = new RSAPrivateKeyImpl(
                new byte[] {0}, new byte[] {0, 0x0c, (byte) 0xa1});
        RSAPublicKeyImpl publicKey = new RSAPublicKeyImpl(
                new byte[] {0, 0x0c, (byte) 0xa1}, PUBLIC_EXPONENT);

        assertEquals(BigInteger.ZERO, privateKey.getPrivateExponent());
        assertEquals(MODULUS, privateKey.getModulus());
        assertEquals(MODULUS, publicKey.getModulus());
    }

    @Test
    public void testRsaByteArrayConstructorsRejectEmptyRequiredComponents() {
        expectIllegalArgument(() -> new RSAPrivateKeyImpl(new byte[0], new byte[] {1}));
        expectIllegalArgument(() -> new RSAPrivateKeyImpl(new byte[] {1}, new byte[0]));
        expectIllegalArgument(() -> new RSAPublicKeyImpl(new byte[0], PUBLIC_EXPONENT));
    }

    @Test
    public void testRsaByteArrayConstructorsRejectNullRequiredComponents() {
        expectIllegalArgument(() -> new RSAPrivateKeyImpl(null, new byte[] {1}));
        expectIllegalArgument(() -> new RSAPrivateKeyImpl(new byte[] {1}, null));
        expectIllegalArgument(() -> new RSAPublicKeyImpl((byte[]) null, PUBLIC_EXPONENT));
    }

    private static RSAPrivateCrtKeySpec validCrtSpec(BigInteger publicExponent, BigInteger primeP,
            BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ,
            BigInteger crtCoefficient) {
        return new RSAPrivateCrtKeySpec(MODULUS, publicExponent, PRIVATE_EXPONENT,
                primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
    }

    private static void expectInvalidKeySpec(KeyFactoryOperation operation) throws Exception {
        try {
            operation.run();
            fail("Expected InvalidKeySpecException");
        } catch (InvalidKeySpecException expected) {
            // Expected.
        }
    }

    private static void expectIllegalArgument(KeyFactoryOperation operation) {
        try {
            operation.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        } catch (Exception e) {
            throw new AssertionError("Expected IllegalArgumentException", e);
        }
    }

    private static void expectEncodingRejected(KeyFactoryOperation operation) {
        try {
            operation.run();
            fail("Expected RSA encoding to reject invalid component");
        } catch (IllegalStateException expected) {
            if (!(expected.getCause() instanceof IllegalArgumentException)) {
                throw new AssertionError("Expected IllegalArgumentException cause", expected);
            }
        } catch (Exception e) {
            throw new AssertionError("Expected IllegalStateException", e);
        }
    }

    private interface KeyFactoryOperation {
        void run() throws Exception;
    }

    private static class ExposedRSAKeyFactory extends RSAKeyFactory {
        PublicKey generatePublic(KeySpec keySpec) throws InvalidKeySpecException {
            return engineGeneratePublic(keySpec);
        }

        PrivateKey generatePrivate(KeySpec keySpec) throws InvalidKeySpecException {
            return engineGeneratePrivate(keySpec);
        }

        Key translateKey(Key key) throws InvalidKeyException {
            return engineTranslateKey(key);
        }

        <T extends KeySpec> T getKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
            return engineGetKeySpec(key, keySpec);
        }
    }

    private static class UnencodableRSAPublicKey implements java.security.interfaces.RSAPublicKey {
        private static final long serialVersionUID = 1L;

        @Override
        public BigInteger getModulus() {
            return MODULUS;
        }

        @Override
        public BigInteger getPublicExponent() {
            return PUBLIC_EXPONENT;
        }

        @Override
        public String getAlgorithm() {
            return "RSA";
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            throw new IllegalStateException("Cannot encode RSA public key");
        }
    }
}
