package org.openhitls.crypto.jce.key;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;
import org.openhitls.crypto.jce.util.ECKeyEncoding;

public class ECKeyEncodingFailureTest {
    private static final ECParameterSpec P256 = ECNamedCurveSpec.getP256Curve();

    @Test
    public void testPrivateKeyWithoutParamsReturnsNullEncoding() {
        ECPrivateKey key = new ECPrivateKey(new byte[] { 1 });

        assertNull(key.getFormat());
        assertNull(key.getEncoded());
    }

    @Test
    public void testPublicKeyWithoutParamsReturnsNullEncoding() {
        ECPublicKey key = new ECPublicKey(new byte[] { 4, 1, 2 });

        assertNull(key.getFormat());
        assertNull(key.getEncoded());
    }

    @Test
    public void testMalformedPrivateKeyStateThrowsDuringEncoding() {
        byte[] oversizedPrivateValue = new byte[33];
        oversizedPrivateValue[0] = 1;
        ECPrivateKey key = new ECPrivateKey(oversizedPrivateValue, P256);

        try {
            key.getEncoded();
            fail("Expected EC private key encoding failure");
        } catch (IllegalStateException expected) {
            assertEquals("Failed to encode EC private key", expected.getMessage());
            assertTrue(expected.getCause().getMessage().contains("less than the curve order"));
        }
    }

    @Test
    public void testPrivateValueEncodingRejectsInvalidScalars() {
        expectInvalidPrivateValue(BigInteger.ZERO, "positive");
        expectInvalidPrivateValue(BigInteger.ONE.negate(), "positive");
        expectInvalidPrivateValue(P256.getOrder(), "less than the curve order");
        expectInvalidPrivateValue(P256.getOrder().add(BigInteger.ONE), "less than the curve order");
    }

    @Test
    public void testMalformedPublicKeyStateThrowsDuringEncoding() {
        ECPublicKey key = new ECPublicKey(new byte[] { 0 }, P256);

        try {
            key.getEncoded();
            fail("Expected EC public key encoding failure");
        } catch (IllegalStateException expected) {
            assertEquals("Failed to encode EC public key", expected.getMessage());
            assertTrue(expected.getCause().getMessage().contains("Invalid public key encoding"));
        }
    }

    @Test
    public void testBinaryFieldParamsFailAsInvalidKeySpec() {
        ECParameterSpec params = new ECParameterSpec(
                new EllipticCurve(new ECFieldF2m(5), BigInteger.ONE, BigInteger.ONE),
                new ECPoint(BigInteger.ONE, BigInteger.ONE),
                BigInteger.valueOf(2),
                1);

        try {
            ECKeyEncoding.getCurveName(params);
            fail("Expected InvalidKeySpecException");
        } catch (InvalidKeySpecException expected) {
            assertTrue(expected.getMessage().contains("Only prime-field EC curves are supported"));
            assertTrue(expected.getCause() instanceof IllegalArgumentException);
        }
    }

    private static void expectInvalidPrivateValue(BigInteger value, String expectedMessage) {
        try {
            ECKeyEncoding.encodePrivateValue(value, P256);
            fail("Expected invalid EC private value");
        } catch (InvalidKeySpecException expected) {
            assertTrue(expected.getMessage().contains(expectedMessage));
        }
    }
}
