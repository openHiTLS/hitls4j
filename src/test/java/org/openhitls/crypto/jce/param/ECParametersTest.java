package org.openhitls.crypto.jce.param;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public class ECParametersTest extends BaseTest {
    private static final String[][] CURVE_ENCODINGS = {
            {"secp256r1", "06082A8648CE3D030107"},
            {"secp384r1", "06052B81040022"},
            {"secp521r1", "06052B81040023"},
            {"sm2p256v1", "06082A811CCF5501822D"}
    };

    @Test
    public void testNamedCurvesEncodeToDerObjectIdentifiers() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        assertNotNull(provider);

        for (String[] curve : CURVE_ENCODINGS) {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
            params.init(new ECGenParameterSpec(curve[0]));

            byte[] expected = hex(curve[1]);
            assertArrayEquals("Unexpected default encoding for " + curve[0], expected, params.getEncoded());
            assertArrayEquals("Unexpected ASN.1 encoding for " + curve[0], expected, params.getEncoded("ASN.1"));
            assertArrayEquals("Unexpected X.509 encoding for " + curve[0], expected, params.getEncoded("X.509"));
            assertEquals(curve[0], params.getParameterSpec(ECGenParameterSpec.class).getName());
            assertNotNull(params.getParameterSpec(ECParameterSpec.class));
        }
    }

    @Test
    public void testDerObjectIdentifiersDecodeToNamedCurves() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        assertNotNull(provider);

        for (String[] curve : CURVE_ENCODINGS) {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
            params.init(hex(curve[1]));

            assertEquals(curve[0], params.getParameterSpec(ECGenParameterSpec.class).getName());
            assertNotNull(params.getParameterSpec(ECParameterSpec.class));
            assertArrayEquals(hex(curve[1]), params.getEncoded());

            AlgorithmParameters formattedParams = AlgorithmParameters.getInstance("EC", provider);
            formattedParams.init(hex(curve[1]), "ASN.1");
            assertEquals(curve[0], formattedParams.getParameterSpec(ECGenParameterSpec.class).getName());
            assertArrayEquals(hex(curve[1]), formattedParams.getEncoded("ASN.1"));
        }
    }

    @Test
    public void testAliasesEncodeAsCanonicalNamedCurveOid() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);

        params.init(new ECGenParameterSpec("prime256v1"));

        assertEquals("secp256r1", params.getParameterSpec(ECGenParameterSpec.class).getName());
        assertArrayEquals(hex("06082A8648CE3D030107"), params.getEncoded());
    }

    @Test
    public void testPlainECParameterSpecEncodesAsNamedCurveOid() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        ECParameterSpec named = ECNamedCurveSpec.getP384Curve();
        ECParameterSpec plain = new ECParameterSpec(
                named.getCurve(), named.getGenerator(), named.getOrder(), named.getCofactor());
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);

        params.init(plain);

        assertEquals("secp384r1", params.getParameterSpec(ECGenParameterSpec.class).getName());
        assertArrayEquals(hex("06052B81040022"), params.getEncoded());
    }

    @Test
    public void testMismatchedNamedCurveSpecIsRejected() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);

        try {
            params.init(mismatchedP256NamedCurveSpec());
            fail("Expected mismatched named curve parameters to be rejected");
        } catch (InvalidParameterSpecException expected) {
            // Expected.
        }
    }

    @Test
    public void testFailedECParameterSpecInitDoesNotReplaceExistingState() throws Exception {
        ExposedECParameters params = new ExposedECParameters();
        params.initialize(new ECGenParameterSpec("secp384r1"));
        ECParameterSpec originalSpec = params.getSpec();

        ECNamedCurveSpec p256 = ECNamedCurveSpec.getP256Curve();
        ECNamedCurveSpec unsupportedNamedCurve = new ECNamedCurveSpec(
                "unsupported-alias",
                p256.getCurve(),
                p256.getGenerator(),
                p256.getOrder(),
                BigInteger.valueOf(p256.getCofactor()));

        try {
            params.initialize(unsupportedNamedCurve);
            fail("Expected unsupported EC named curve to be rejected");
        } catch (InvalidParameterSpecException expected) {
            // Expected.
        }

        assertSame(originalSpec, params.getSpec());
        assertEquals("secp384r1", params.getName());
        assertArrayEquals(hex("06052B81040022"), params.getEncodedBytes());
    }

    @Test
    public void testUnsupportedEcParameterEncodingsAreRejected() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);

        try {
            params.init(hex("06032A0304"));
            fail("Expected unknown named-curve OID to be rejected");
        } catch (IOException expected) {
            // Expected.
        }

        params = AlgorithmParameters.getInstance("EC", provider);
        try {
            params.init(hex("3000"));
            fail("Expected non-OID EC parameters to be rejected");
        } catch (IOException expected) {
            // Expected.
        }

        params = AlgorithmParameters.getInstance("EC", provider);
        params.init(new ECGenParameterSpec("secp256r1"));
        try {
            params.getEncoded("RAW");
            fail("Expected unsupported EC parameter encoding format to be rejected");
        } catch (IOException expected) {
            // Expected.
        }
    }

    @Test
    public void testOverflowingDerLengthIsRejectedAsInvalidLength() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);

        try {
            params.init(hex("068480000000"));
            fail("Expected overflowing DER length to be rejected");
        } catch (IOException expected) {
            assertEquals("Invalid DER length", expected.getMessage());
        }
    }

    private static byte[] hex(String value) {
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters");
        }

        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static ECNamedCurveSpec mismatchedP256NamedCurveSpec() {
        ECNamedCurveSpec sm2 = ECNamedCurveSpec.getSM2Curve();
        return new ECNamedCurveSpec(
                "secp256r1",
                sm2.getCurve(),
                sm2.getGenerator(),
                sm2.getOrder(),
                BigInteger.valueOf(sm2.getCofactor()));
    }

    private static final class ExposedECParameters extends ECParameters {
        private void initialize(ECGenParameterSpec spec) throws InvalidParameterSpecException {
            engineInit(spec);
        }

        private void initialize(ECParameterSpec spec) throws InvalidParameterSpecException {
            engineInit(spec);
        }

        private ECParameterSpec getSpec() throws InvalidParameterSpecException {
            return engineGetParameterSpec(ECParameterSpec.class);
        }

        private String getName() throws InvalidParameterSpecException {
            return engineGetParameterSpec(ECGenParameterSpec.class).getName();
        }

        private byte[] getEncodedBytes() throws IOException {
            return engineGetEncoded();
        }
    }
}
