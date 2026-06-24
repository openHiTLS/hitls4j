package org.openhitls.crypto.jce.provider;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.InvalidAlgorithmParameterException;
import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class ECServiceRegistrationTest extends BaseTest {
    @Test
    public void testGenericECServicesAreRegisteredByHiTls4j() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        assertNotNull(provider);

        assertNotNull(provider.getService("KeyPairGenerator", "EC"));
        assertNotNull(provider.getService("KeyFactory", "EC"));
        assertNotNull(provider.getService("AlgorithmParameters", "EC"));
        assertNotNull(KeyPairGenerator.getInstance("EC", provider));
        assertNotNull(KeyFactory.getInstance("EC", provider));
        assertNotNull(AlgorithmParameters.getInstance("EC", provider));
    }

    @Test
    public void testUnsupportedGenericECServicesAreNotRegisteredByHiTls4j() {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        assertNotNull(provider);

        assertNull(provider.getService("AlgorithmParameterGenerator", "EC"));
        assertNull(provider.getService("KeyAgreement", "EC"));
        assertNull(provider.getService("Signature", "EC"));
    }

    @Test
    public void testExplicitECDSAAndSM2ServicesAreRegistered() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        assertNotNull(provider);

        assertNotNull(KeyPairGenerator.getInstance("ECDSA", provider));
        assertNotNull(KeyFactory.getInstance("ECDSA", provider));
        assertNotNull(Signature.getInstance("SHA256withECDSA", provider));

        assertNotNull(KeyPairGenerator.getInstance("SM2", provider));
        assertNotNull(KeyFactory.getInstance("SM2", provider));
        assertNotNull(Signature.getInstance("SM3withSM2", provider));
        assertNotNull(Cipher.getInstance("SM2", provider));
    }

    @Test
    public void testExplicitGeneratorsRejectOtherCurveFamily() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);

        KeyPairGenerator ecdsaGenerator = KeyPairGenerator.getInstance("ECDSA", provider);
        try {
            ecdsaGenerator.initialize(new ECGenParameterSpec("sm2p256v1"));
            fail("Expected ECDSA generator to reject SM2 curve");
        } catch (InvalidAlgorithmParameterException expected) {
            // Expected.
        }

        KeyPairGenerator sm2Generator = KeyPairGenerator.getInstance("SM2", provider);
        try {
            sm2Generator.initialize(new ECGenParameterSpec("secp256r1"));
            fail("Expected SM2 generator to reject ECDSA curve");
        } catch (InvalidAlgorithmParameterException expected) {
            // Expected.
        }
    }

    @Test
    public void testGeneratorsRejectMismatchedNamedCurveSpec() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);
        ECNamedCurveSpec forged = mismatchedP256NamedCurveSpec();

        KeyPairGenerator genericGenerator = KeyPairGenerator.getInstance("EC", provider);
        try {
            genericGenerator.initialize(forged);
            fail("Expected generic EC generator to reject mismatched named curve parameters");
        } catch (InvalidAlgorithmParameterException expected) {
            // Expected.
        }

        KeyPairGenerator ecdsaGenerator = KeyPairGenerator.getInstance("ECDSA", provider);
        try {
            ecdsaGenerator.initialize(forged);
            fail("Expected ECDSA generator to reject mismatched named curve parameters");
        } catch (InvalidAlgorithmParameterException expected) {
            // Expected.
        }
    }

    @Test
    public void testGeneratedKeysAdvertiseRegisteredKeyFactoryAlgorithm() throws Exception {
        Provider provider = Security.getProvider(HiTls4jProvider.PROVIDER_NAME);

        assertGeneratedKeyFactoryRoundTrip(provider, "EC", "secp256r1");
        assertGeneratedKeyFactoryRoundTrip(provider, "ECDSA", "secp256r1");
        assertGeneratedKeyFactoryRoundTrip(provider, "SM2", "sm2p256v1");
    }

    private void assertGeneratedKeyFactoryRoundTrip(Provider provider, String algorithm, String curveName)
            throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        keyPairGenerator.initialize(new ECGenParameterSpec(curveName));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        assertEquals(algorithm, keyPair.getPublic().getAlgorithm());
        assertEquals(algorithm, keyPair.getPrivate().getAlgorithm());
        assertEquals("X.509", keyPair.getPublic().getFormat());
        assertEquals("PKCS#8", keyPair.getPrivate().getFormat());
        assertEquals(0x30, keyPair.getPublic().getEncoded()[0] & 0xff);
        assertEquals(0x30, keyPair.getPrivate().getEncoded()[0] & 0xff);

        KeyFactory publicKeyFactory = KeyFactory.getInstance(keyPair.getPublic().getAlgorithm(), provider);
        assertNotNull(publicKeyFactory.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class));
        PublicKey reparsedPublic = publicKeyFactory.generatePublic(
                new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
        assertEquals(algorithm, reparsedPublic.getAlgorithm());

        KeyFactory privateKeyFactory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm(), provider);
        assertNotNull(privateKeyFactory.getKeySpec(keyPair.getPrivate(), ECPrivateKeySpec.class));
        PrivateKey reparsedPrivate = privateKeyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
        assertEquals(algorithm, reparsedPrivate.getAlgorithm());
    }

    private ECNamedCurveSpec mismatchedP256NamedCurveSpec() {
        ECNamedCurveSpec sm2 = ECNamedCurveSpec.getSM2Curve();
        return new ECNamedCurveSpec(
                "secp256r1",
                sm2.getCurve(),
                sm2.getGenerator(),
                sm2.getOrder(),
                BigInteger.valueOf(sm2.getCofactor()));
    }
}
