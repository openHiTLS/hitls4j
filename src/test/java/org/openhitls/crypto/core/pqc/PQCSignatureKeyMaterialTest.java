package org.openhitls.crypto.core.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.core.CryptoConstants;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.jce.spec.MLDSASignatureParameterSpec;
import org.openhitls.crypto.jce.spec.SLHDSASignatureParameterSpec;

public class PQCSignatureKeyMaterialTest extends BaseTest {
    @Test
    public void testMLDSAImplCopiesPrivateKeyInput() {
        byte[] publicKey = null;
        byte[] privateKey = null;
        MLDSASignatureParameterSpec params = new MLDSASignatureParameterSpec(false, false, false, null);
        byte[] message = "MLDSA private key copy".getBytes(StandardCharsets.UTF_8);

        try (MLDSAImpl source = new MLDSAImpl("ML-DSA-44")) {
            publicKey = source.getPublicKey();
            privateKey = source.getPrivateKey();

            try (MLDSAImpl signer = new MLDSAImpl("ML-DSA-44", CryptoConstants.HASH_ALG_SHA256, null, privateKey);
                 MLDSAImpl verifier = new MLDSAImpl("ML-DSA-44", CryptoConstants.HASH_ALG_SHA256, publicKey, null)) {
                SensitiveDataUtil.clear(privateKey);
                byte[] signature = signer.signData(message, params);

                assertTrue(verifier.verifySignature(message, signature, params));
            }
        } finally {
            SensitiveDataUtil.clear(publicKey);
            SensitiveDataUtil.clear(privateKey);
        }
    }

    @Test
    public void testSLHDSAImplCopiesPrivateKeyInput() {
        byte[] publicKey = null;
        byte[] privateKey = null;
        SLHDSASignatureParameterSpec params = new SLHDSASignatureParameterSpec(false, false, null, null);
        byte[] message = "SLHDSA private key copy".getBytes(StandardCharsets.UTF_8);

        try (SLHDSAImpl source = new SLHDSAImpl("SLH-DSA-SHA2-128s")) {
            publicKey = source.getPublicKey();
            privateKey = source.getPrivateKey();

            try (SLHDSAImpl signer = new SLHDSAImpl("SLH-DSA-SHA2-128s", CryptoConstants.HASH_ALG_SHA256, null, privateKey);
                 SLHDSAImpl verifier = new SLHDSAImpl("SLH-DSA-SHA2-128s", CryptoConstants.HASH_ALG_SHA256, publicKey, null)) {
                SensitiveDataUtil.clear(privateKey);
                byte[] signature = signer.signData(message, params);

                assertTrue(verifier.verifySignature(message, signature, params));
            }
        } finally {
            SensitiveDataUtil.clear(publicKey);
            SensitiveDataUtil.clear(privateKey);
        }
    }

    @Test
    public void testSLHDSASetKeysClearsPreviousPrivateKey() throws Exception {
        byte[] firstPrivateKey = null;
        byte[] replacementPublicKey = null;

        try (SLHDSAImpl first = new SLHDSAImpl("SLH-DSA-SHA2-128s");
             SLHDSAImpl replacement = new SLHDSAImpl("SLH-DSA-SHA2-128s")) {
            firstPrivateKey = first.getPrivateKey();
            replacementPublicKey = replacement.getPublicKey();

            try (SLHDSAImpl target = new SLHDSAImpl("SLH-DSA-SHA2-128s", CryptoConstants.HASH_ALG_SHA256, null, firstPrivateKey)) {
                byte[] previousPrivateKey = getPrivateKey(target, SLHDSAImpl.class);

                target.setKeys(replacementPublicKey, null);

                assertArrayZeroed(previousPrivateKey);
            }
        } finally {
            SensitiveDataUtil.clear(firstPrivateKey);
            SensitiveDataUtil.clear(replacementPublicKey);
        }
    }

    @Test
    public void testMLDSASignatureParameterSpecCopiesContext() {
        byte[] context = "mldsa-context".getBytes(StandardCharsets.UTF_8);
        MLDSASignatureParameterSpec params = new MLDSASignatureParameterSpec(false, false, false, context);

        context[0] ^= 0x7f;
        byte[] returned = params.getContext();
        returned[0] ^= 0x7f;

        assertArrayEquals("mldsa-context".getBytes(StandardCharsets.UTF_8), params.getContext());
    }

    @Test
    public void testSLHDSASignatureParameterSpecCopiesMutableInputs() {
        byte[] context = "slhdsa-context".getBytes(StandardCharsets.UTF_8);
        byte[] additionalRandomness = "randomness".getBytes(StandardCharsets.UTF_8);
        SLHDSASignatureParameterSpec params =
                new SLHDSASignatureParameterSpec(false, false, context, additionalRandomness);

        context[0] ^= 0x7f;
        additionalRandomness[0] ^= 0x7f;
        byte[] returnedContext = params.getContext();
        byte[] returnedRandomness = params.getAdditionalRandomness();
        returnedContext[0] ^= 0x7f;
        returnedRandomness[0] ^= 0x7f;

        assertArrayEquals("slhdsa-context".getBytes(StandardCharsets.UTF_8), params.getContext());
        assertArrayEquals("randomness".getBytes(StandardCharsets.UTF_8), params.getAdditionalRandomness());
    }

    private static byte[] getPrivateKey(Object target, Class<?> type) throws Exception {
        Field field = type.getDeclaredField("privateKey");
        field.setAccessible(true);
        return (byte[]) field.get(target);
    }

    private static void assertArrayZeroed(byte[] value) {
        assertArrayEquals(new byte[value.length], value);
    }
}
