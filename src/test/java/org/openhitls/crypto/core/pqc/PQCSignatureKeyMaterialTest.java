package org.openhitls.crypto.core.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
        SLHDSASignatureParameterSpec params = new SLHDSASignatureParameterSpec(false, false, null);
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
    public void testSLHDSASetKeysRejectsMismatchedPublicKeyReplacement() {
        byte[] firstPrivateKey = null;
        byte[] replacementPublicKey = null;

        try (SLHDSAImpl first = new SLHDSAImpl("SLH-DSA-SHA2-128s");
             SLHDSAImpl replacement = new SLHDSAImpl("SLH-DSA-SHA2-128s")) {
            firstPrivateKey = first.getPrivateKey();
            replacementPublicKey = replacement.getPublicKey();

            try (SLHDSAImpl target = new SLHDSAImpl("SLH-DSA-SHA2-128s", CryptoConstants.HASH_ALG_SHA256, null, firstPrivateKey)) {
                byte[] message = "unchanged SLHDSA context".getBytes(StandardCharsets.UTF_8);
                SLHDSASignatureParameterSpec params =
                        new SLHDSASignatureParameterSpec(false, false, null);

                try {
                    target.setKeys(replacementPublicKey, null);
                    fail("Expected mismatched public-key replacement to fail");
                } catch (IllegalStateException expected) {
                    assertTrue(expected.getMessage().contains("Failed to set SLHDSA public key"));
                }

                assertArrayEquals(firstPrivateKey, target.getPrivateKey());
                assertTrue(first.verifySignature(message, target.signData(message, params), params));
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
    public void testSLHDSASignatureParameterSpecCopiesContext() {
        byte[] context = "slhdsa-context".getBytes(StandardCharsets.UTF_8);
        SLHDSASignatureParameterSpec params =
                new SLHDSASignatureParameterSpec(false, false, context);

        context[0] ^= 0x7f;
        byte[] returnedContext = params.getContext();
        returnedContext[0] ^= 0x7f;

        assertArrayEquals("slhdsa-context".getBytes(StandardCharsets.UTF_8), params.getContext());
    }
}
