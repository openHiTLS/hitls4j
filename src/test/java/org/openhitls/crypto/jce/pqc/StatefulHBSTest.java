package org.openhitls.crypto.jce.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import org.junit.Test;
import org.openhitls.crypto.jce.interfaces.StatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.HSSParameterSpec;
import org.openhitls.crypto.jce.spec.LMSParameterSpec;
import org.openhitls.crypto.jce.spec.XMSSMTParameterSpec;
import org.openhitls.crypto.jce.spec.XMSSMTPrivateKeySpec;
import org.openhitls.crypto.jce.spec.XMSSParameterSpec;
import org.openhitls.crypto.jce.state.FileHbsStateStore;
import org.openhitls.crypto.jce.state.HbsStateRecord;
import org.openhitls.crypto.jce.state.InMemoryHbsStateStore;

public class StatefulHBSTest {
    private static final String[] XMSS_HEIGHTS = {"10", "16", "20"};
    private static final String[][] XMSS_DIGEST_SIZES = {
            {"SHA2", "192", "256", "512"},
            {"SHAKE", "256", "512"},
            {"SHAKE256", "192", "256"}
    };
    private static final String[][] XMSSMT_HEIGHT_LAYERS = {
            {"20", "2"}, {"20", "4"},
            {"40", "2"}, {"40", "4"}, {"40", "8"},
            {"60", "3"}, {"60", "6"}, {"60", "12"}
    };

    static {
        Security.addProvider(new HiTls4jProvider());
    }

    @Test
    public void testLmsHssVerificationServicesAvailableButSigningAndKeyGenerationUnavailable() throws Exception {
        assertNotNull(AlgorithmParameters.getInstance("LMS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(AlgorithmParameters.getInstance("HSS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(KeyFactory.getInstance("LMS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(KeyFactory.getInstance("HSS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(Signature.getInstance("LMS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(Signature.getInstance("SHA256withLMS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(Signature.getInstance("HSS", HiTls4jProvider.PROVIDER_NAME));
        assertNotNull(Signature.getInstance("SHA256withHSS", HiTls4jProvider.PROVIDER_NAME));
        assertKeyPairGeneratorUnavailable("LMS");
        assertKeyPairGeneratorUnavailable("HSS");
        assertSigningUnavailable("LMS");
        assertSigningUnavailable("HSS");
    }

    @Test
    public void testXmssSignVerifyAndStateUpdate() throws Exception {
        KeyPair keyPair = generate("XMSS", new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256"));
        assertSignVerifyAndStateUpdate("XMSS", keyPair);
    }

    @Test
    public void testXmssmtSignVerifyAndStateUpdate() throws Exception {
        KeyPair keyPair = generate("XMSSMT", new XMSSMTParameterSpec("CRYPT_XMSSMT_SHA2_20_2_256"));
        assertSignVerifyAndStateUpdate("XMSSMT", keyPair);
    }

    @Test
    public void testTamperedMessagesAndSignaturesAreRejected() throws Exception {
        assertTamperingRejected("XMSS",
                generate("XMSS", new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256")));
        assertTamperingRejected("XMSSMT",
                generate("XMSSMT", new XMSSMTParameterSpec("CRYPT_XMSSMT_SHA2_20_2_256")));
    }

    @Test
    public void testAlgorithmParametersRoundTripSpecs() throws Exception {
        LMSParameterSpec lms = new LMSParameterSpec("CRYPT_LMS_SHA256_M32_H5", "CRYPT_LMOTS_SHA256_N32_W8");
        AlgorithmParameters lmsParams = AlgorithmParameters.getInstance("LMS", HiTls4jProvider.PROVIDER_NAME);
        lmsParams.init(lms);
        LMSParameterSpec decodedLms = lmsParams.getParameterSpec(LMSParameterSpec.class);
        assertEquals(lms.getName(), decodedLms.getName());
        assertEquals(lms.getLmsType(), decodedLms.getLmsType());
        assertEquals(lms.getOtsType(), decodedLms.getOtsType());

        HSSParameterSpec hss = HSSParameterSpec.named("HSS_SHA256_L2_H10_H10");
        AlgorithmParameters hssParams = AlgorithmParameters.getInstance("HSS", HiTls4jProvider.PROVIDER_NAME);
        hssParams.init(hss);
        HSSParameterSpec decodedHss = hssParams.getParameterSpec(HSSParameterSpec.class);
        assertEquals(hss.getName(), decodedHss.getName());
        assertArrayEquals(hss.getLmsTypes(), decodedHss.getLmsTypes());
        assertArrayEquals(hss.getOtsTypes(), decodedHss.getOtsTypes());

        XMSSParameterSpec xmss = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        AlgorithmParameters xmssParams = AlgorithmParameters.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        xmssParams.init(xmss);
        assertEquals(xmss.getName(), xmssParams.getParameterSpec(XMSSParameterSpec.class).getName());

        XMSSMTParameterSpec xmssmt = new XMSSMTParameterSpec("CRYPT_XMSSMT_SHA2_20_2_256");
        AlgorithmParameters xmssmtParams = AlgorithmParameters.getInstance("XMSSMT", HiTls4jProvider.PROVIDER_NAME);
        xmssmtParams.init(xmssmt);
        assertEquals(xmssmt.getName(), xmssmtParams.getParameterSpec(XMSSMTParameterSpec.class).getName());
    }

    @Test
    public void testUnboundSigningRequiresExplicitUnsafeMode() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        Signature signer = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update("requires-state-store".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        try {
            signer.sign();
            fail("Expected unbound stateful HBS signing to fail");
        } catch (SignatureException expected) {
            assertTrue(expected.getMessage().contains("HbsStateStore"));
        }
    }

    @Test
    public void testSignFailureClearsBufferedInputBeforeReuse() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        AbstractStatefulHBSPrivateKey privateKey = (AbstractStatefulHBSPrivateKey) keyPair.getPrivate();

        InMemoryHbsStateStore store = new InMemoryHbsStateStore();
        HbsStateRecord initial = HbsStateRecord.create("XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), privateKey.getEncoded());
        HbsStateRecord mismatched = new HbsStateRecord(initial.getKeyId(), "XMSS", "WRONG-PARAMETER-SET",
                keyPair.getPublic().getEncoded(), privateKey.getEncoded(), -1L, 0L);
        store.save(mismatched);
        privateKey.bindStateStore(store, mismatched.getKeyId());

        Signature signer = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update("failed-message".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            signer.sign();
            fail("Expected signing with mismatched state parameters to fail");
        } catch (SignatureException expected) {
            assertTrue(expected.getMessage().contains("parameter set"));
        }

        HbsStateRecord corrected = new HbsStateRecord(initial.getKeyId(), "XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), privateKey.getEncoded(), -1L, 1L);
        store.save(corrected);

        byte[] message = "message-after-sign-failure".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        signer.update(message);
        byte[] signature = signer.sign();

        assertVerify("XMSS", keyPair, message, signature);
    }

    @Test
    public void testXmssStateStoreCommitBeforeSignatureReturn() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        AbstractStatefulHBSPrivateKey privateKey = (AbstractStatefulHBSPrivateKey) keyPair.getPrivate();

        InMemoryHbsStateStore store = new InMemoryHbsStateStore();
        HbsStateRecord initial = HbsStateRecord.create("XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), privateKey.getEncoded());
        store.save(initial);
        privateKey.bindStateStore(store, initial.getKeyId());

        byte[] message = "state-store-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = sign("XMSS", privateKey, message);

        HbsStateRecord persisted = store.load(initial.getKeyId());
        assertNotNull(signature);
        assertFalse(Arrays.equals(initial.getPrivateState(), persisted.getPrivateState()));
        assertArrayEquals(privateKey.getEncoded(), persisted.getPrivateState());
        assertVerify("XMSS", keyPair, message, signature);
    }

    @Test
    public void testStateStoresRejectRollbackRecords() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        HbsStateRecord initial = HbsStateRecord.create("XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
        HbsStateRecord advanced = initial.withPrivateState(flipFirstByte(initial.getPrivateState()), -1L);

        InMemoryHbsStateStore memoryStore = new InMemoryHbsStateStore();
        memoryStore.save(initial);
        memoryStore.save(advanced);
        assertRejectsRollback(memoryStore, initial);

        Path dir = Files.createTempDirectory("hitls4j-hbs-state");
        FileHbsStateStore fileStore = new FileHbsStateStore(dir);
        fileStore.save(initial);
        fileStore.save(advanced);
        assertRejectsRollback(fileStore, initial);
    }

    @Test
    public void testFileStateStoreRejectsMismatchedLoadedKeyId() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        HbsStateRecord initial = HbsStateRecord.create("XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
        HbsStateRecord mismatched = new HbsStateRecord(repeat('f', 64), "XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(), -1L, 0L);

        Path dir = Files.createTempDirectory("hitls4j-hbs-state-mismatch");
        FileHbsStateStore fileStore = new FileHbsStateStore(dir);
        fileStore.save(initial);
        fileStore.save(mismatched);
        Files.move(dir.resolve(mismatched.getKeyId() + ".state"), dir.resolve(initial.getKeyId() + ".state"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        try {
            fileStore.load(initial.getKeyId());
            fail("Expected mismatched state keyId to be rejected");
        } catch (GeneralSecurityException expected) {
            assertTrue(expected.getMessage().contains("keyId"));
        }
    }

    @Test
    public void testFileStateStoreSupportsHmacIntegrityKey() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        HbsStateRecord initial = HbsStateRecord.create("XMSS", params.getName(),
                keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());

        Path dir = Files.createTempDirectory("hitls4j-hbs-state-hmac");
        byte[] integrityKey = "hitls4j-state-integrity-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        FileHbsStateStore fileStore = new FileHbsStateStore(dir, integrityKey);
        fileStore.save(initial);
        assertEquals(initial.getKeyId(), fileStore.load(initial.getKeyId()).getKeyId());

        byte[] wrongIntegrityKey = "wrong-hitls4j-state-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        try {
            new FileHbsStateStore(dir, wrongIntegrityKey).load(initial.getKeyId());
            fail("Expected wrong HMAC integrity key to be rejected");
        } catch (GeneralSecurityException expected) {
            assertTrue(expected.getMessage().contains("authentication tag"));
        }
    }

    @Test
    public void testSegmentedUpdatesProduceValidSignature() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        byte[] message = "segmented-stateful-hbs-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message, 0, 9);
        signer.update(message, 9, message.length - 9);
        byte[] signature = signer.sign();

        assertVerify("XMSS", keyPair, message, signature);
    }

    @Test
    public void testVerifyRejectsNullSignature() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        byte[] validMessage = "message-after-null-signature".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] validSignature = sign("XMSS", keyPair.getPrivate(), validMessage);

        Signature verifier = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update("null-signature".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        try {
            verifier.verify(null);
            fail("Expected null signature to be rejected");
        } catch (SignatureException expected) {
            assertTrue(expected.getMessage().contains("Signature cannot be null"));
        }

        verifier.update(validMessage);
        assertTrue(verifier.verify(validSignature));
    }

    @Test
    public void testSignatureObjectsResetBufferedInputForReuse() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        byte[] previous = "previous-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] current = "current-message".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] combined = concat(previous, current);

        Signature reusedSigner = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        reusedSigner.initSign(keyPair.getPrivate());
        reusedSigner.update(previous);
        byte[] previousSignature = reusedSigner.sign();
        reusedSigner.update(current);
        byte[] currentSignature = reusedSigner.sign();

        assertTrue(verify("XMSS", keyPair.getPublic(), previous, previousSignature));
        assertTrue("Reused signer should sign only the new message",
                verify("XMSS", keyPair.getPublic(), current, currentSignature));
        assertFalse("Reused signer must not sign previous || current",
                verify("XMSS", keyPair.getPublic(), combined, currentSignature));

        byte[] combinedSignature = sign("XMSS", keyPair.getPrivate(), combined);

        Signature reusedVerifier = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
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
    public void testFailedInitPreservesPreviousState() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        KeyPair rsaKeyPair = generateRsaKeyPair();
        byte[] message = "stateful-hbs-after-failed-init".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        try {
            signer.initSign(rsaKeyPair.getPrivate());
            fail("Expected InvalidKeyException for RSA private key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        byte[] preservedSignature = signer.sign();
        assertVerify("XMSS", keyPair, message, preservedSignature);

        byte[] signature = sign("XMSS", keyPair.getPrivate(), message);
        Signature verifier = Signature.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        try {
            verifier.initVerify(rsaKeyPair.getPublic());
            fail("Expected InvalidKeyException for RSA public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
        assertTrue("Failed initVerify must leave the previous verification state usable",
                verifier.verify(signature));
    }

    @Test
    public void testKeyFactoryRejectsMismatchedStatefulKeySpecType() throws Exception {
        XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");
        KeyPair keyPair = generate("XMSS", params);
        KeyFactory keyFactory = KeyFactory.getInstance("XMSS", HiTls4jProvider.PROVIDER_NAME);

        try {
            keyFactory.getKeySpec(keyPair.getPrivate(), XMSSMTPrivateKeySpec.class);
            fail("Expected mismatched stateful HBS key spec type to be rejected");
        } catch (java.security.spec.InvalidKeySpecException expected) {
            assertTrue(expected.getMessage().contains("does not match"));
        }
    }

    @Test
    public void testParameterSetValidationCoverage() {
        int lmsCombinations = 0;
        for (String height : new String[]{"5", "10", "15", "20", "25"}) {
            for (String w : new String[]{"1", "2", "4", "8"}) {
                new LMSParameterSpec("LMS_SHA256_M32_H" + height, "LMOTS_SHA256_N32_W" + w);
                lmsCombinations++;
            }
        }
        assertEquals(20, lmsCombinations);

        assertNotNull(HSSParameterSpec.named("HSS_SHA256_L2_H10_H10"));
        assertNotNull(HSSParameterSpec.named("HSS_SHA256_L2_H15_H15"));
        assertNotNull(HSSParameterSpec.named("HSS_SHA256_L2_H20_H20"));
        assertNotNull(HSSParameterSpec.named("HSS_SHA256_L3_H10_H10_H10"));

        int xmssCombinations = 0;
        for (String height : XMSS_HEIGHTS) {
            for (String[] digestSizes : XMSS_DIGEST_SIZES) {
                for (int i = 1; i < digestSizes.length; i++) {
                    new XMSSParameterSpec("CRYPT_XMSS_" + digestSizes[0] + "_" + height + "_" + digestSizes[i]);
                    xmssCombinations++;
                }
            }
        }
        assertEquals(21, xmssCombinations);

        int xmssmtCombinations = 0;
        for (String[] heightLayers : XMSSMT_HEIGHT_LAYERS) {
            for (String[] digestSizes : XMSS_DIGEST_SIZES) {
                for (int i = 1; i < digestSizes.length; i++) {
                    new XMSSMTParameterSpec("CRYPT_XMSSMT_" + digestSizes[0] + "_" + heightLayers[0]
                            + "_" + heightLayers[1] + "_" + digestSizes[i]);
                    xmssmtCombinations++;
                }
            }
        }
        assertEquals(56, xmssmtCombinations);

        assertInvalidXmssParameter("CRYPT_XMSS_SHAKE_10_192");
        assertInvalidXmssParameter("CRYPT_XMSS_SHAKE256_10_512");
        assertInvalidXmssmtParameter("CRYPT_XMSSMT_SHA2_20_3_256");
        assertInvalidXmssmtParameter("CRYPT_XMSSMT_SHAKE_20_2_192");
        assertInvalidXmssmtParameter("CRYPT_XMSSMT_SHAKE256_20_2_512");
    }

    private static KeyPair generate(String algorithm, java.security.spec.AlgorithmParameterSpec params) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        generator.initialize(params);
        return generator.generateKeyPair();
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static void assertKeyPairGeneratorUnavailable(String algorithm) throws Exception {
        try {
            KeyPairGenerator.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
            fail("Expected " + algorithm + " key generation to be unavailable");
        } catch (java.security.NoSuchAlgorithmException expected) {
            // Expected.
        }
    }

    private static void assertSigningUnavailable(String algorithm) throws Exception {
        Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        try {
            signer.initSign(generateRsaKeyPair().getPrivate());
            fail("Expected " + algorithm + " signing to be unavailable");
        } catch (InvalidKeyException expected) {
            assertTrue(expected.getMessage().contains("signing is not supported"));
        }
    }

    private static void assertSignVerifyAndStateUpdate(String algorithm, KeyPair keyPair) throws Exception {
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        byte[] before = keyPair.getPrivate().getEncoded();
        byte[] message = ("message-" + algorithm).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = sign(algorithm, keyPair.getPrivate(), message);
        assertNotNull(signature);
        assertFalse(Arrays.equals(before, keyPair.getPrivate().getEncoded()));
        assertVerify(algorithm, keyPair, message, signature);
    }

    private static byte[] sign(String algorithm, java.security.PrivateKey privateKey, byte[] message) throws Exception {
        Signature signer = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        signer.initSign(privateKey);
        signer.update(message);
        return signer.sign();
    }

    private static void assertTamperingRejected(String algorithm, KeyPair keyPair) throws Exception {
        enableUnsafeInMemorySigning(keyPair.getPrivate());
        byte[] message = ("tamper-message-" + algorithm).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] signature = sign(algorithm, keyPair.getPrivate(), message);

        byte[] modifiedMessage = message.clone();
        modifiedMessage[0] ^= 1;
        assertFalse(verify(algorithm, keyPair.getPublic(), modifiedMessage, signature));

        byte[] modifiedSignature = flipFirstByte(signature);
        assertFalse(verify(algorithm, keyPair.getPublic(), message, modifiedSignature));
    }

    private static boolean verify(String algorithm, java.security.PublicKey publicKey, byte[] message, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private static void enableUnsafeInMemorySigning(PrivateKey privateKey) {
        ((StatefulHBSPrivateKey) privateKey).enableUnsafeInMemorySigning();
    }

    private static void assertVerify(String algorithm, KeyPair keyPair, byte[] message, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance(algorithm, HiTls4jProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        assertTrue(verifier.verify(signature));
    }

    private static byte[] flipFirstByte(byte[] data) {
        byte[] updated = data.clone();
        updated[0] ^= 1;
        return updated;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] combined = new byte[first.length + second.length];
        System.arraycopy(first, 0, combined, 0, first.length);
        System.arraycopy(second, 0, combined, first.length, second.length);
        return combined;
    }

    private static String repeat(char value, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, value);
        return new String(chars);
    }

    private static void assertRejectsRollback(org.openhitls.crypto.jce.state.HbsStateStore store,
                                              HbsStateRecord staleRecord) throws Exception {
        try {
            store.save(staleRecord);
            fail("Expected stale HBS state to be rejected");
        } catch (GeneralSecurityException expected) {
            // expected
        }
    }

    private static void assertInvalidXmssParameter(String name) {
        try {
            new XMSSParameterSpec(name);
            fail("Expected invalid XMSS parameter set: " + name);
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

    private static void assertInvalidXmssmtParameter(String name) {
        try {
            new XMSSMTParameterSpec(name);
            fail("Expected invalid XMSSMT parameter set: " + name);
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }

}
