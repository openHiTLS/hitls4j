package org.openhitls.crypto.jce.pqc;

import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.FrodoKEMGenParameterSpec;
import org.openhitls.crypto.jce.key.FrodoKEMCiphertextKey;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;

public class FrodoKEMTest {
    static {
        Security.addProvider(new HiTls4jProvider());
    }

    private static final String[] PARAMETER_SETS = {
        "FrodoKEM-640-SHAKE",
        "FrodoKEM-640-AES",
        "FrodoKEM-976-SHAKE",
        "FrodoKEM-976-AES",
        "FrodoKEM-1344-SHAKE",
        "FrodoKEM-1344-AES"
    };

    private static final int[][] EXPECTED_SIZES = {
        // {publicKeySize, privateKeySize, sharedKeySize}
        {9616, 19888, 16},     // FrodoKEM-640-SHAKE
        {9616, 19888, 16},     // FrodoKEM-640-AES
        {15632, 31296, 24},    // FrodoKEM-976-SHAKE
        {15632, 31296, 24},    // FrodoKEM-976-AES
        {21520, 43088, 32},    // FrodoKEM-1344-SHAKE
        {21520, 43088, 32}     // FrodoKEM-1344-AES
    };

    @Test
    public void testKeyGeneration() throws Exception {
        for (int i = 0; i < PARAMETER_SETS.length; i++) {
            String paramSet = PARAMETER_SETS[i];
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
            kpg.initialize(new FrodoKEMGenParameterSpec(paramSet));
            KeyPair keyPair = kpg.generateKeyPair();

            assertNotNull("Public key should not be null for " + paramSet, keyPair.getPublic());
            assertNotNull("Private key should not be null for " + paramSet, keyPair.getPrivate());
            assertEquals("Public key length mismatch for " + paramSet,
                    EXPECTED_SIZES[i][0], keyPair.getPublic().getEncoded().length);
            assertEquals("Private key length mismatch for " + paramSet,
                    EXPECTED_SIZES[i][1], keyPair.getPrivate().getEncoded().length);
        }
    }

    @Test
    public void testEncapsulateDecapsulate() throws Exception {
        for (int i = 0; i < PARAMETER_SETS.length; i++) {
            String paramSet = PARAMETER_SETS[i];
            // Generate key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
            kpg.initialize(new FrodoKEMGenParameterSpec(paramSet));
            KeyPair keyPair = kpg.generateKeyPair();

            // Encapsulation with public key
            KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
            senderAgreement.init(keyPair.getPublic());
            Key ciphertextKey = senderAgreement.doPhase(null, true);
            byte[] senderSharedSecret = senderAgreement.generateSecret();

            assertNotNull("Ciphertext should not be null for " + paramSet, ciphertextKey);
            assertTrue("Ciphertext key should be FrodoKEMCiphertextKey",
                    ciphertextKey instanceof FrodoKEMCiphertextKey);
            assertNotNull("Sender shared secret should not be null for " + paramSet, senderSharedSecret);
            assertEquals("Shared key length mismatch for " + paramSet,
                    EXPECTED_SIZES[i][2], senderSharedSecret.length);

            // Decapsulation with private key
            KeyAgreement receiverAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
            receiverAgreement.init(keyPair.getPrivate());
            receiverAgreement.doPhase(ciphertextKey, true);
            byte[] receiverSharedSecret = receiverAgreement.generateSecret();

            assertNotNull("Receiver shared secret should not be null for " + paramSet, receiverSharedSecret);
            assertArrayEquals("Shared secrets should match for " + paramSet,
                    senderSharedSecret, receiverSharedSecret);
        }
    }

    @Test
    public void testRejectsWrongPrivateKeyAndModifiedCiphertext() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        kpg.initialize(new FrodoKEMGenParameterSpec("FrodoKEM-640-SHAKE"));
        KeyPair keyPair = kpg.generateKeyPair();

        KeyAgreement senderAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        senderAgreement.init(keyPair.getPublic());
        Key ciphertextKey = senderAgreement.doPhase(null, true);
        byte[] senderSharedSecret = senderAgreement.generateSecret();

        KeyPair wrongKeyPair = kpg.generateKeyPair();
        KeyAgreement wrongReceiver = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        wrongReceiver.init(wrongKeyPair.getPrivate());
        wrongReceiver.doPhase(ciphertextKey, true);
        assertFalse("Shared secret should differ with another private key",
                Arrays.equals(senderSharedSecret, wrongReceiver.generateSecret()));

        byte[] modifiedCiphertext = ciphertextKey.getEncoded();
        modifiedCiphertext[0] ^= 0x01;
        KeyAgreement modifiedReceiver = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        modifiedReceiver.init(keyPair.getPrivate());
        modifiedReceiver.doPhase(new FrodoKEMCiphertextKey(modifiedCiphertext), true);
        assertFalse("Shared secret should differ with modified ciphertext",
                Arrays.equals(senderSharedSecret, modifiedReceiver.generateSecret()));
    }

    @Test
    public void testInvalidKeyAgreementUsage() throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        try {
            keyAgreement.doPhase(null, true);
            fail("Expected IllegalStateException before init");
        } catch (IllegalStateException expected) {
            // Expected.
        }

        try {
            keyAgreement.init(new SecretKeySpec(new byte[16], "AES"));
            fail("Expected InvalidKeyException for non-FrodoKEM key");
        } catch (java.security.InvalidKeyException expected) {
            // Expected.
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FrodoKEM", HiTls4jProvider.PROVIDER_NAME);
        kpg.initialize(new FrodoKEMGenParameterSpec("FrodoKEM-640-SHAKE"));
        KeyPair keyPair = kpg.generateKeyPair();

        keyAgreement.init(keyPair.getPublic());
        try {
            keyAgreement.generateSecret();
            fail("Expected IllegalStateException before encapsulation phase");
        } catch (IllegalStateException expected) {
            // Expected.
        }

        try {
            keyAgreement.doPhase(null, false);
            fail("Expected IllegalStateException for non-final FrodoKEM phase");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }
}
