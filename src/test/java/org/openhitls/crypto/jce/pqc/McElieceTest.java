package org.openhitls.crypto.jce.pqc;

import org.junit.Test;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.McElieceGenParameterSpec;
import org.openhitls.crypto.jce.key.McElieceCiphertextKey;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.Security;

import static org.junit.Assert.*;

public class McElieceTest {
    static {
        Security.addProvider(new HiTls4jProvider());
    }

    // Only test 'f' variants (faster key generation) to keep test execution time reasonable.
    // The non-f variants use the same cryptographic core but with slower key generation.
    private static final String[] PARAMETER_SETS = {
        "McEliece-6688128f",
        "McEliece-6960119f",
        "McEliece-8192128f"
    };

    private static final int[][] EXPECTED_SIZES = {
        // {publicKeySize, privateKeySize, sharedKeySize}
        {1044992, 13932, 32},   // McEliece-6688128f
        {1047319, 13948, 32},   // McEliece-6960119f
        {1357824, 14120, 32}    // McEliece-8192128f
    };

    @Test
    public void testKeyGeneration() throws Exception {
        for (int i = 0; i < PARAMETER_SETS.length; i++) {
            String paramSet = PARAMETER_SETS[i];
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
            kpg.initialize(new McElieceGenParameterSpec(paramSet));
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
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
            kpg.initialize(new McElieceGenParameterSpec(paramSet));
            KeyPair keyPair = kpg.generateKeyPair();

            // Encapsulation with public key
            KeyAgreement senderAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
            senderAgreement.init(keyPair.getPublic());
            Key ciphertextKey = senderAgreement.doPhase(null, true);
            byte[] senderSharedSecret = senderAgreement.generateSecret();

            assertNotNull("Ciphertext should not be null for " + paramSet, ciphertextKey);
            assertTrue("Ciphertext key should be McElieceCiphertextKey",
                    ciphertextKey instanceof McElieceCiphertextKey);
            assertNotNull("Sender shared secret should not be null for " + paramSet, senderSharedSecret);
            assertEquals("Shared key length mismatch for " + paramSet,
                    EXPECTED_SIZES[i][2], senderSharedSecret.length);

            // Decapsulation with private key
            KeyAgreement receiverAgreement = KeyAgreement.getInstance("Classic-McEliece", HiTls4jProvider.PROVIDER_NAME);
            receiverAgreement.init(keyPair.getPrivate());
            receiverAgreement.doPhase(ciphertextKey, true);
            byte[] receiverSharedSecret = receiverAgreement.generateSecret();

            assertNotNull("Receiver shared secret should not be null for " + paramSet, receiverSharedSecret);
            assertArrayEquals("Shared secrets should match for " + paramSet,
                    senderSharedSecret, receiverSharedSecret);
        }
    }
}
