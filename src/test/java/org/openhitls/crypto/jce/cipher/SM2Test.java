package org.openhitls.crypto.jce.cipher;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import static org.junit.Assert.assertArrayEquals;

public class SM2Test extends BaseTest {
    private static final byte[] TEST_DATA = "Test message for SM2 encryption".getBytes();

    @Test
    public void testSm2EncryptDecrypt() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Generate SM2 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        keyGen.initialize(sm2Spec);
        KeyPair keyPair = keyGen.generateKeyPair();

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // Encrypt the test data
        byte[] ciphertext = cipher.doFinal(TEST_DATA);

        // Initialize cipher for decryption
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // Decrypt the data
        byte[] decryptedData = cipher.doFinal(ciphertext);

        // Verify the decrypted data matches the original
        assertArrayEquals("Decrypted data should match original", TEST_DATA, decryptedData);
    }
}