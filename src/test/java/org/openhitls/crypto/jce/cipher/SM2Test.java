package org.openhitls.crypto.jce.cipher;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidKeyException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class SM2Test extends BaseTest {
    private static final byte[] TEST_DATA = "Test message for SM2 encryption".getBytes();

    @Test
    public void testSm2EncryptDecrypt() throws Exception {
        // Register HITLS provider if not already registered
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        // Generate SM2 key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);
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

    @Test
    public void testSm2RejectsInvalidUsageAndInputs() throws Exception {
        if (Security.getProvider(HiTls4jProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new HiTls4jProvider());
        }

        KeyPairGenerator sm2KeyGen = KeyPairGenerator.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);
        sm2KeyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        KeyPair sm2KeyPair = sm2KeyGen.generateKeyPair();

        Cipher cipher = Cipher.getInstance("SM2", HiTls4jProvider.PROVIDER_NAME);
        try {
            cipher.doFinal(TEST_DATA);
            fail("Expected IllegalStateException before init");
        } catch (IllegalStateException expected) {
            // Expected.
        }

        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", HiTls4jProvider.PROVIDER_NAME);
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
            fail("Expected InvalidKeyException for RSA public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }

        cipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());
        byte[] ciphertext = cipher.doFinal(TEST_DATA);
        ciphertext[ciphertext.length - 1] ^= 0x01;

        cipher.init(Cipher.DECRYPT_MODE, sm2KeyPair.getPrivate());
        try {
            cipher.doFinal(ciphertext);
            fail("Expected BadPaddingException for tampered SM2 ciphertext");
        } catch (BadPaddingException expected) {
            // Expected.
        }
    }
}
