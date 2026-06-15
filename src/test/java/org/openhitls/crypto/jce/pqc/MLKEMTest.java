package org.openhitls.crypto.jce.pqc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.junit.Test;
import org.openhitls.crypto.BaseTest;
import org.openhitls.crypto.jce.key.MLKEMCiphertextKey;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.MLKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMPrivateKeySpec;
import org.openhitls.crypto.jce.spec.MLKEMPublicKeySpec;

public class MLKEMTest extends BaseTest {
    private static final String[] SUPPORTED_PARAMETERSETS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    boolean verifyKeyLen(String parameterSet, int pubKeyLen, int privKeyLen) {
        switch (parameterSet) {
            case "ML-KEM-512":
                return pubKeyLen == 800 && privKeyLen == 1632;
            case "ML-KEM-768":
                return pubKeyLen == 1184 && privKeyLen == 2400;
            case "ML-KEM-1024":
                return pubKeyLen == 1568 && privKeyLen == 3168;
            default:
                throw new IllegalArgumentException("Unsupported ML-KEM parameter set");
        }
    }

    @Test
    public void testKeyGeneration() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
        for (String parameterSet : SUPPORTED_PARAMETERSETS) {
            MLKEMGenParameterSpec paramSpec = new MLKEMGenParameterSpec(parameterSet);
            keyGen.initialize(paramSpec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            assertNotNull(publicKey);
            assertNotNull(privateKey);

            // verify key length
            assertTrue(verifyKeyLen(parameterSet, publicKey.getEncoded().length, privateKey.getEncoded().length));

            KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            MLKEMPublicKeySpec pubSpec = keyFactory.getKeySpec(publicKey, MLKEMPublicKeySpec.class);
            MLKEMPrivateKeySpec privSpec = keyFactory.getKeySpec(privateKey, MLKEMPrivateKeySpec.class);
            assertNotNull("Public key spec should not be null for " + parameterSet, pubSpec);
            assertNotNull("Private key spec should not be null for " + parameterSet, privSpec);
        }
    }

    boolean verifyDataLen(String parameterSet, int ciphertextLen, int sharedKeyLen) {
        if (sharedKeyLen != 32) {
            return false;
        }
        switch (parameterSet) {
            case "ML-KEM-512":
                return ciphertextLen == 768;
            case "ML-KEM-768":
                return ciphertextLen == 1088;
            case "ML-KEM-1024":
                return ciphertextLen == 1568;
            default:
                throw new IllegalArgumentException("Unsupported ML-KEM parameter set");
        }
    }

    @Test
    public void testEncapsulationAndDecapsulation() throws Exception {
        for (String parameterSet : SUPPORTED_PARAMETERSETS) {
            // Set up parameters and key pair generation
            AlgorithmParameters params = AlgorithmParameters.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            params.init(new MLKEMGenParameterSpec(parameterSet));
            MLKEMParameterSpec mlkemParameterSpec = params.getParameterSpec(MLKEMParameterSpec.class);

            // Generate key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            keyGen.initialize(mlkemParameterSpec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Encapsulation side
            KeyAgreement kaSender = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            kaSender.init(keyPair.getPublic());
            byte[] ciphertext = kaSender.doPhase(null, true).getEncoded();
            byte[] senderSharedKey = kaSender.generateSecret();

            // verify ciphertext length and senderSharedKey length
            assertTrue(verifyDataLen(parameterSet, ciphertext.length, senderSharedKey.length));

            // Decapsulation side
            KeyAgreement kaReceiver = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            kaReceiver.init(keyPair.getPrivate());
            kaReceiver.doPhase(new MLKEMCiphertextKey(ciphertext), true);
            byte[] receiverSharedKey = kaReceiver.generateSecret();

            assertArrayEquals(senderSharedKey, receiverSharedKey);

            // Decapsulate with another privateKey;
            KeyPairGenerator keyGen1 = KeyPairGenerator.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            keyGen1.initialize(mlkemParameterSpec, new SecureRandom());
            KeyPair keyPair1 = keyGen1.generateKeyPair();

            KeyAgreement kaReceiver1 = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            kaReceiver1.init(keyPair1.getPrivate());
            kaReceiver1.doPhase(new MLKEMCiphertextKey(ciphertext), true);
            byte[] receiverSharedKey1 = kaReceiver1.generateSecret();

            assertFalse("Shared secrets should be different with another privateKey", Arrays.equals(senderSharedKey, receiverSharedKey1));

            // Decapsulate with modified ciphertext;
            ciphertext[0] ^= 1;
            KeyAgreement kaReceiver2 = KeyAgreement.getInstance("ML-KEM", HiTls4jProvider.PROVIDER_NAME);
            kaReceiver2.init(keyPair.getPrivate());
            kaReceiver2.doPhase(new MLKEMCiphertextKey(ciphertext), true);
            byte[] receiverSharedKey2 = kaReceiver2.generateSecret();

            assertFalse("Shared secrets should be different with modified ciphertext", Arrays.equals(senderSharedKey, receiverSharedKey2));
        }
    }
}
