package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.LMSImpl;
import org.openhitls.crypto.jce.key.LMSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSKeyPairGenerator extends KeyPairGeneratorSpi {
    private LMSParameterSpec params = new LMSParameterSpec("CRYPT_LMS_SHA256_M32_H5", "CRYPT_LMOTS_SHA256_N32_W8");

    @Override
    public void initialize(int keysize, SecureRandom random) {
        String lmsType;
        switch (keysize) {
            case 5:
            case 10:
            case 15:
            case 20:
            case 25:
                lmsType = "CRYPT_LMS_SHA256_M32_H" + keysize;
                break;
            default:
                throw new InvalidParameterException("Unsupported LMS height: " + keysize);
        }
        try {
            initialize(new LMSParameterSpec(lmsType, "CRYPT_LMOTS_SHA256_N32_W8"), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof LMSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only LMSParameterSpec is supported");
        }
        this.params = (LMSParameterSpec) params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (LMSImpl impl = new LMSImpl(params)) {
            byte[][] keyPair = impl.generateKeyPair();
            return new KeyPair(new LMSPublicKeyImpl(params, keyPair[0]), new LMSPrivateKeyImpl(params, keyPair[1]));
        } catch (Exception e) {
            throw new ProviderException("Failed to generate LMS key pair", e);
        }
    }
}
