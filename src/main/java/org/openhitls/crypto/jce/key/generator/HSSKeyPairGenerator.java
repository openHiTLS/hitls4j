package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.HSSImpl;
import org.openhitls.crypto.jce.key.HSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.HSSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSKeyPairGenerator extends KeyPairGeneratorSpi {
    private HSSParameterSpec params = HSSParameterSpec.named("HSS_SHA256_L2_H10_H10");

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            if (keysize == 2) {
                initialize(HSSParameterSpec.named("HSS_SHA256_L2_H10_H10"), random);
            } else if (keysize == 3) {
                initialize(HSSParameterSpec.named("HSS_SHA256_L3_H10_H10_H10"), random);
            } else {
                throw new InvalidParameterException("Unsupported HSS level count: " + keysize);
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof HSSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only HSSParameterSpec is supported");
        }
        this.params = (HSSParameterSpec) params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (HSSImpl impl = new HSSImpl(params)) {
            byte[][] keyPair = impl.generateKeyPair();
            return new KeyPair(new HSSPublicKeyImpl(params, keyPair[0]), new HSSPrivateKeyImpl(params, keyPair[1]));
        } catch (Exception e) {
            throw new ProviderException("Failed to generate HSS key pair", e);
        }
    }
}
