package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.SLHDSAImpl;
import org.openhitls.crypto.jce.key.SLHDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.SLHDSAPublicKeyImpl;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private SLHDSAParameterSpec params;
    private String paramSetName;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException("Not supported, please use initialize(AlgorithmParameterSpec params, SecureRandom random) instead");
    }
    
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("Parameter cannot be null");
        }
        if (params instanceof SLHDSAParameterSpec) {
            this.params = (SLHDSAParameterSpec)params;
            this.paramSetName = ((SLHDSAParameterSpec)params).getName();
        } else {
            throw new InvalidAlgorithmParameterException("Only SLHDSAParameterSpec is suppourted");
        }
    }
    
    @Override
    public KeyPair generateKeyPair() {
        if (params == null || paramSetName == null) {
            throw new IllegalStateException("SLHDSA parameters not initialized");
        }

        SLHDSAImpl slhdsaImpl = new SLHDSAImpl(paramSetName);
        byte[] publicKey = slhdsaImpl.getPublicKey();
        byte[] privateKey = slhdsaImpl.getPrivateKey();

        return new KeyPair(
                new SLHDSAPublicKeyImpl(params, publicKey),
                new SLHDSAPrivateKeyImpl(params, privateKey)
        );
    }
}
