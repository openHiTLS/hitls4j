package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.MLKEMImpl;
import org.openhitls.crypto.jce.key.MLKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.MLKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;

public class MLKEMKeyPairGenerator extends KeyPairGeneratorSpi {
    private MLKEMParameterSpec params;
    private String parameterSet;

    @Override
    public void initialize(int suffix, SecureRandom random) {
        String paramSet;
        switch (suffix) {
            case 512:
                paramSet = "ML-KEM-512";
                break;
            case 768:
                paramSet = "ML-KEM-768";
                break;
            case 1024:
                paramSet = "ML-KEM-1024";
                break;
            default:
                throw new IllegalArgumentException("Unsupported parameter suffix number: " + suffix);
        }
        try {
            initialize(new MLKEMGenParameterSpec(paramSet), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("Failed to initialize MLKEM: " + e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("ML-KEM parameters cannot be null");
        }

        if (params instanceof MLKEMParameterSpec) {
            this.params = (MLKEMParameterSpec) params;
            this.parameterSet = this.params.getName();
        } else if (params instanceof MLKEMGenParameterSpec) {
            String name = ((MLKEMGenParameterSpec) params).getName();
            if (!name.matches("^ML-KEM-(512|768|1024)$")) {
                throw new InvalidAlgorithmParameterException("Unsupported ML-KEM parameter set: " + name);
            }
            this.parameterSet = name;
            this.params = MLKEMParameterSpec.getParamByName(name);
        } else {
            throw new InvalidAlgorithmParameterException("Only MLKEMParameterSpec and MLKEMGenParameterSpec are supported");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null && parameterSet == null) {
            throw new IllegalStateException("ML-KEM parameters not initialized");
        }

        try {
            MLKEMImpl mlkem = new MLKEMImpl(parameterSet);
            byte[] publicKey = mlkem.getEK();
            byte[] privateKey = mlkem.getDk();

            return new KeyPair(
                    new MLKEMPublicKeyImpl(params, publicKey),
                    new MLKEMPrivateKeyImpl(params, privateKey)
            );
        } catch (Exception e) {
            throw new ProviderException("Failed to generate ML-KEM key pair", e);
        }
    }

}
