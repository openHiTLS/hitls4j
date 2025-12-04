package org.openhitls.crypto.jce.key.generator;

import org.openhitls.crypto.core.pqc.MLDSAImpl;
import org.openhitls.crypto.jce.key.MLDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLDSAPublicKeyImpl;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.spec.MLDSAGenParameterSpec;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;
import org.openhitls.crypto.jce.util.MLDSAUtil;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class MLDSAKeyPairGenerator extends KeyPairGeneratorSpi {
    private MLDSAParameterSpec params;
    private String paramSetName;

    @Override
    public void initialize(int keySize, SecureRandom random) {
        // Map parameter set suffix to ML-DSA parameter set name
        try {
            String paramSet = switch (keySize) {
                case 44 -> "ML-DSA-44";
                case 65 -> "ML-DSA-65";
                case 87 -> "ML-DSA-87";
                default -> throw new InvalidParameterException("Unsupported MLDSA key size: " + keySize);
            };
            initialize(new MLDSAGenParameterSpec(paramSet), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("Failed to initialize MLDSA: " + e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("MLDSA parameters cannot be null");
        }

        // Handle MLDSAParameterSpec
        if (params instanceof MLDSAParameterSpec mldsaParams) {
            this.params = mldsaParams;
            this.paramSetName = MLDSAUtil.getParamSetName(mldsaParams);
        } else if (params instanceof MLDSAGenParameterSpec genSpec) {
            String name = genSpec.getName();
            // Validate supported parameter sets
            if (!name.equals("ML-DSA-44") && !name.equals("ML-DSA-65") && !name.equals("ML-DSA-87")) {
                throw new InvalidAlgorithmParameterException("Unsupported MLDSA param set: " + name);
            }
            try {
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("ML-DSA", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(genSpec);
                this.params = algorithmParameters.getParameterSpec(MLDSAParameterSpec.class);
                this.paramSetName = name;
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to create MLDSA parameters: " + e.getMessage(), e);
            }
        }
        // Unsupported parameter type
        else {
            throw new InvalidAlgorithmParameterException("MLDSA only supports MLDSAParameterSpec and MLDSAGenParameterSpec");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null || paramSetName == null) {
            throw new IllegalStateException("ML-DSA parameters not initialized");
        }

        MLDSAImpl mldsaImpl = new MLDSAImpl(paramSetName);
        byte[] publicKeyBytes = mldsaImpl.getPublicKey();
        byte[] privateKeyBytes = mldsaImpl.getPrivateKey();

        // Wrap as JCE key objects
        return new KeyPair(
                new MLDSAPublicKeyImpl(params, publicKeyBytes),
                new MLDSAPrivateKeyImpl(params, privateKeyBytes)
        );
    }
}
