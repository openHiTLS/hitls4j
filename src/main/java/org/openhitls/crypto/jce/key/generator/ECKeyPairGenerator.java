package org.openhitls.crypto.jce.key.generator;

import java.security.*;
import java.security.spec.*;
import org.openhitls.crypto.jce.key.ECPublicKey;
import org.openhitls.crypto.jce.key.ECPrivateKey;
import org.openhitls.crypto.jce.provider.HiTls4jProvider;
import org.openhitls.crypto.jce.util.ECUtil;
import org.openhitls.crypto.core.asymmetric.ECDSAImpl;

public class ECKeyPairGenerator extends KeyPairGeneratorSpi {
    private ECParameterSpec params;
    private String curveName;

    @Override
    public void initialize(int keySize, SecureRandom random) {
        // Map key sizes to appropriate curves
        try {
            String curve;
            switch (keySize) {
                case 256:
                    curve = "secp256v1";
                    break;
                case 384:
                    curve = "secp384r1";
                    break;
                case 521:
                    curve = "secp521r1";
                    break;
                default:
                    throw new InvalidParameterException("Unsupported key size: " + keySize);
            }
            initialize(new ECGenParameterSpec(curve), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {

        if (params == null) {
            throw new InvalidAlgorithmParameterException("Parameters cannot be null");
        } else if (params instanceof ECParameterSpec) {
            try {
                this.params = (ECParameterSpec) params;
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to verify parameters: " + e.getMessage());
            }
        } else if (params instanceof ECGenParameterSpec) {
            ECGenParameterSpec spec = (ECGenParameterSpec)params;
            // Support all our curves
            String name = spec.getName().toLowerCase();
            if (!name.equals("sm2p256v1") && !name.equals("secp256r1") && 
                !name.equals("secp384r1") && !name.equals("secp521r1")) {
                throw new InvalidAlgorithmParameterException("Unsupported curve: " + spec.getName());
            }
            try {
                AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC", HiTls4jProvider.PROVIDER_NAME);
                algorithmParameters.init(spec);
                this.params = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Failed to initialize parameters: " + e.getMessage());
            }
        } else {
            throw new InvalidAlgorithmParameterException("Only ECParameterSpec and ECGenParameterSpec are supported");
        }
        // Store curve name for key generation
        if (params instanceof ECGenParameterSpec) {
            this.curveName = ((ECGenParameterSpec)params).getName();
        } else {
            // Derive curve name from parameters
            this.curveName = ECUtil.getCurveName(this.params);
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null) {
            throw new IllegalStateException("ECParameterSpec not initialized");
        }
        ECDSAImpl ecdsaImpl = new ECDSAImpl(curveName);
        byte[] publicKey = ecdsaImpl.getPublicKey();
        byte[] privateKey = ecdsaImpl.getPrivateKey();
        
        return new KeyPair(
            new ECPublicKey(publicKey, params),
            new ECPrivateKey(privateKey, params)
        );
    }
}
