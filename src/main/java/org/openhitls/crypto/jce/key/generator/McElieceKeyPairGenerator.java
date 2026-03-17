package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.McElieceImpl;
import org.openhitls.crypto.jce.key.McEliecePrivateKeyImpl;
import org.openhitls.crypto.jce.key.McEliecePublicKeyImpl;
import org.openhitls.crypto.jce.spec.McElieceGenParameterSpec;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

public class McElieceKeyPairGenerator extends KeyPairGeneratorSpi {
    private McElieceParameterSpec params;
    private String parameterSet;

    private static final String PARAM_REGEX =
            "^McEliece-(6688128|6688128f|6688128pc|6688128pcf|6960119|6960119f|6960119pc|6960119pcf|8192128|8192128f|8192128pc|8192128pcf)$";

    @Override
    public void initialize(int keysize, SecureRandom random) {
        // Classic McEliece does not support integer-based initialization
        throw new IllegalArgumentException(
                "Classic McEliece requires AlgorithmParameterSpec initialization. Use initialize(McElieceGenParameterSpec, SecureRandom) instead.");
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("Classic McEliece parameters cannot be null");
        }

        if (params instanceof McElieceParameterSpec) {
            this.params = (McElieceParameterSpec) params;
            this.parameterSet = this.params.getName();
        } else if (params instanceof McElieceGenParameterSpec) {
            String name = ((McElieceGenParameterSpec) params).getName();
            if (!name.matches(PARAM_REGEX)) {
                throw new InvalidAlgorithmParameterException("Unsupported Classic McEliece parameter set: " + name);
            }
            this.parameterSet = name;
            this.params = McElieceParameterSpec.getParamByName(name);
        } else {
            throw new InvalidAlgorithmParameterException("Only McElieceParameterSpec and McElieceGenParameterSpec are supported");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null && parameterSet == null) {
            throw new IllegalStateException("Classic McEliece parameters not initialized");
        }

        try {
            McElieceImpl mcEliece = new McElieceImpl(parameterSet);
            byte[] publicKey = mcEliece.getEK();
            byte[] privateKey = mcEliece.getDk();

            return new KeyPair(
                    new McEliecePublicKeyImpl(params, publicKey),
                    new McEliecePrivateKeyImpl(params, privateKey)
            );
        } catch (Exception e) {
            throw new ProviderException("Failed to generate Classic McEliece key pair", e);
        }
    }
}
