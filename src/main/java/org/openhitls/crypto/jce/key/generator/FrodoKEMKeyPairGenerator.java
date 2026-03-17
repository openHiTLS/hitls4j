package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.FrodoKEMImpl;
import org.openhitls.crypto.jce.key.FrodoKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.FrodoKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.FrodoKEMGenParameterSpec;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

public class FrodoKEMKeyPairGenerator extends KeyPairGeneratorSpi {
    private FrodoKEMParameterSpec params;
    private String parameterSet;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        String paramSet;
        switch (keysize) {
            case 640:
                paramSet = "FrodoKEM-640-SHAKE";
                break;
            case 976:
                paramSet = "FrodoKEM-976-SHAKE";
                break;
            case 1344:
                paramSet = "FrodoKEM-1344-SHAKE";
                break;
            default:
                throw new IllegalArgumentException("Unsupported parameter keysize: " + keysize);
        }
        try {
            initialize(new FrodoKEMGenParameterSpec(paramSet), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("Failed to initialize FrodoKEM: " + e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("FrodoKEM parameters cannot be null");
        }

        if (params instanceof FrodoKEMParameterSpec) {
            this.params = (FrodoKEMParameterSpec) params;
            this.parameterSet = this.params.getName();
        } else if (params instanceof FrodoKEMGenParameterSpec) {
            String name = ((FrodoKEMGenParameterSpec) params).getName();
            if (!name.matches("^FrodoKEM-(640|976|1344)-(SHAKE|AES)$")) {
                throw new InvalidAlgorithmParameterException("Unsupported FrodoKEM parameter set: " + name);
            }
            this.parameterSet = name;
            this.params = FrodoKEMParameterSpec.getParamByName(name);
        } else {
            throw new InvalidAlgorithmParameterException("Only FrodoKEMParameterSpec and FrodoKEMGenParameterSpec are supported");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (params == null && parameterSet == null) {
            throw new IllegalStateException("FrodoKEM parameters not initialized");
        }

        try {
            FrodoKEMImpl frodoKem = new FrodoKEMImpl(parameterSet);
            byte[] publicKey = frodoKem.getEK();
            byte[] privateKey = frodoKem.getDk();

            return new KeyPair(
                    new FrodoKEMPublicKeyImpl(params, publicKey),
                    new FrodoKEMPrivateKeyImpl(params, privateKey)
            );
        } catch (Exception e) {
            throw new ProviderException("Failed to generate FrodoKEM key pair", e);
        }
    }
}
