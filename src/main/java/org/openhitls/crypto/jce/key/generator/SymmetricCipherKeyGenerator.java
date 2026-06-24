package org.openhitls.crypto.jce.key.generator;

import org.openhitls.crypto.core.SensitiveDataUtil;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SymmetricCipherKeyGenerator extends KeyGeneratorSpi {
    private SecureRandom random;
    private int keySize;

    public SymmetricCipherKeyGenerator() {
        super();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("SM4 key generation does not use any parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != 128 && keysize != 192 && keysize != 256) {
            throw new IllegalArgumentException("Invalid key size: " + keysize);
        }
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] keyBytes = new byte[keySize / 8];
        try {
            random.nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            SensitiveDataUtil.clear(keyBytes);
        }
    }
}
