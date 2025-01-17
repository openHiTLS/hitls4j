package org.openhitls.crypto.jce.key.generator;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import org.openhitls.crypto.core.asymmetric.SM2;
import org.openhitls.crypto.jce.key.SM2PublicKey;
import org.openhitls.crypto.jce.key.SM2PrivateKey;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        SM2 sm2 = new SM2();
        byte[] publicKey = sm2.getPublicKey();
        byte[] privateKey = sm2.getPrivateKey();
        
        return new KeyPair(
            new SM2PublicKey(publicKey),
            new SM2PrivateKey(privateKey)
        );
    }
}
