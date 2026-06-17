package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.XMSSImpl;
import org.openhitls.crypto.jce.key.XMSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSKeyPairGenerator extends KeyPairGeneratorSpi {
    private XMSSParameterSpec params = new XMSSParameterSpec("CRYPT_XMSS_SHA2_10_256");

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            initialize(new XMSSParameterSpec("CRYPT_XMSS_SHA2_" + keysize + "_256"), random);
        } catch (RuntimeException | InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof XMSSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only XMSSParameterSpec is supported");
        }
        this.params = (XMSSParameterSpec) params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (XMSSImpl impl = new XMSSImpl(params)) {
            byte[][] keyPair = impl.generateKeyPair();
            return new KeyPair(new XMSSPublicKeyImpl(params, keyPair[0]), new XMSSPrivateKeyImpl(params, keyPair[1]));
        } catch (Exception e) {
            throw new ProviderException("Failed to generate XMSS key pair", e);
        }
    }
}
