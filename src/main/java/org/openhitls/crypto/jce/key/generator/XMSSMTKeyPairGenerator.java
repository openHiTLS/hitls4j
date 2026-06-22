package org.openhitls.crypto.jce.key.generator;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.core.pqc.XMSSMTImpl;
import org.openhitls.crypto.jce.key.XMSSMTPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSMTPublicKeyImpl;
import org.openhitls.crypto.jce.spec.XMSSMTParameterSpec;

public class XMSSMTKeyPairGenerator extends KeyPairGeneratorSpi {
    private XMSSMTParameterSpec params = new XMSSMTParameterSpec("CRYPT_XMSSMT_SHA2_20_2_256");

    @Override
    public void initialize(int keysize, SecureRandom random) {
        try {
            initialize(new XMSSMTParameterSpec("CRYPT_XMSSMT_SHA2_" + keysize + "_2_256"), random);
        } catch (RuntimeException | InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof XMSSMTParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only XMSSMTParameterSpec is supported");
        }
        this.params = (XMSSMTParameterSpec) params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try (XMSSMTImpl impl = new XMSSMTImpl(params)) {
            byte[][] keyPair = impl.generateKeyPair();
            return new KeyPair(new XMSSMTPublicKeyImpl(params, keyPair[0]), new XMSSMTPrivateKeyImpl(params, keyPair[1]));
        } catch (Exception e) {
            throw new ProviderException("Failed to generate XMSSMT key pair", e);
        }
    }
}
