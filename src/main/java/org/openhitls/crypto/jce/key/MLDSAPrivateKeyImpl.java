package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.MLDSAPrivateKey;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;

public class MLDSAPrivateKeyImpl implements MLDSAPrivateKey {
    private static final long serialVersionUID = 1L;
    private final MLDSAParameterSpec params;
    private final byte[] encoded;
    private final byte[] privateKeyData;

    public MLDSAPrivateKeyImpl(byte[] encoded) {
        this.encoded = encoded;
        this.params = null;
        this.privateKeyData = null;
    }

    public MLDSAPrivateKeyImpl(MLDSAParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded;
        this.privateKeyData = null;
    }

    @Override
    public byte[] getPrivateData() {
        return privateKeyData != null ? privateKeyData.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public MLDSAParameterSpec getParams() {
        return params;
    }
}
