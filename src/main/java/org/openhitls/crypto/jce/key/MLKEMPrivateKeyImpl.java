package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.MLKEMPrivateKey;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;

public class MLKEMPrivateKeyImpl implements MLKEMPrivateKey {
    private static final long serialVersionUID = 1L;
    private final MLKEMParameterSpec params;
    private final byte[] encoded;
    private final byte[] privateKeyData; // raw private data

    public MLKEMPrivateKeyImpl(byte[] encoded) {
        this.encoded = encoded;
        this.params = null;
        this.privateKeyData = null;
    }

    public MLKEMPrivateKeyImpl(MLKEMParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded;
        this.privateKeyData = null;
    }

    @Override
    public byte[] getPrivateData() {
        return null; // not support yet
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
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
    public MLKEMParameterSpec getParams() {
        return params;
    }
}