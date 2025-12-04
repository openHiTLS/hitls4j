package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.MLDSAPublicKey;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;

public class MLDSAPublicKeyImpl implements MLDSAPublicKey {
    private static final long serialVersionUID = 1L;
    private final MLDSAParameterSpec params;
    private final byte[] encoded;
    private final byte[] publicKeyData;

    public MLDSAPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded;
        this.params = null;
        this.publicKeyData = null;
    }

    public MLDSAPublicKeyImpl(MLDSAParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded;
        this.publicKeyData = null;
    }

    @Override
    public byte[] getPublicData() {
        return publicKeyData != null ? publicKeyData.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "ML-DSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
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
