package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.MLKEMPublicKey;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;

public class MLKEMPublicKeyImpl implements MLKEMPublicKey {
    private static final long serialVersionUID = 1L;
    private final MLKEMParameterSpec params;
    private final byte[] encoded;
    private final byte[] publicKeyData; // raw public data

    public MLKEMPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
        this.publicKeyData = null;
    }

    public MLKEMPublicKeyImpl(MLKEMParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
        this.publicKeyData = null;
    }

    @Override
    public byte[] getPublicData() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
    }

    @Override
    public String getFormat() {
        return "RAW";
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
