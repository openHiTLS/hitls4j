package org.openhitls.crypto.jce.spec;

import java.security.spec.KeySpec;

public class MLDSAPublicKeySpec implements KeySpec {
    private final byte[] encoded;
    private final MLDSAParameterSpec params;

    public MLDSAPublicKeySpec(byte[] encoded, MLDSAParameterSpec params) {
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public MLDSAParameterSpec getParams() {
        return params;
    }
}