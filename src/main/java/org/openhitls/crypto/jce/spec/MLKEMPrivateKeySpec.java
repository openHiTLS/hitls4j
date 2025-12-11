package org.openhitls.crypto.jce.spec;

import java.security.spec.KeySpec;

public class MLKEMPrivateKeySpec implements KeySpec{
    private final byte[] encoded;
    private final MLKEMParameterSpec params;

    public MLKEMPrivateKeySpec(byte[] encoded, MLKEMParameterSpec params) {
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public MLKEMParameterSpec getParams() {
        return params;
    }
}
