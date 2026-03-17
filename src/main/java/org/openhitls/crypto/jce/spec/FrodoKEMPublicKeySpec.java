package org.openhitls.crypto.jce.spec;

import java.security.spec.KeySpec;

public class FrodoKEMPublicKeySpec implements KeySpec {
    private final byte[] encoded;
    private final FrodoKEMParameterSpec params;

    public FrodoKEMPublicKeySpec(byte[] encoded, FrodoKEMParameterSpec params) {
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public FrodoKEMParameterSpec getParams() {
        return params;
    }
}
