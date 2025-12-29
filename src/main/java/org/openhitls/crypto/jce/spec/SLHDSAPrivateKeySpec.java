package org.openhitls.crypto.jce.spec;

import java.security.spec.KeySpec;

public class SLHDSAPrivateKeySpec implements KeySpec{
    private final byte[] encoded;
    private final SLHDSAParameterSpec params;

    public SLHDSAPrivateKeySpec(byte[] encoded, SLHDSAParameterSpec params) {
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public SLHDSAParameterSpec getParams() {
        return params;
    }
}
