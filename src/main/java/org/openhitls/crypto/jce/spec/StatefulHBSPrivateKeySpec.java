package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

public class StatefulHBSPrivateKeySpec implements KeySpec {
    private final byte[] encoded;
    private final AlgorithmParameterSpec params;

    protected StatefulHBSPrivateKeySpec(byte[] encoded, AlgorithmParameterSpec params) {
        if (encoded == null || params == null) {
            throw new NullPointerException("encoded and params cannot be null");
        }
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public AlgorithmParameterSpec getParams() {
        return params;
    }
}
