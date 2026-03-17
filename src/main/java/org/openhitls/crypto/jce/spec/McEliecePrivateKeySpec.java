package org.openhitls.crypto.jce.spec;

import java.security.spec.KeySpec;

public class McEliecePrivateKeySpec implements KeySpec {
    private final byte[] encoded;
    private final McElieceParameterSpec params;

    public McEliecePrivateKeySpec(byte[] encoded, McElieceParameterSpec params) {
        this.encoded = encoded.clone();
        this.params = params;
    }

    public byte[] getEncoded() {
        return encoded.clone();
    }

    public McElieceParameterSpec getParams() {
        return params;
    }
}
