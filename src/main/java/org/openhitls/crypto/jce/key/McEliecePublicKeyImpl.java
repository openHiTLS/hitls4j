package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.McEliecePublicKey;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

public class McEliecePublicKeyImpl implements McEliecePublicKey {
    private static final long serialVersionUID = 1L;
    private final McElieceParameterSpec params;
    private final byte[] encoded;

    public McEliecePublicKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
    }

    public McEliecePublicKeyImpl(McElieceParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
    }

    @Override
    public byte[] getPublicData() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "Classic-McEliece";
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
    public McElieceParameterSpec getParams() {
        return params;
    }
}
