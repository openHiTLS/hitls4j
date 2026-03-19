package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.McEliecePrivateKey;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;

public class McEliecePrivateKeyImpl implements McEliecePrivateKey {
    private static final long serialVersionUID = 1L;
    private final McElieceParameterSpec params;
    private final byte[] encoded;

    public McEliecePrivateKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
    }

    public McEliecePrivateKeyImpl(McElieceParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
    }

    @Override
    public byte[] getPrivateData() {
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
