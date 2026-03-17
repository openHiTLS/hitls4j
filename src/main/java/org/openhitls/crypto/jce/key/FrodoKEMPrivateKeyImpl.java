package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.FrodoKEMPrivateKey;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

public class FrodoKEMPrivateKeyImpl implements FrodoKEMPrivateKey {
    private static final long serialVersionUID = 1L;
    private final FrodoKEMParameterSpec params;
    private final byte[] encoded;

    public FrodoKEMPrivateKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
    }

    public FrodoKEMPrivateKeyImpl(FrodoKEMParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
    }

    @Override
    public byte[] getPrivateData() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "FrodoKEM";
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
    public FrodoKEMParameterSpec getParams() {
        return params;
    }
}
