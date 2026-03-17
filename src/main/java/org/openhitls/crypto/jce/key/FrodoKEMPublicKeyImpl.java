package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.FrodoKEMPublicKey;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

public class FrodoKEMPublicKeyImpl implements FrodoKEMPublicKey {
    private static final long serialVersionUID = 1L;
    private final FrodoKEMParameterSpec params;
    private final byte[] encoded;

    public FrodoKEMPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
    }

    public FrodoKEMPublicKeyImpl(FrodoKEMParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
    }

    @Override
    public byte[] getPublicData() {
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
