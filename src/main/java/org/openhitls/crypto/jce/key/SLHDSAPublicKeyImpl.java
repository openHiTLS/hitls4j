package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.SLHDSAPublicKey;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAPublicKeyImpl implements SLHDSAPublicKey{
    private static final long serialVersionUID = 1L;
    private final SLHDSAParameterSpec params;
    private final byte[] encoded;
    private final byte[] publicKeyData; // raw public key data, not support yet

    public SLHDSAPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded;
        this.params = null;
        this.publicKeyData = null;
    }

    public SLHDSAPublicKeyImpl(SLHDSAParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded;
        this.publicKeyData = null;
    }

    @Override
    public SLHDSAParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "SLH-DSA";
    }

    @Override
    public byte[] getEncoded() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getPublicData() {
        return publicKeyData != null ? publicKeyData.clone() : null;
    }
    
}
