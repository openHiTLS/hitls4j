package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.interfaces.SLHDSAPrivateKey;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAPrivateKeyImpl implements SLHDSAPrivateKey{
    private static final long serialVersionUID = 1L;
    private final SLHDSAParameterSpec params;
    private final byte[] encoded;
    private final byte[] privateKeyData; // raw private key data, not support yet

    public SLHDSAPrivateKeyImpl(byte[] encoded) {
        this.encoded = encoded;
        this.params = null;
        this.privateKeyData = null;
    }

    public SLHDSAPrivateKeyImpl(SLHDSAParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded;
        this.privateKeyData = null;
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
        return "RAW";
    }

    @Override
    public byte[] getPrivateData() {
        return encoded != null ? encoded.clone() : null;
    }
    
}
