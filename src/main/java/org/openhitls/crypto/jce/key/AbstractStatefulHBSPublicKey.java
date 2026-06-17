package org.openhitls.crypto.jce.key;

import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.jce.interfaces.StatefulHBSPublicKey;

public abstract class AbstractStatefulHBSPublicKey implements StatefulHBSPublicKey {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final AlgorithmParameterSpec params;
    private final byte[] encoded;

    protected AbstractStatefulHBSPublicKey(String algorithm, AlgorithmParameterSpec params, byte[] encoded) {
        if (algorithm == null || params == null || encoded == null) {
            throw new NullPointerException("algorithm, params and encoded cannot be null");
        }
        this.algorithm = algorithm;
        this.params = params;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public byte[] getPublicData() {
        return encoded.clone();
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        return params;
    }
}
