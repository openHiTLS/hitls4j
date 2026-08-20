package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class SLHDSASignatureParameterSpec implements AlgorithmParameterSpec{
    private final boolean deterministic;
    private final boolean preHash;
    private final byte[] context;

    public SLHDSASignatureParameterSpec(boolean deterministic, boolean preHash, byte[] context) {
        this.deterministic = deterministic;
        this.preHash = preHash;
        this.context = context != null ? context.clone() : null;
    }

    public boolean isDeterministic(){
        return deterministic;
    }

    public boolean isPreHash() {
        return preHash;
    }

    public byte[] getContext() {
        return context != null ? context.clone() : null;
    }
}
