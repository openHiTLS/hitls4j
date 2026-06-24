package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class SLHDSASignatureParameterSpec implements AlgorithmParameterSpec{
    private final boolean deterministic;
    private final boolean preHash;
    private final byte[] context;
    private final byte[] additionalRandomness;

    public SLHDSASignatureParameterSpec(boolean deterministic, boolean preHash, byte[] context, byte[] additionalRandomness) {
        this.deterministic = deterministic;
        this.preHash = preHash;
        this.context = context != null ? context.clone() : null;
        this.additionalRandomness = additionalRandomness != null ? additionalRandomness.clone() : null;
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

    public byte[] getAdditionalRandomness() {
        return additionalRandomness != null ? additionalRandomness.clone() : null;
    }
}
