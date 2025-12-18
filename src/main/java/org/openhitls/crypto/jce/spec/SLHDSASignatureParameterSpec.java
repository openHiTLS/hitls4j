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
        this.context = context;
        this.additionalRandomness = additionalRandomness;
    }

    public boolean isDeterministic(){
        return deterministic;
    }

    public boolean isPreHash() {
        return preHash;
    }

    public byte[] getContext() {
        return context;
    }

    public byte[] getAdditionalRandomness() {
        return additionalRandomness;
    }
}
