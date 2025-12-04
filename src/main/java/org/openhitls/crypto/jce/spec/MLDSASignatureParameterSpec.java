package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class MLDSASignatureParameterSpec implements AlgorithmParameterSpec {
    private final boolean deterministic;  // CRYPT_CTRL_SET_DETERMINISTIC_FLAG
    private final boolean preHash;        // CRYPT_CTRL_SET_PREHASH_FLAG
    private final boolean encodeFlag;     // CRYPT_CTRL_SET_MLDSA_ENCODE_FLAG
    private final boolean externalMuFlag; // CRYPT_CTRL_SET_MLDSA_MUMSG_FLAG
    private final byte[] context;         // Additional context

    public MLDSASignatureParameterSpec(boolean deterministic, boolean preHash, boolean encodeFlag, boolean externalMuFlag, byte[] context) {
        this.deterministic = deterministic;
        this.preHash = preHash;
        this.encodeFlag = encodeFlag;
        this.externalMuFlag = externalMuFlag;
        this.context = context;
    }

    public boolean isDeterministic() {
        return deterministic;
    }

    public boolean isPreHash() {
        return preHash;
    }

    public boolean isEncodeFlag() {
        return encodeFlag;
    }

    public boolean isExternalMuFlag() {
        return externalMuFlag;
    }

    public byte[] getContext() {
        return context;
    }
}