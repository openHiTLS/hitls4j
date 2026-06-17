package org.openhitls.crypto.jce.state;

public final class HbsSignCommit {
    private final HbsStateRecord updatedState;
    private final byte[] signature;

    public HbsSignCommit(HbsStateRecord updatedState, byte[] signature) {
        if (updatedState == null || signature == null) {
            throw new NullPointerException("updatedState and signature cannot be null");
        }
        this.updatedState = updatedState;
        this.signature = signature.clone();
    }

    public HbsStateRecord getUpdatedState() {
        return updatedState;
    }

    public byte[] getSignature() {
        return signature.clone();
    }
}
