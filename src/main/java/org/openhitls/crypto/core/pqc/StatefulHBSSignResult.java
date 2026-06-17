package org.openhitls.crypto.core.pqc;

public class StatefulHBSSignResult {
    private final byte[] signature;
    private final byte[] updatedPrivateKey;

    public StatefulHBSSignResult(byte[] signature, byte[] updatedPrivateKey) {
        this.signature = signature != null ? signature.clone() : null;
        this.updatedPrivateKey = updatedPrivateKey != null ? updatedPrivateKey.clone() : null;
    }

    public byte[] getSignature() {
        return signature != null ? signature.clone() : null;
    }

    public byte[] getUpdatedPrivateKey() {
        return updatedPrivateKey != null ? updatedPrivateKey.clone() : null;
    }
}
