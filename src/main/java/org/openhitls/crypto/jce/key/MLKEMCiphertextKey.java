package org.openhitls.crypto.jce.key;

import java.security.Key;

public class MLKEMCiphertextKey implements Key {
    private final byte[] ciphertext;

    public MLKEMCiphertextKey(byte[] ciphertext) {
        this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
    }

    @Override
    public String getAlgorithm() {
        return "ML-KEM";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return ciphertext != null ? ciphertext.clone() : null;
    }
}
