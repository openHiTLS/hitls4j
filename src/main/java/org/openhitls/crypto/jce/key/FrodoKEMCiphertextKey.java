package org.openhitls.crypto.jce.key;

import java.security.Key;

public class FrodoKEMCiphertextKey implements Key {
    private final byte[] ciphertext;

    public FrodoKEMCiphertextKey(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }
        this.ciphertext = ciphertext.clone();
    }

    @Override
    public String getAlgorithm() {
        return "FrodoKEM";
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
