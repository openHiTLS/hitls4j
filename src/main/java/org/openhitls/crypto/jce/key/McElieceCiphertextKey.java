package org.openhitls.crypto.jce.key;

import java.security.Key;

public class McElieceCiphertextKey implements Key {
    private final byte[] ciphertext;

    public McElieceCiphertextKey(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }
        this.ciphertext = ciphertext.clone();
    }

    @Override
    public String getAlgorithm() {
        return "Classic-McEliece";
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
