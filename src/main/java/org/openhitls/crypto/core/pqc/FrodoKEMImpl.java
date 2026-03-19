package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class FrodoKEMImpl extends NativeResource {
    private byte[] encapKey;
    private byte[] decapKey;
    private String parameterSet;

    public FrodoKEMImpl(String parameterSet) {
        super(initContext(parameterSet), CryptoNative::frodoKemFreeContext);
        this.parameterSet = parameterSet;
        byte[][] keyPair = CryptoNative.frodoKemGenerateKeyPair(nativeContext, this.parameterSet);
        this.encapKey = keyPair[0];
        this.decapKey = keyPair[1];
    }

    public FrodoKEMImpl(String parameterSet, byte[] encapKey, byte[] decapKey) {
        super(initContext(parameterSet), CryptoNative::frodoKemFreeContext);
        this.parameterSet = parameterSet;
        setKeys(encapKey, decapKey);
    }

    void setKeys(byte[] encapKey, byte[] decapKey) {
        if (encapKey == null && decapKey == null) {
            throw new IllegalArgumentException("At least one key must be non-null");
        }
        CryptoNative.frodoKemSetKeys(nativeContext, encapKey, decapKey);
        this.encapKey = encapKey;
        this.decapKey = decapKey;
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.frodoKemCreateContext(parameterSet);
    }

    public byte[] getEK() {
        return encapKey;
    }

    public byte[] getDk() {
        return decapKey;
    }

    public String getParameterSet() {
        return parameterSet;
    }

    public byte[][] encapsulate() {
        if (encapKey == null) {
            throw new IllegalStateException("encapsulate key not initialized");
        }
        try {
            return CryptoNative.frodoKemEncapsulate(nativeContext);
        } catch (Exception e) {
            throw new IllegalStateException("FrodoKEM encapsulation failed: " + e.getMessage(), e);
        }
    }

    public byte[] decapsulate(byte[] ciphertext) {
        if (decapKey == null) {
            throw new IllegalArgumentException("decapsulate key not initialized");
        }
        if (ciphertext == null) {
            throw new IllegalArgumentException("ciphertext cannot be null");
        }
        try {
            return CryptoNative.frodoKemDecapsulate(nativeContext, ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("FrodoKEM decapsulation failed: " + e.getMessage(), e);
        }
    }
}
