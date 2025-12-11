package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class MLKEMImpl extends NativeResource {
    private byte[] encapKey;
    private byte[] decapKey;
    private String parameterSet;

    public MLKEMImpl(String parameterSet) {
        super(initContext(parameterSet), CryptoNative::mlkemFreeContext);
        this.parameterSet = parameterSet;
        byte[][] keyPair = CryptoNative.mlkemGenerateKeyPair(nativeContext, this.parameterSet);
        this.encapKey = keyPair[0];
        this.decapKey = keyPair[1];
    }

    public MLKEMImpl(String parameterSet, byte[] encapKey, byte[] decapKey) {
        super(initContext(parameterSet), CryptoNative::mlkemFreeContext);
        this.parameterSet = parameterSet;
        setKeys(encapKey, decapKey);
    }

    void setKeys(byte[] encapKey, byte[] decapKey) {
        this.encapKey = encapKey;
        this.decapKey = decapKey;
        CryptoNative.mlkemSetKeys(nativeContext, encapKey, decapKey);
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.mlkemCreateContext(parameterSet);
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
            return CryptoNative.mlkemEncapsulate(nativeContext);
        } catch (Exception e) {
            throw new IllegalStateException("ML-KEM encapsulation failed: " + e.getMessage(), e);
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
            return CryptoNative.mlkemDecapsulate(nativeContext, ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("ML-KEM decapsulation failed: " + e.getMessage(), e);
        }
    }
}