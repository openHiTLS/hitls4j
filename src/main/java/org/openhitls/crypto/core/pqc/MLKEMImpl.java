package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.SensitiveDataUtil.KeyMaterial;

public class MLKEMImpl extends NativeResource {
    private byte[] encapKey;
    private byte[] decapKey;
    private String parameterSet;

    public MLKEMImpl(String parameterSet) {
        super(initContext(parameterSet), CryptoNative::mlkemFreeContext);
        this.parameterSet = parameterSet;
        byte[][] keyPair = null;
        try {
            keyPair = CryptoNative.mlkemGenerateKeyPair(nativeContext, this.parameterSet);
            if (keyPair == null || keyPair.length != 2 || keyPair[0] == null || keyPair[1] == null) {
                throw new IllegalStateException("Generated ML-KEM key pair is invalid");
            }
            this.encapKey = keyPair[0];
            this.decapKey = keyPair[1];
        } catch (RuntimeException | Error e) {
            SensitiveDataUtil.clear(keyPair != null && keyPair.length > 1 ? keyPair[1] : null);
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    public MLKEMImpl(String parameterSet, byte[] encapKey, byte[] decapKey) {
        super(initContext(parameterSet), CryptoNative::mlkemFreeContext);
        this.parameterSet = parameterSet;
        try {
            setKeys(encapKey, decapKey);
        } catch (RuntimeException | Error e) {
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    void setKeys(byte[] encapKey, byte[] decapKey) {
        if (encapKey == null && decapKey == null) {
            throw new IllegalArgumentException("At least one key must be non-null");
        }
        KeyMaterial keyMaterial = SensitiveDataUtil.copyKeyMaterial(encapKey, decapKey);
        boolean updated = false;
        try {
            CryptoNative.mlkemSetKeys(nativeContext, keyMaterial.publicKey(), keyMaterial.privateKey());
            updated = true;
            SensitiveDataUtil.clear(this.decapKey);
            this.encapKey = keyMaterial.publicKey();
            this.decapKey = keyMaterial.privateKey();
        } finally {
            if (!updated) {
                keyMaterial.clearPrivate();
            }
        }
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.mlkemCreateContext(parameterSet);
    }

    public byte[] getEK() {
        return encapKey != null ? encapKey.clone() : null;
    }

    public byte[] getDk() {
        return decapKey != null ? decapKey.clone() : null;
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
