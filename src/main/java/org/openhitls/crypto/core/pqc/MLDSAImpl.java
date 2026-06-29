package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.SensitiveDataUtil.KeyMaterial;
import org.openhitls.crypto.jce.spec.MLDSASignatureParameterSpec;

public class MLDSAImpl extends NativeResource {
    private byte[] publicKey;
    private byte[] privateKey;
    private String parameterSet;
    private int hashAlgorithm;

    public MLDSAImpl(String parameterSet) {
        this(parameterSet, 0);
    }

    public MLDSAImpl(String parameterSet, int hashAlgorithm) {
        super(initContext(parameterSet), CryptoNative::mldsaFreeContext);
        this.parameterSet = parameterSet;
        this.hashAlgorithm = hashAlgorithm;
        byte[][] keyPair = null;
        try {
            keyPair = CryptoNative.mldsaGenerateKeyPair(nativeContext, this.parameterSet);
            if (keyPair == null || keyPair.length != 2 || keyPair[0] == null || keyPair[1] == null) {
                throw new IllegalStateException("Generated ML-DSA key pair is invalid");
            }
            this.publicKey = keyPair[0];
            this.privateKey = keyPair[1];
        } catch (RuntimeException | Error e) {
            SensitiveDataUtil.clear(keyPair != null && keyPair.length > 1 ? keyPair[1] : null);
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    public MLDSAImpl(String parameterSet, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(parameterSet), CryptoNative::mldsaFreeContext);
        this.parameterSet = parameterSet;
        this.hashAlgorithm = hashAlgorithm;
        try {
            setKeys(publicKey, privateKey);
        } catch (RuntimeException | Error e) {
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.mldsaCreateContext(parameterSet);
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("At least one key must be non-null");
        }
        KeyMaterial keyMaterial = SensitiveDataUtil.copyKeyMaterial(publicKey, privateKey);
        boolean updated = false;
        try {
            CryptoNative.mldsaSetKeys(nativeContext, keyMaterial.publicKey(), keyMaterial.privateKey());
            updated = true;
            SensitiveDataUtil.clear(this.privateKey);
            this.publicKey = keyMaterial.publicKey();
            this.privateKey = keyMaterial.privateKey();
        } finally {
            if (!updated) {
                keyMaterial.clearPrivate();
            }
        }
    }

    public byte[] getPublicKey() {
        return publicKey.clone();
    }

    public byte[] getPrivateKey() {
        return privateKey.clone();
    }

    public String getParameterSet() {
        return parameterSet;
    }

    public int getHashAlgorithm() {
        return hashAlgorithm;
    }

    public byte[] signData(byte[] data, MLDSASignatureParameterSpec signParams) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        if (signParams == null) {
            throw new IllegalArgumentException("Signature parameters cannot be null");
        }
        try { // set ML-DSA signature parameters
            CryptoNative.mldsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.mldsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.mldsaSetExternalMuFlag(nativeContext, signParams.isExternalMuFlag());
            CryptoNative.mldsaSetCxt(nativeContext, signParams.getContext());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to set MLDSA signatureParameters:" + e.getMessage(), e);
        }
        return CryptoNative.mldsaSign(nativeContext, data, hashAlgorithm);
    }

    public boolean verifySignature(byte[] data, byte[] signature, MLDSASignatureParameterSpec signParams) {
        if (data == null || signature == null) {
            throw new IllegalArgumentException("input data and signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey not initialized");
        }
        if (signParams == null) {
            throw new IllegalArgumentException("Signature parameters cannot be null");
        }
        try {
            CryptoNative.mldsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.mldsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.mldsaSetExternalMuFlag(nativeContext, signParams.isExternalMuFlag());
            CryptoNative.mldsaSetCxt(nativeContext, signParams.getContext());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to set MLDSA signatureParameters:" + e.getMessage(), e);
        }
        return CryptoNative.mldsaVerify(nativeContext, data, signature, hashAlgorithm);
    }
}
