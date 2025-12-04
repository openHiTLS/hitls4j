package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
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
        byte[][] keyPair = CryptoNative.mldsaGenerateKeyPair(nativeContext, this.parameterSet);
        this.publicKey = keyPair[0];
        this.privateKey = keyPair[1];
    }

    public MLDSAImpl(String parameterSet, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(parameterSet), CryptoNative::mldsaFreeContext);
        this.parameterSet = parameterSet;
        this.hashAlgorithm = hashAlgorithm;
        setKeys(publicKey, privateKey);
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.mldsaCreateContext(parameterSet);
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        CryptoNative.mldsaSetKeys(nativeContext, publicKey, privateKey);
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
        try { // set ML-DSA signature parameters
            CryptoNative.mldsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.mldsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.mldsaSetEncodeFlag(nativeContext, signParams.isEncodeFlag());
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
        try {
            CryptoNative.mldsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.mldsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.mldsaSetEncodeFlag(nativeContext, signParams.isEncodeFlag());
            CryptoNative.mldsaSetExternalMuFlag(nativeContext, signParams.isExternalMuFlag());
            CryptoNative.mldsaSetCxt(nativeContext, signParams.getContext());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to set MLDSA signatureParameters:" + e.getMessage(), e);
        }
        return CryptoNative.mldsaVerify(nativeContext, data, signature, hashAlgorithm);
    }
}
