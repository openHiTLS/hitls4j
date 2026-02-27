package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.SLHDSASignatureParameterSpec;

public class SLHDSAImpl extends NativeResource {
    private byte[] publicKey;
    private byte[] privateKey;
    private String parameterSet;
    private int hashAlgorithm;

    public SLHDSAImpl(String parameterSet) {
        this(parameterSet, 0);
    }

    public SLHDSAImpl(String parameterSet, int hashAlgorithm) {
        super(initContext(parameterSet), CryptoNative::slhdsaFreeContext);
        this.parameterSet = parameterSet;
        this.hashAlgorithm = hashAlgorithm;
        byte[][] keyPair = CryptoNative.slhdsaGenerateKeyPair(nativeContext, this.parameterSet);
        this.publicKey = keyPair[0];
        this.privateKey = keyPair[1];
    }

    public SLHDSAImpl(String parameterSet, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(parameterSet), CryptoNative::slhdsaFreeContext);
        this.parameterSet = parameterSet;
        this.hashAlgorithm = hashAlgorithm;
        setKeys(publicKey, privateKey);
    }

    private static long initContext(String parameterSet) {
        if (parameterSet == null) {
            throw new IllegalArgumentException("Parameter set cannot be null");
        }
        return CryptoNative.slhdsaCreateContext(parameterSet);
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        CryptoNative.slhdsaSetKeys(nativeContext, publicKey, privateKey);
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

    public byte[] signData(byte[] data, SLHDSASignatureParameterSpec signParams) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalStateException("Private key not initialized");
        }
        try {
            CryptoNative.slhdsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.slhdsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.slhdsaSetCxt(nativeContext, signParams.getContext());
            CryptoNative.slhdsaSetAdditionalRandomness(nativeContext, signParams.getAdditionalRandomness());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to set SLHDSA signatureParameters:" + e.getMessage(), e);
        }
        return CryptoNative.slhdsaSign(nativeContext, data, hashAlgorithm);
    }

    public boolean verifySignature(byte[] data, byte[] signature, SLHDSASignatureParameterSpec signParams) {
        if (data == null || signature == null) {
            throw new IllegalArgumentException("Input data and signature cannot be null");
        }
        if (publicKey == null) {
            throw new IllegalStateException("Public key not initialized");
        }
        try {
            CryptoNative.slhdsaSetDeterministic(nativeContext, signParams.isDeterministic());
            CryptoNative.slhdsaSetPreHash(nativeContext, signParams.isPreHash());
            CryptoNative.slhdsaSetCxt(nativeContext, signParams.getContext());
            CryptoNative.slhdsaSetAdditionalRandomness(nativeContext, signParams.getAdditionalRandomness());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to set SLHDSA signatureParameters:" + e.getMessage(), e);
        }
        return CryptoNative.slhdsaVerify(nativeContext, data, signature, hashAlgorithm);
    }
}
