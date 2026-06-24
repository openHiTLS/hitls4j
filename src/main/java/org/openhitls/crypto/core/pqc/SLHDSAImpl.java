package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.SensitiveDataUtil.KeyMaterial;
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
        byte[][] keyPair = null;
        try {
            keyPair = CryptoNative.slhdsaGenerateKeyPair(nativeContext, this.parameterSet);
            if (keyPair == null || keyPair.length != 2 || keyPair[0] == null || keyPair[1] == null) {
                throw new IllegalStateException("Generated SLH-DSA key pair is invalid");
            }
            this.publicKey = keyPair[0];
            this.privateKey = keyPair[1];
        } catch (RuntimeException | Error e) {
            SensitiveDataUtil.clear(keyPair != null && keyPair.length > 1 ? keyPair[1] : null);
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    public SLHDSAImpl(String parameterSet, int hashAlgorithm, byte[] publicKey, byte[] privateKey) {
        super(initContext(parameterSet), CryptoNative::slhdsaFreeContext);
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
        return CryptoNative.slhdsaCreateContext(parameterSet);
    }

    void setKeys(byte[] publicKey, byte[] privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("At least one key must be non-null");
        }
        KeyMaterial keyMaterial = SensitiveDataUtil.copyKeyMaterial(publicKey, privateKey);
        boolean updated = false;
        try {
            CryptoNative.slhdsaSetKeys(nativeContext, keyMaterial.publicKey(), keyMaterial.privateKey());
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
