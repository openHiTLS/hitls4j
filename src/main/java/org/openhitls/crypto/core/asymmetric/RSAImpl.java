package org.openhitls.crypto.core.asymmetric;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.signer.RSAPadding;
import org.openhitls.crypto.jce.signer.RSAPadding.PSSParameterSpec;

public class RSAImpl extends NativeResource {
    private boolean parametersSet = false;
    private byte[] publicKey;
    private byte[] privateKey;
    private String digestAlgorithm = "SHA256"; // Default to SHA256
    private int paddingMode = RSAPadding.PADDING_PKCS1;
    private PSSParameterSpec pssParams;

    public RSAImpl() {
        super(CryptoNative.rsaCreateContext(), RSAImpl::freeNativeContext);
    }

    public RSAImpl(byte[] publicKey, byte[] privateKey) {
        super(CryptoNative.rsaCreateContext(), RSAImpl::freeNativeContext);
        setKeys(publicKey, privateKey);
    }

    private static void freeNativeContext(long nativeContext) {
        if (nativeContext != 0) {
            CryptoNative.rsaFreeContext(nativeContext);
        }
    }

    public void setKeys(byte[] publicKey, byte[] privateKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : null;
        this.privateKey = privateKey != null ? privateKey.clone() : null;
        CryptoNative.rsaSetKeys(nativeContext, publicKey, privateKey);
    }

    public void setParameters(byte[] e, int keyBits) {
        if (e == null) {
            throw new IllegalArgumentException("RSA parameters cannot be null");
        }

        // Set parameters in native context
        CryptoNative.rsaSetParameters(nativeContext, e, keyBits);
        parametersSet = true;
    }

    public byte[][] generateKeyPair() {
        if (!parametersSet) {
            throw new IllegalStateException("RSA parameters must be set before generating key pair");
        }
        return CryptoNative.rsaGenerateKeyPair(nativeContext);
    }

    public byte[] sign(byte[] data) throws SignatureException {
        if (paddingMode == RSAPadding.PADDING_PSS && pssParams != null) {
            return CryptoNative.rsaSignPSS(nativeContext, data, digestAlgorithm, 
                pssParams.getMGF1HashAlgorithm(), pssParams.getSaltLength(), pssParams.getTrailerField());
        }
        return CryptoNative.rsaSign(nativeContext, data, digestAlgorithm);
    }

    public boolean verify(byte[] data, byte[] signature) throws SignatureException {
        if (paddingMode == RSAPadding.PADDING_PSS && pssParams != null) {
            return CryptoNative.rsaVerifyPSS(nativeContext, data, signature, digestAlgorithm,
                pssParams.getMGF1HashAlgorithm(), pssParams.getSaltLength(), pssParams.getTrailerField());
        }
        return CryptoNative.rsaVerify(nativeContext, data, signature, digestAlgorithm);
    }

    public byte[] encrypt(byte[] data) {
        if (publicKey == null) {
            throw new IllegalStateException("Public key must be set before encryption");
        }
        return CryptoNative.rsaEncrypt(nativeContext, data);
    }

    public byte[] decrypt(byte[] encryptedData) {
        if (privateKey == null) {
            throw new IllegalStateException("Private key must be set before decryption");
        }
        return CryptoNative.rsaDecrypt(nativeContext, encryptedData);
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        if (digestAlgorithm == null) {
            throw new IllegalArgumentException("Digest algorithm cannot be null");
        }
        this.digestAlgorithm = digestAlgorithm;
    }

    public void setPadding(int paddingMode) {
        this.paddingMode = paddingMode;
    }

    public void setPSSParameters(PSSParameterSpec params) {
        this.pssParams = params;
        this.paddingMode = RSAPadding.PADDING_PSS;
    }

    public byte[] getPublicKey() {
        return publicKey != null ? publicKey.clone() : null;
    }

    public byte[] getPrivateKey() {
        return privateKey != null ? privateKey.clone() : null;
    }
} 