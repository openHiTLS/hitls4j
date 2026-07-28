package org.openhitls.crypto.core.asymmetric;

import java.security.SignatureException;
import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.core.NativeResourceUtil;
import org.openhitls.crypto.core.SensitiveDataUtil;
import org.openhitls.crypto.core.SensitiveDataUtil.KeyMaterial;
import org.openhitls.crypto.jce.signer.RSAPadding;
import org.openhitls.crypto.jce.signer.RSAPadding.PSSParameterSpec;

public class RSAImpl extends NativeResource {
    private boolean parametersSet = false;
    private String digestAlgorithm = "SHA256"; // Default to SHA256
    private int paddingMode = RSAPadding.PADDING_PKCS1;
    private PSSParameterSpec pssParams;

    public RSAImpl() {
        super(CryptoNative.rsaCreateContext(), RSAImpl::freeNativeContext);
    }

    public RSAImpl(byte[] publicKey, byte[] privateKey, byte[] publicExponent) {
        super(createContextForKeys(publicKey, privateKey, publicExponent), RSAImpl::freeNativeContext);
        try {
            if (privateKey != null) {
                setPrivateKey(publicKey, privateKey, publicExponent);
            }
            if (publicKey != null) {
                setPublicKey(publicKey, publicExponent);
            }
        } catch (RuntimeException | Error e) {
            NativeResourceUtil.closeSuppressing(this, e);
            throw e;
        }
    }

    private static void freeNativeContext(long nativeContext) {
        if (nativeContext != 0) {
            CryptoNative.rsaFreeContext(nativeContext);
        }
    }

    public void setPublicKey(byte[] modulus, byte[] publicExponent) {
        requirePublicKeyComponents(modulus, publicExponent);
        CryptoNative.rsaSetPublicKey(nativeContext, modulus, publicExponent);
    }

    public void setPrivateKey(byte[] modulus, byte[] privateExponent, byte[] publicExponent,
            byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ,
            byte[] crtCoefficient) {
        requireCrtKeyComponents(modulus, privateExponent, publicExponent, primeP, primeQ,
                primeExponentP, primeExponentQ, crtCoefficient);
        setPrivateKeyInternal(modulus, privateExponent, publicExponent, primeP, primeQ,
                primeExponentP, primeExponentQ, crtCoefficient);
    }

    public void setPrivateKey(byte[] modulus, byte[] privateExponent, byte[] publicExponent) {
        requirePrivateKeyComponents(modulus, privateExponent, publicExponent);
        setPrivateKeyInternal(modulus, privateExponent, publicExponent,
                null, null, null, null, null);
    }

    private void setPrivateKeyInternal(byte[] modulus, byte[] privateExponent, byte[] publicExponent,
            byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ,
            byte[] crtCoefficient) {
        KeyMaterial keyMaterial = SensitiveDataUtil.copyKeyMaterial(modulus, privateExponent);
        try {
            CryptoNative.rsaSetPrivateKey(nativeContext, keyMaterial.publicKey(), keyMaterial.privateKey(),
                    publicExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
        } finally {
            keyMaterial.clearPrivate();
        }
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

    public byte[] signDigest(byte[] digest) throws SignatureException {
        if (paddingMode == RSAPadding.PADDING_PSS && pssParams != null) {
            return CryptoNative.rsaSignDigestPSS(nativeContext, digest, digestAlgorithm,
                pssParams.getMGF1HashAlgorithm(), pssParams.getSaltLength(), pssParams.getTrailerField());
        }
        return CryptoNative.rsaSignDigest(nativeContext, digest, digestAlgorithm);
    }

    public boolean verifyDigest(byte[] digest, byte[] signature) throws SignatureException {
        if (paddingMode == RSAPadding.PADDING_PSS && pssParams != null) {
            return CryptoNative.rsaVerifyDigestPSS(nativeContext, digest, signature, digestAlgorithm,
                pssParams.getMGF1HashAlgorithm(), pssParams.getSaltLength(), pssParams.getTrailerField());
        }
        return CryptoNative.rsaVerifyDigest(nativeContext, digest, signature, digestAlgorithm);
    }

    public byte[] encrypt(byte[] data) {
        return CryptoNative.rsaEncrypt(nativeContext, data);
    }

    public byte[] decrypt(byte[] encryptedData) {
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

    private static long createContextForKeys(byte[] publicKey, byte[] privateKey, byte[] publicExponent) {
        if (privateKey != null) {
            requirePrivateKeyComponents(publicKey, privateKey, publicExponent);
        } else if (publicKey != null) {
            requirePublicKeyComponents(publicKey, publicExponent);
        }
        return CryptoNative.rsaCreateContext();
    }

    private static void requirePublicKeyComponents(byte[] modulus, byte[] publicExponent) {
        if (modulus == null || modulus.length == 0
                || publicExponent == null || publicExponent.length == 0) {
            throw new IllegalArgumentException("RSA public key components cannot be null or empty");
        }
    }

    private static void requireCrtKeyComponents(byte[] modulus, byte[] privateExponent,
            byte[] publicExponent, byte[] primeP, byte[] primeQ, byte[] primeExponentP,
            byte[] primeExponentQ, byte[] crtCoefficient) {
        requirePrivateKeyComponents(modulus, privateExponent, publicExponent);
        if (primeP == null || primeP.length == 0 || primeQ == null || primeQ.length == 0) {
            throw new IllegalArgumentException("RSA CRT primes cannot be null or empty");
        }

        boolean derivedCrtValuesOmitted = primeExponentP == null
                && primeExponentQ == null && crtCoefficient == null;
        if (!derivedCrtValuesOmitted
                && (primeExponentP == null || primeExponentP.length == 0
                || primeExponentQ == null || primeExponentQ.length == 0
                || crtCoefficient == null || crtCoefficient.length == 0)) {
            throw new IllegalArgumentException(
                    "RSA CRT exponents and coefficient must be all provided or all omitted");
        }
    }

    private static void requirePrivateKeyComponents(
            byte[] modulus, byte[] privateExponent, byte[] publicExponent) {
        if (modulus == null || modulus.length == 0
                || privateExponent == null || privateExponent.length == 0
                || publicExponent == null || publicExponent.length == 0) {
            throw new IllegalArgumentException("RSA private key components cannot be null or empty");
        }
    }

}
