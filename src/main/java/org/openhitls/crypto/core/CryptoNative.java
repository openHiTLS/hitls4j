package org.openhitls.crypto.core;

public class CryptoNative {
    // Hash native methods
    public static native long messageDigestInit(String algorithm);
    public static native void messageDigestUpdate(long contextPtr, byte[] data, int offset, int length);
    public static native byte[] messageDigestFinal(long contextPtr);
    public static native void messageDigestFree(long contextPtr);

    // HMAC native methods
    public static native long hmacInit(String algorithm, byte[] key);
    public static native void hmacUpdate(long contextPtr, byte[] data, int offset, int length);
    public static native byte[] hmacFinal(long contextPtr);
    public static native void hmacReinit(long contextPtr);
    public static native int hmacGetMacLength(long contextPtr);
    public static native void hmacFree(long contextPtr);

    // ECDSA native methods
    public static native long ecdsaCreateContext(String curveName);
    public static native void ecdsaFreeContext(long nativeRef);
    public static native void ecdsaSetKeys(long nativeRef, String curveName, byte[] publicKey, byte[] privateKey);
    public static native void ecdsaSetUserId(long nativeRef, byte[] userId);
    public static native byte[][] ecdsaGenerateKeyPair(long nativeRef, String curveName);
    public static native byte[] ecdsaEncrypt(long nativeRef, byte[] data);
    public static native byte[] ecdsaDecrypt(long nativeRef, byte[] encryptedData);
    public static native byte[] ecdsaSign(long nativeRef, byte[] data, int hashAlg);
    public static native boolean ecdsaVerify(long nativeRef, byte[] data, byte[] signature, int hashAlg);

    // SM4 native methods
    public static native long symmetricCipherInit(String algorithm, String cipherMode, byte[] key, byte[] iv, int mode);
    public static native void symmetricCipherSetPadding(long contextPtr, int paddingType);
    public static native void symmetricCipherUpdate(long contextPtr, byte[] input, int inputOffset, int inputLen,
                                             byte[] output, int outputOffset, int[] outLen);
    public static native byte[] symmetricCipherFinal(long contextPtr);
    public static native void symmetricCipherFree(long contextPtr);

    // DSA native methods
    public static native long dsaCreateContext();
    public static native void dsaFreeContext(long nativeRef);
    public static native void dsaSetParameters(long nativeRef, byte[] p, byte[] q, byte[] g);
    public static native void dsaSetKeys(long nativeRef, byte[] publicKey, byte[] privateKey);
    public static native byte[][] dsaGenerateKeyPair(long nativeRef);
    public static native byte[] dsaSign(long nativeRef, byte[] data, int hashAlg);
    public static native boolean dsaVerify(long nativeRef, byte[] data, byte[] signature, int hashAlg);

    // RSA native methods
    public static native long rsaCreateContext();
    public static native void rsaFreeContext(long nativeRef);
    public static native void rsaSetParameters(long nativeRef, byte[] e, int keyBits);
    public static native void rsaSetKeys(long nativeRef, byte[] publicKey, byte[] privateKey);
    public static native void rsaSetPadding(long nativeRef, int paddingMode);
    public static native byte[][] rsaGenerateKeyPair(long nativeRef);
    public static native byte[] rsaSign(long nativeRef, byte[] data, String digestAlgorithm);
    public static native boolean rsaVerify(long nativeRef, byte[] data, byte[] signature, String digestAlgorithm);
    public static native byte[] rsaEncrypt(long nativeRef, byte[] data);
    public static native byte[] rsaDecrypt(long nativeRef, byte[] encryptedData);
    
    // Add PSS support
    public static native byte[] rsaSignPSS(long nativeRef, byte[] data, String digestAlgorithm,
                                         String mgf1Algorithm, int saltLength, int trailerField);
    public static native boolean rsaVerifyPSS(long nativeRef, byte[] data, byte[] signature,
                                            String digestAlgorithm, String mgf1Algorithm,
                                            int saltLength, int trailerField);
} 