package org.openhitls.crypto.core.hash;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class MessageDigestImpl extends NativeResource {
    private final String algorithm;

    public MessageDigestImpl(String algorithm) {
        super(initContext(algorithm), CryptoNative::messageDigestFree);
        this.algorithm = algorithm;
    }

    private static long initContext(String algorithm) {
        return CryptoNative.messageDigestInit(algorithm);
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        CryptoNative.messageDigestUpdate(nativeContext, data, 0, data.length);
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (offset < 0 || length < 0 || length > data.length - offset) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        CryptoNative.messageDigestUpdate(nativeContext, data, offset, length);
    }

    public byte[] doFinal() {
        return CryptoNative.messageDigestFinal(nativeContext);
    }

    public byte[] digest(byte[] data) {
        update(data);
        return doFinal();
    }

    public static byte[] hash(String algorithm, byte[] data) {
        try (MessageDigestImpl md = new MessageDigestImpl(algorithm)) {
            return md.digest(data);
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
