package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.util.Arrays;

import org.openhitls.crypto.core.CryptoNative;

public final class RSAKeyCodec {
    private RSAKeyCodec() {
    }

    public static byte[] encodePublic(BigInteger modulus, BigInteger publicExponent) {
        return CryptoNative.rsaEncodePublicKey(RSAKeyUtil.toUnsignedBytes(modulus),
                RSAKeyUtil.toUnsignedBytes(publicExponent));
    }

    public static byte[] encodePrivate(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent,
            BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ,
            BigInteger crtCoefficient) {
        if (publicExponent == null) {
            throw new IllegalArgumentException("RSA private key public exponent cannot be null");
        }
        byte[] modulusBytes = null;
        byte[] privateExponentBytes = null;
        byte[] publicExponentBytes = null;
        byte[] primePBytes = null;
        byte[] primeQBytes = null;
        byte[] primeExponentPBytes = null;
        byte[] primeExponentQBytes = null;
        byte[] crtCoefficientBytes = null;
        try {
            modulusBytes = RSAKeyUtil.toUnsignedBytes(modulus);
            privateExponentBytes = RSAKeyUtil.toUnsignedBytes(privateExponent);
            publicExponentBytes = RSAKeyUtil.toUnsignedBytes(publicExponent);
            primePBytes = toNullableUnsignedBytes(primeP);
            primeQBytes = toNullableUnsignedBytes(primeQ);
            primeExponentPBytes = toNullableUnsignedBytes(primeExponentP);
            primeExponentQBytes = toNullableUnsignedBytes(primeExponentQ);
            crtCoefficientBytes = toNullableUnsignedBytes(crtCoefficient);
            return CryptoNative.rsaEncodePrivateKey(modulusBytes, privateExponentBytes, publicExponentBytes,
                    primePBytes, primeQBytes, primeExponentPBytes, primeExponentQBytes, crtCoefficientBytes);
        } finally {
            clear(privateExponentBytes);
            clear(primePBytes);
            clear(primeQBytes);
            clear(primeExponentPBytes);
            clear(primeExponentQBytes);
            clear(crtCoefficientBytes);
        }
    }

    public static BigInteger[] decodePublic(byte[] x509EncodedKey) {
        byte[][] key = CryptoNative.rsaDecodePublicKey(x509EncodedKey);
        if (key == null || key.length != 2) {
            throw new IllegalStateException("Invalid decoded RSA public key");
        }
        return new BigInteger[] {
            new BigInteger(1, key[0]),
            new BigInteger(1, key[1])
        };
    }

    public static BigInteger[] decodePrivate(byte[] pkcs8EncodedKey) {
        byte[][] key = CryptoNative.rsaDecodePrivateKey(pkcs8EncodedKey);
        try {
            if (key == null || (key.length != 3 && key.length != 8)) {
                throw new IllegalStateException("Invalid decoded RSA private key");
            }
            BigInteger[] result = new BigInteger[key.length];
            for (int i = 0; i < key.length; i++) {
                result[i] = new BigInteger(1, key[i]);
            }
            return result;
        } finally {
            clearAll(key);
        }
    }

    private static byte[] toNullableUnsignedBytes(BigInteger value) {
        return value == null ? null : RSAKeyUtil.toUnsignedBytes(value);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static void clearAll(byte[][] values) {
        if (values == null) {
            return;
        }
        for (byte[] value : values) {
            clear(value);
        }
    }
}
