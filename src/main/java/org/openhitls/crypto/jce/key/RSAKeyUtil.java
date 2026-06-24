package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public final class RSAKeyUtil {
    private RSAKeyUtil() {
    }

    public static BigInteger getPublicExponent(RSAPublicKey key) {
        return key.getPublicExponent();
    }

    public static BigInteger getPublicExponent(RSAPrivateKey key) {
        if (key instanceof RSAPrivateKeyImpl) {
            BigInteger publicExponent = ((RSAPrivateKeyImpl) key).getPublicExponent();
            if (publicExponent != null) {
                return publicExponent;
            }
        }
        if (key instanceof RSAPrivateCrtKey) {
            BigInteger publicExponent = ((RSAPrivateCrtKey) key).getPublicExponent();
            if (publicExponent != null) {
                return publicExponent;
            }
        }
        return null;
    }

    public static BigInteger requirePublicExponent(RSAPrivateKey key) throws InvalidKeyException {
        BigInteger publicExponent = getPublicExponent(key);
        if (publicExponent == null) {
            throw new InvalidKeyException("RSA private key public exponent cannot be null");
        }
        return publicExponent;
    }

    public static byte[] toUnsignedBytes(BigInteger value) {
        if (value == null) {
            throw new IllegalArgumentException("RSA value cannot be null");
        }
        if (value.signum() <= 0) {
            throw new IllegalArgumentException("RSA value must be positive");
        }
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] unsigned = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, unsigned, 0, unsigned.length);
            Arrays.fill(bytes, (byte) 0);
            return unsigned;
        }
        return bytes;
    }

    static BigInteger fromUnsignedBytes(byte[] value, String name) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException("RSA " + name + " cannot be null or empty");
        }
        return new BigInteger(1, value);
    }
}
