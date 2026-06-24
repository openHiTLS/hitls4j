package org.openhitls.crypto.jce.key;

import java.security.spec.*;
import java.math.BigInteger;
import java.util.Arrays;

import org.openhitls.crypto.jce.util.ECKeyEncoding;

public class ECPrivateKey implements java.security.interfaces.ECPrivateKey {
    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ALGORITHM = "EC";
    private final byte[] keyBytes;
    private final ECParameterSpec params;
    private final String algorithm;
    private BigInteger s;  // Cache the private value to avoid repeated computation

    public ECPrivateKey(byte[] keyBytes) {
        this(keyBytes, null, DEFAULT_ALGORITHM);
    }

    public ECPrivateKey(byte[] keyBytes, String algorithm) {
        this(keyBytes, null, algorithm);
    }

    public ECPrivateKey(byte[] keyBytes, ECParameterSpec params) {
        this(keyBytes, params, DEFAULT_ALGORITHM);
    }

    public ECPrivateKey(byte[] keyBytes, ECParameterSpec params, String algorithm) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
        this.algorithm = normalizeAlgorithm(algorithm);
        this.s = null;
    }

    public ECPrivateKey(BigInteger s, ECParameterSpec params) {
        this(s, params, DEFAULT_ALGORITHM);
    }

    public ECPrivateKey(BigInteger s, ECParameterSpec params, String algorithm) {
        validatePrivateValue(s, params);
        this.s = s;
        int fieldSize = (params.getCurve().getField().getFieldSize() + 7) / 8;
        
        this.keyBytes = toFixedLengthUnsigned(s, fieldSize);
        this.params = params;
        this.algorithm = normalizeAlgorithm(algorithm);
    }

    private static void validatePrivateValue(BigInteger s, ECParameterSpec params) {
        try {
            ECKeyEncoding.validatePrivateValue(s, params);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private static byte[] toFixedLengthUnsigned(BigInteger value, int fieldSize) {
        byte[] valueBytes = value.toByteArray();
        byte[] unsigned = valueBytes;
        try {
            if (valueBytes.length == fieldSize + 1 && valueBytes[0] == 0) {
                unsigned = Arrays.copyOfRange(valueBytes, 1, valueBytes.length);
            }
            if (unsigned.length > fieldSize) {
                throw new IllegalArgumentException("EC private value is too large");
            }

            byte[] encoded = new byte[fieldSize];
            System.arraycopy(unsigned, 0, encoded, fieldSize - unsigned.length, unsigned.length);
            return encoded;
        } finally {
            Arrays.fill(valueBytes, (byte) 0);
            if (unsigned != valueBytes) {
                Arrays.fill(unsigned, (byte) 0);
            }
        }
    }

    public ECParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return params != null ? "PKCS#8" : null;
    }

    @Override
    public byte[] getEncoded() {
        if (params == null) {
            return null;
        }
        try {
            return ECKeyCodec.encodePrivate(getS(), params);
        } catch (InvalidKeySpecException | RuntimeException e) {
            throw new IllegalStateException("Failed to encode EC private key", e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECPrivateKey that = (ECPrivateKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }

    @Override
    public BigInteger getS() {
        if (s == null && keyBytes != null) {
            s = new BigInteger(1, keyBytes);
        }
        return s;
    }

    private static String normalizeAlgorithm(String algorithm) {
        return algorithm == null ? DEFAULT_ALGORITHM : algorithm;
    }
}
