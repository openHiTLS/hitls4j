package org.openhitls.crypto.jce.key;

import java.security.spec.*;
import java.util.Arrays;
import java.math.BigInteger;

import org.openhitls.crypto.jce.util.ECKeyEncoding;

public class ECPublicKey implements java.security.interfaces.ECPublicKey {
    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_ALGORITHM = "EC";
    private final byte[] keyBytes;
    private final ECParameterSpec params;
    private final String algorithm;
    private ECPoint w;  // Cache the ECPoint to avoid repeated computation

    public ECPublicKey(byte[] keyBytes) {
        this(keyBytes, null, DEFAULT_ALGORITHM);
    }

    public ECPublicKey(byte[] keyBytes, String algorithm) {
        this(keyBytes, null, algorithm);
    }

    public ECPublicKey(byte[] keyBytes, ECParameterSpec params) {
        this(keyBytes, params, DEFAULT_ALGORITHM);
    }

    public ECPublicKey(byte[] keyBytes, ECParameterSpec params, String algorithm) {
        this.keyBytes = keyBytes.clone();
        this.params = params;
        this.algorithm = normalizeAlgorithm(algorithm);
        this.w = null;
    }

    public ECPublicKey(ECPoint w, ECParameterSpec params) {
        this(w, params, DEFAULT_ALGORITHM);
    }

    public ECPublicKey(ECPoint w, ECParameterSpec params, String algorithm) {
        this.w = w;
        try {
            this.keyBytes = ECKeyEncoding.encodePublicPoint(w, params);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        this.params = params;
        this.algorithm = normalizeAlgorithm(algorithm);
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
        return params != null ? "X.509" : null;
    }

    @Override
    public byte[] getEncoded() {
        if (params == null) {
            return null;
        }
        try {
            return ECKeyCodec.encodePublic(getW(), params);
        } catch (InvalidKeySpecException | RuntimeException e) {
            throw new IllegalStateException("Failed to encode EC public key", e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECPublicKey that = (ECPublicKey) o;
        return Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }

    @Override
    public ECPoint getW() {
        if (w == null && keyBytes != null) {
            // Convert from encoded format (0x04 || X || Y)
            if (keyBytes[0] != 0x04) {
                throw new IllegalStateException("Invalid public key encoding");
            }

            int fieldSize = (keyBytes.length - 1) / 2;
            byte[] x = Arrays.copyOfRange(keyBytes, 1, 1 + fieldSize);
            byte[] y = Arrays.copyOfRange(keyBytes, 1 + fieldSize, keyBytes.length);

            w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        }
        return w;
    }

    private static String normalizeAlgorithm(String algorithm) {
        return algorithm == null ? DEFAULT_ALGORITHM : algorithm;
    }
}
