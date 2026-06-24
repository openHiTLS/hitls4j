package org.openhitls.crypto.jce.util;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public final class ECKeyEncoding {
    private ECKeyEncoding() {
    }

    public static byte[] encodePublicPoint(ECPoint point, ECParameterSpec params)
            throws InvalidKeySpecException {
        if (point == null || ECPoint.POINT_INFINITY.equals(point)) {
            throw new InvalidKeySpecException("Invalid EC public point");
        }
        int fieldSize = ECUtil.getFieldSize(params);
        byte[] encoded = new byte[1 + 2 * fieldSize];
        encoded[0] = 0x04;
        byte[] x = toFixedLength(point.getAffineX(), fieldSize);
        byte[] y = toFixedLength(point.getAffineY(), fieldSize);
        System.arraycopy(x, 0, encoded, 1, fieldSize);
        System.arraycopy(y, 0, encoded, 1 + fieldSize, fieldSize);
        return encoded;
    }

    public static ECPoint decodePublicPoint(byte[] encoded, ECParameterSpec params)
            throws InvalidKeySpecException {
        int fieldSize = ECUtil.getFieldSize(params);
        if (encoded == null || encoded.length != 1 + 2 * fieldSize || encoded[0] != 0x04) {
            throw new InvalidKeySpecException("Only uncompressed EC public keys are supported");
        }
        return new ECPoint(
                new BigInteger(1, Arrays.copyOfRange(encoded, 1, 1 + fieldSize)),
                new BigInteger(1, Arrays.copyOfRange(encoded, 1 + fieldSize, encoded.length)));
    }

    public static byte[] encodePrivateValue(BigInteger privateValue, ECParameterSpec params)
            throws InvalidKeySpecException {
        validatePrivateValue(privateValue, params);
        return toFixedLength(privateValue, ECUtil.getFieldSize(params));
    }

    public static void validatePrivateValue(BigInteger privateValue, ECParameterSpec params)
            throws InvalidKeySpecException {
        if (params == null) {
            throw new InvalidKeySpecException("EC parameters cannot be null");
        }
        if (privateValue == null || privateValue.signum() <= 0) {
            throw new InvalidKeySpecException("EC private value must be positive");
        }
        if (privateValue.compareTo(params.getOrder()) >= 0) {
            throw new InvalidKeySpecException("EC private value must be less than the curve order");
        }
    }

    public static String getCurveName(ECParameterSpec params) throws InvalidKeySpecException {
        if (params == null) {
            throw new InvalidKeySpecException("Key parameters cannot be null");
        }
        try {
            return ECCurveRegistry.canonicalName(ECUtil.getCurveName(params));
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }
    }

    private static byte[] toFixedLength(BigInteger value, int length) throws InvalidKeySpecException {
        if (value == null || value.signum() < 0) {
            throw new InvalidKeySpecException("Invalid EC integer value");
        }
        byte[] bytes = value.toByteArray();
        byte[] unsigned = bytes.length > 1 && bytes[0] == 0
                ? Arrays.copyOfRange(bytes, 1, bytes.length)
                : bytes;
        try {
            if (unsigned.length > length) {
                throw new InvalidKeySpecException("EC integer value is too large");
            }
            byte[] fixed = new byte[length];
            System.arraycopy(unsigned, 0, fixed, length - unsigned.length, unsigned.length);
            return fixed;
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (unsigned != bytes) {
                Arrays.fill(unsigned, (byte) 0);
            }
        }
    }
}
