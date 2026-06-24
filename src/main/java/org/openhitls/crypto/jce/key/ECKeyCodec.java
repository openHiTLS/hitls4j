package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.jce.util.ECKeyEncoding;

public final class ECKeyCodec {
    private ECKeyCodec() {
    }

    public static byte[] encodePublic(ECPoint point, ECParameterSpec params) throws InvalidKeySpecException {
        return CryptoNative.ecEncodePublicKey(
                ECKeyEncoding.getCurveName(params),
                ECKeyEncoding.encodePublicPoint(point, params));
    }

    public static byte[] encodePrivate(BigInteger privateValue, ECParameterSpec params)
            throws InvalidKeySpecException {
        byte[] encodedPrivate = ECKeyEncoding.encodePrivateValue(privateValue, params);
        try {
            return CryptoNative.ecEncodePrivateKey(ECKeyEncoding.getCurveName(params), encodedPrivate);
        } finally {
            clear(encodedPrivate);
        }
    }

    public static DecodedPublicKey decodePublic(byte[] x509EncodedKey) {
        byte[][] key = CryptoNative.ecDecodePublicKey(x509EncodedKey);
        if (key == null || key.length != 2) {
            throw new IllegalStateException("Invalid decoded EC public key");
        }
        return new DecodedPublicKey(curveName(key[0]), requireKeyMaterial(key[1], "public"));
    }

    public static DecodedPrivateKey decodePrivate(byte[] pkcs8EncodedKey) {
        byte[][] key = CryptoNative.ecDecodePrivateKey(pkcs8EncodedKey);
        if (key == null || key.length != 2) {
            throw new IllegalStateException("Invalid decoded EC private key");
        }
        try {
            return new DecodedPrivateKey(curveName(key[0]), new BigInteger(1, requireKeyMaterial(key[1], "private")));
        } finally {
            clear(key[1]);
        }
    }

    private static String curveName(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new IllegalStateException("Decoded EC key does not contain a curve name");
        }
        return new String(encoded, StandardCharsets.US_ASCII);
    }

    static byte[] requireKeyMaterial(byte[] encoded, String keyType) {
        if (encoded == null || encoded.length == 0) {
            throw new IllegalStateException("Decoded EC " + keyType + " key does not contain key material");
        }
        return encoded;
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    public static final class DecodedPublicKey {
        private final String curveName;
        private final byte[] publicKey;

        private DecodedPublicKey(String curveName, byte[] publicKey) {
            this.curveName = curveName;
            this.publicKey = publicKey.clone();
        }

        public String getCurveName() {
            return curveName;
        }

        public byte[] getPublicKey() {
            return publicKey.clone();
        }
    }

    public static final class DecodedPrivateKey {
        private final String curveName;
        private final BigInteger privateValue;

        private DecodedPrivateKey(String curveName, BigInteger privateValue) {
            this.curveName = curveName;
            this.privateValue = privateValue;
        }

        public String getCurveName() {
            return curveName;
        }

        public BigInteger getPrivateValue() {
            return privateValue;
        }
    }
}
