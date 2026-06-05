package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class RSAPublicKeyImpl implements RSAPublicKey {
    private static final long serialVersionUID = 1234567L;
    private final BigInteger modulus;
    private final BigInteger publicExponent;

    public RSAPublicKeyImpl(byte[] modulus, BigInteger publicExponent) {
        this.modulus = RSAKeyUtil.fromUnsignedBytes(modulus, "modulus");
        this.publicExponent = publicExponent;
    }

    public RSAPublicKeyImpl(BigInteger modulus, BigInteger publicExponent) {
        this.modulus = Objects.requireNonNull(modulus, "RSA modulus cannot be null");
        this.publicExponent = Objects.requireNonNull(publicExponent, "RSA public exponent cannot be null");
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        try {
            return RSAKeyCodec.encodePublic(modulus, publicExponent);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode RSA public key", e);
        }
    }
} 
