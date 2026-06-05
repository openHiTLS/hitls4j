package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Objects;

public class RSAPrivateKeyImpl implements RSAPrivateKey {
    private static final long serialVersionUID = 1234567L;
    protected final BigInteger modulus;
    protected final BigInteger privateExponent;
    protected final BigInteger publicExponent;
    protected final BigInteger primeP;
    protected final BigInteger primeQ;
    protected final BigInteger primeExponentP;
    protected final BigInteger primeExponentQ;
    protected final BigInteger crtCoefficient;

    public RSAPrivateKeyImpl(byte[] privateExponent, byte[] modulus) {
        this(privateExponent, modulus, null);
    }

    public RSAPrivateKeyImpl(byte[] privateExponent, byte[] modulus, BigInteger publicExponent) {
        this(privateExponent, modulus, publicExponent, null, null, null, null, null);
    }

    public RSAPrivateKeyImpl(byte[] privateExponent, byte[] modulus, BigInteger publicExponent,
            byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ, byte[] crtCoefficient) {
        this.privateExponent = RSAKeyUtil.fromUnsignedBytes(privateExponent, "private exponent");
        this.modulus = RSAKeyUtil.fromUnsignedBytes(modulus, "modulus");
        this.publicExponent = publicExponent;
        this.primeP = toBigInteger(primeP);
        this.primeQ = toBigInteger(primeQ);
        this.primeExponentP = toBigInteger(primeExponentP);
        this.primeExponentQ = toBigInteger(primeExponentQ);
        this.crtCoefficient = toBigInteger(crtCoefficient);
    }

    public RSAPrivateKeyImpl(BigInteger modulus, BigInteger privateExponent) {
        this(modulus, privateExponent, null);
    }

    public RSAPrivateKeyImpl(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {
        this(modulus, privateExponent, publicExponent, null, null, null, null, null);
    }

    public RSAPrivateKeyImpl(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent,
            BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ,
            BigInteger crtCoefficient) {
        this.modulus = Objects.requireNonNull(modulus, "RSA modulus cannot be null");
        this.privateExponent = Objects.requireNonNull(privateExponent, "RSA private exponent cannot be null");
        this.publicExponent = publicExponent;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.primeExponentP = primeExponentP;
        this.primeExponentQ = primeExponentQ;
        this.crtCoefficient = crtCoefficient;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return publicExponent == null ? null : "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        if (publicExponent == null) {
            return null;
        }
        try {
            return RSAKeyCodec.encodePrivate(modulus, privateExponent, publicExponent,
                    primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode RSA private key", e);
        }
    }

    private static BigInteger toBigInteger(byte[] value) {
        return value == null ? null : new BigInteger(1, value);
    }
}
