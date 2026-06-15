package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class RSAPublicKeyImpl implements RSAPublicKey {
    private static final long serialVersionUID = 1234567L;
    private final BigInteger modulus;
    private final BigInteger publicExponent;

    public RSAPublicKeyImpl(byte[] modulus, BigInteger publicExponent) {
        // Remove leading zero if present
        if (modulus[0] == 0) {
            byte[] tmp = new byte[modulus.length - 1];
            System.arraycopy(modulus, 1, tmp, 0, tmp.length);
            this.modulus = new BigInteger(1, tmp);
        } else {
            this.modulus = new BigInteger(1, modulus);
        }
        this.publicExponent = publicExponent;
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
        // For now, return null as we don't need the encoded form
        return null;
    }
} 