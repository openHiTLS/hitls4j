package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class RSAPrivateKeyImpl implements RSAPrivateKey {
    private static final long serialVersionUID = 1234567L;
    private final BigInteger modulus;
    private final BigInteger privateExponent;

    public RSAPrivateKeyImpl(byte[] privateExponent, byte[] modulus) {
        // Remove leading zeros if present
        if (privateExponent[0] == 0) {
            byte[] tmp = new byte[privateExponent.length - 1];
            System.arraycopy(privateExponent, 1, tmp, 0, tmp.length);
            this.privateExponent = new BigInteger(1, tmp);
        } else {
            this.privateExponent = new BigInteger(1, privateExponent);
        }

        if (modulus[0] == 0) {
            byte[] tmp = new byte[modulus.length - 1];
            System.arraycopy(modulus, 1, tmp, 0, tmp.length);
            this.modulus = new BigInteger(1, tmp);
        } else {
            this.modulus = new BigInteger(1, modulus);
        }
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        // For now, return null as we don't need the encoded form
        return null;
    }
} 