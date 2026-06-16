package org.openhitls.crypto.jce.key;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

public class RSAPrivateCrtKeyImpl extends RSAPrivateKeyImpl implements RSAPrivateCrtKey {
    private static final long serialVersionUID = 1234568L;

    public RSAPrivateCrtKeyImpl(byte[] privateExponent, byte[] modulus, BigInteger publicExponent,
            byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ, byte[] crtCoefficient) {
        super(privateExponent, modulus, publicExponent,
                primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
    }

    public RSAPrivateCrtKeyImpl(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent,
            BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ,
            BigInteger crtCoefficient) {
        super(modulus, privateExponent, publicExponent,
                primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
    }

    @Override
    public BigInteger getPrimeP() {
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        return primeQ;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return primeExponentQ;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        return crtCoefficient;
    }
}
