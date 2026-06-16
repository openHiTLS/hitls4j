package org.openhitls.crypto.jce.key.factory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.math.BigInteger;

import org.openhitls.crypto.jce.key.RSAKeyCodec;
import org.openhitls.crypto.jce.key.RSAKeyUtil;
import org.openhitls.crypto.jce.key.RSAPrivateCrtKeyImpl;
import org.openhitls.crypto.jce.key.RSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.RSAPublicKeyImpl;

public class RSAKeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("RSA public key specification cannot be null");
        }

        if (keySpec instanceof RSAPublicKeySpec) {
            RSAPublicKeySpec rsaSpec = (RSAPublicKeySpec) keySpec;
            validatePublicParameters(rsaSpec.getModulus(), rsaSpec.getPublicExponent());
            return new RSAPublicKeyImpl(rsaSpec.getModulus(), rsaSpec.getPublicExponent());
        }

        if (keySpec instanceof X509EncodedKeySpec) {
            BigInteger[] rsaKey = parsePublicKey((X509EncodedKeySpec) keySpec);
            validatePublicParameters(rsaKey[0], rsaKey[1]);
            return new RSAPublicKeyImpl(rsaKey[0], rsaKey[1]);
        }

        throw new InvalidKeySpecException("Unsupported RSA public key specification: "
                + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("RSA private key specification cannot be null");
        }

        if (keySpec instanceof RSAPrivateCrtKeySpec) {
            RSAPrivateCrtKeySpec rsaSpec = (RSAPrivateCrtKeySpec) keySpec;
            validatePrivateCrtParameters(rsaSpec.getModulus(), rsaSpec.getPrivateExponent(),
                    rsaSpec.getPublicExponent(), rsaSpec.getPrimeP(), rsaSpec.getPrimeQ(),
                    rsaSpec.getPrimeExponentP(), rsaSpec.getPrimeExponentQ(), rsaSpec.getCrtCoefficient());
            return new RSAPrivateCrtKeyImpl(rsaSpec.getModulus(), rsaSpec.getPrivateExponent(),
                    rsaSpec.getPublicExponent(), rsaSpec.getPrimeP(), rsaSpec.getPrimeQ(),
                    rsaSpec.getPrimeExponentP(), rsaSpec.getPrimeExponentQ(), rsaSpec.getCrtCoefficient());
        }

        if (keySpec instanceof RSAPrivateKeySpec) {
            RSAPrivateKeySpec rsaSpec = (RSAPrivateKeySpec) keySpec;
            validatePrivateParameters(rsaSpec.getModulus(), rsaSpec.getPrivateExponent());
            return new RSAPrivateKeyImpl(rsaSpec.getModulus(), rsaSpec.getPrivateExponent());
        }

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            BigInteger[] rsaKey = parsePrivateKey((PKCS8EncodedKeySpec) keySpec);
            if (rsaKey.length == 3) {
                validatePrivateParameters(rsaKey[0], rsaKey[1]);
                requireUnsignedParameter("public exponent", rsaKey[2]);
                return new RSAPrivateKeyImpl(rsaKey[0], rsaKey[1], rsaKey[2]);
            }
            if (rsaKey.length == 8) {
                validatePrivateCrtParameters(rsaKey[0], rsaKey[1], rsaKey[2],
                        rsaKey[3], rsaKey[4], rsaKey[5], rsaKey[6], rsaKey[7]);
                return new RSAPrivateCrtKeyImpl(rsaKey[0], rsaKey[1], rsaKey[2],
                        rsaKey[3], rsaKey[4], rsaKey[5], rsaKey[6], rsaKey[7]);
            }
            throw new InvalidKeySpecException("Invalid PKCS#8 RSA private key parameter count");
        }

        throw new InvalidKeySpecException("Unsupported RSA private key specification: "
                + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("RSA key specification cannot be null");
        }
        if (key == null) {
            throw new InvalidKeySpecException("RSA key cannot be null");
        }

        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;
            if (keySpec.isAssignableFrom(RSAPublicKeySpec.class)) {
                return keySpec.cast(new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()));
            }
            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                byte[] encoded;
                try {
                    encoded = key.getEncoded();
                } catch (RuntimeException e) {
                    throw new InvalidKeySpecException("RSA public key cannot be X.509 encoded", e);
                }
                if (encoded == null) {
                    throw new InvalidKeySpecException("RSA public key cannot be X.509 encoded");
                }
                return keySpec.cast(new X509EncodedKeySpec(encoded));
            }
        }

        if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaKey = (RSAPrivateKey) key;
            if (RSAPrivateCrtKeySpec.class.isAssignableFrom(keySpec)) {
                if (!(key instanceof RSAPrivateCrtKey)) {
                    throw new InvalidKeySpecException("RSA private key does not contain CRT parameters");
                }
                RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
                return keySpec.cast(new RSAPrivateCrtKeySpec(crtKey.getModulus(), crtKey.getPublicExponent(),
                        crtKey.getPrivateExponent(), crtKey.getPrimeP(), crtKey.getPrimeQ(),
                        crtKey.getPrimeExponentP(), crtKey.getPrimeExponentQ(), crtKey.getCrtCoefficient()));
            }
            if (keySpec.isAssignableFrom(RSAPrivateKeySpec.class)) {
                return keySpec.cast(new RSAPrivateKeySpec(rsaKey.getModulus(), rsaKey.getPrivateExponent()));
            }
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] encoded;
                try {
                    encoded = key.getEncoded();
                } catch (RuntimeException e) {
                    throw new InvalidKeySpecException("RSA private key cannot be PKCS#8 encoded", e);
                }
                if (encoded == null) {
                    throw new InvalidKeySpecException("RSA private key cannot be PKCS#8 encoded");
                }
                return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
            }
        }

        throw new InvalidKeySpecException("Unsupported RSA key or key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("RSA key cannot be null");
        }

        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) key;
            return new RSAPublicKeyImpl(rsaKey.getModulus(), rsaKey.getPublicExponent());
        }
        if (key instanceof RSAPrivateKey) {
            if (key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
                return new RSAPrivateCrtKeyImpl(rsaKey.getModulus(), rsaKey.getPrivateExponent(),
                        rsaKey.getPublicExponent(), rsaKey.getPrimeP(), rsaKey.getPrimeQ(),
                        rsaKey.getPrimeExponentP(), rsaKey.getPrimeExponentQ(), rsaKey.getCrtCoefficient());
            }
            RSAPrivateKey rsaKey = (RSAPrivateKey) key;
            return new RSAPrivateKeyImpl(rsaKey.getModulus(), rsaKey.getPrivateExponent(),
                    RSAKeyUtil.getPublicExponent(rsaKey));
        }

        throw new InvalidKeyException("Unsupported RSA key type: " + key.getClass().getName());
    }

    private static BigInteger[] parsePublicKey(X509EncodedKeySpec keySpec) throws InvalidKeySpecException {
        try {
            return RSAKeyCodec.decodePublic(keySpec.getEncoded());
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid X.509 RSA public key", e);
        }
    }

    private static BigInteger[] parsePrivateKey(PKCS8EncodedKeySpec keySpec) throws InvalidKeySpecException {
        try {
            return RSAKeyCodec.decodePrivate(keySpec.getEncoded());
        } catch (Exception e) {
            throw new InvalidKeySpecException("Invalid PKCS#8 RSA private key", e);
        }
    }

    private static void validatePublicParameters(BigInteger modulus, BigInteger publicExponent)
            throws InvalidKeySpecException {
        requireUnsignedParameter("modulus", modulus);
        requireUnsignedParameter("public exponent", publicExponent);
    }

    private static void validatePrivateParameters(BigInteger modulus, BigInteger privateExponent)
            throws InvalidKeySpecException {
        requireUnsignedParameter("modulus", modulus);
        requireUnsignedParameter("private exponent", privateExponent);
    }

    private static void validatePrivateCrtParameters(BigInteger modulus, BigInteger privateExponent,
            BigInteger publicExponent, BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP,
            BigInteger primeExponentQ, BigInteger crtCoefficient) throws InvalidKeySpecException {
        validatePrivateParameters(modulus, privateExponent);
        requireUnsignedParameter("public exponent", publicExponent);
        requireUnsignedParameter("prime P", primeP);
        requireUnsignedParameter("prime Q", primeQ);
        requireUnsignedParameter("prime exponent P", primeExponentP);
        requireUnsignedParameter("prime exponent Q", primeExponentQ);
        requireUnsignedParameter("CRT coefficient", crtCoefficient);
    }

    private static void requireUnsignedParameter(String name, BigInteger value) throws InvalidKeySpecException {
        if (value == null) {
            throw new InvalidKeySpecException("RSA " + name + " cannot be null");
        }
        if (value.signum() <= 0) {
            throw new InvalidKeySpecException("RSA " + name + " must be positive");
        }
    }
}
