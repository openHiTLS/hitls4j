package org.openhitls.crypto.jce.key.factory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.openhitls.crypto.jce.key.FrodoKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.FrodoKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;
import org.openhitls.crypto.jce.spec.FrodoKEMPrivateKeySpec;
import org.openhitls.crypto.jce.spec.FrodoKEMPublicKeySpec;

public class FrodoKEMKeyFactory extends KeyFactorySpi {

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof FrodoKEMPrivateKeySpec) {
            FrodoKEMPrivateKeySpec spec = (FrodoKEMPrivateKeySpec) keySpec;
            return new FrodoKEMPrivateKeyImpl(spec.getParams(), spec.getEncoded());
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            throw new InvalidKeySpecException(
                    "PKCS#8 encoding is not supported for FrodoKEM keys; use FrodoKEMPrivateKeySpec");
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof FrodoKEMPublicKeySpec) {
            FrodoKEMPublicKeySpec spec = (FrodoKEMPublicKeySpec) keySpec;
            return new FrodoKEMPublicKeyImpl(spec.getParams(), spec.getEncoded());
        } else if (keySpec instanceof X509EncodedKeySpec) {
            throw new InvalidKeySpecException(
                    "X.509 encoding is not supported for FrodoKEM keys; use FrodoKEMPublicKeySpec");
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof FrodoKEMPublicKeyImpl) {
            FrodoKEMPublicKeyImpl frodoKey = (FrodoKEMPublicKeyImpl) key;

            if (keySpec.isAssignableFrom(FrodoKEMPublicKeySpec.class)) {
                FrodoKEMParameterSpec params = frodoKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new FrodoKEMPublicKeySpec(frodoKey.getEncoded(), params));
            }
        } else if (key instanceof FrodoKEMPrivateKeyImpl) {
            FrodoKEMPrivateKeyImpl frodoKey = (FrodoKEMPrivateKeyImpl) key;

            if (keySpec.isAssignableFrom(FrodoKEMPrivateKeySpec.class)) {
                FrodoKEMParameterSpec params = frodoKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new FrodoKEMPrivateKeySpec(frodoKey.getEncoded(), params));
            }
        }

        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        try {
            if (key instanceof FrodoKEMPublicKeyImpl) {
                FrodoKEMPublicKeyImpl frodoKey = (FrodoKEMPublicKeyImpl) key;
                return engineGeneratePublic(new FrodoKEMPublicKeySpec(
                        frodoKey.getEncoded(),
                        frodoKey.getParams()
                ));
            } else if (key instanceof FrodoKEMPrivateKeyImpl) {
                FrodoKEMPrivateKeyImpl frodoKey = (FrodoKEMPrivateKeyImpl) key;
                return engineGeneratePrivate(new FrodoKEMPrivateKeySpec(
                        frodoKey.getEncoded(),
                        frodoKey.getParams()
                ));
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate key: " + e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}
