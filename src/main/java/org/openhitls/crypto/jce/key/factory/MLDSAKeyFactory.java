package org.openhitls.crypto.jce.key.factory;

import org.openhitls.crypto.jce.key.MLDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLDSAPublicKeyImpl;
import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;
import org.openhitls.crypto.jce.spec.MLDSAPrivateKeySpec;
import org.openhitls.crypto.jce.spec.MLDSAPublicKeySpec;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class MLDSAKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof MLDSAPublicKeySpec) {
            MLDSAPublicKeySpec mldsaSpec = (MLDSAPublicKeySpec) keySpec;
            return new MLDSAPublicKeyImpl(mldsaSpec.getParams(), mldsaSpec.getEncoded());
        } else if (keySpec instanceof X509EncodedKeySpec) {
            try {
                return new MLDSAPublicKeyImpl(((X509EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException("Invalid X509EncodedKeySpec for MLDSA public key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof MLDSAPrivateKeySpec) {
            MLDSAPrivateKeySpec mldsaSpec = (MLDSAPrivateKeySpec) keySpec;
            return new MLDSAPrivateKeyImpl(mldsaSpec.getParams(), mldsaSpec.getEncoded());
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                return new MLDSAPrivateKeyImpl(((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException("Invalid PKCS8EncodedKeySpec for MLDSA private key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof MLDSAPublicKeyImpl) {
            MLDSAPublicKeyImpl mldsaKey = (MLDSAPublicKeyImpl) key;

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }

            if (keySpec.isAssignableFrom(MLDSAPublicKeySpec.class)) {
                MLDSAParameterSpec params = mldsaKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new MLDSAPublicKeySpec(mldsaKey.getEncoded(), params));
            }
        } else if (key instanceof MLDSAPrivateKeyImpl) {
            MLDSAPrivateKeyImpl mldsaKey = (MLDSAPrivateKeyImpl) key;

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }

            if (keySpec.isAssignableFrom(MLDSAPrivateKeySpec.class)) {
                MLDSAParameterSpec params = mldsaKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new MLDSAPrivateKeySpec(mldsaKey.getEncoded(), params));
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
            if (key instanceof MLDSAPublicKeyImpl) {
                MLDSAPublicKeyImpl mldsaKey = (MLDSAPublicKeyImpl) key;
                return engineGeneratePublic(new MLDSAPublicKeySpec(
                        mldsaKey.getEncoded(),
                        mldsaKey.getParams()
                ));
            } else if (key instanceof MLDSAPrivateKeyImpl) {
                MLDSAPrivateKeyImpl mldsaKey = (MLDSAPrivateKeyImpl) key;
                return engineGeneratePrivate(new MLDSAPrivateKeySpec(
                        mldsaKey.getEncoded(),
                        mldsaKey.getParams()
                ));
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate key: " + e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}