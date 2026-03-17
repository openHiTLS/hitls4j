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

import org.openhitls.crypto.jce.key.McEliecePrivateKeyImpl;
import org.openhitls.crypto.jce.key.McEliecePublicKeyImpl;
import org.openhitls.crypto.jce.spec.McElieceParameterSpec;
import org.openhitls.crypto.jce.spec.McEliecePrivateKeySpec;
import org.openhitls.crypto.jce.spec.McEliecePublicKeySpec;

public class McElieceKeyFactory extends KeyFactorySpi {

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof McEliecePrivateKeySpec) {
            McEliecePrivateKeySpec spec = (McEliecePrivateKeySpec) keySpec;
            return new McEliecePrivateKeyImpl(spec.getParams(), spec.getEncoded());
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            throw new InvalidKeySpecException(
                    "PKCS#8 encoding is not supported for Classic McEliece keys; use McEliecePrivateKeySpec");
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof McEliecePublicKeySpec) {
            McEliecePublicKeySpec spec = (McEliecePublicKeySpec) keySpec;
            return new McEliecePublicKeyImpl(spec.getParams(), spec.getEncoded());
        } else if (keySpec instanceof X509EncodedKeySpec) {
            throw new InvalidKeySpecException(
                    "X.509 encoding is not supported for Classic McEliece keys; use McEliecePublicKeySpec");
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof McEliecePublicKeyImpl) {
            McEliecePublicKeyImpl mcElieceKey = (McEliecePublicKeyImpl) key;

            if (keySpec.isAssignableFrom(McEliecePublicKeySpec.class)) {
                McElieceParameterSpec params = mcElieceKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new McEliecePublicKeySpec(mcElieceKey.getEncoded(), params));
            }
        } else if (key instanceof McEliecePrivateKeyImpl) {
            McEliecePrivateKeyImpl mcElieceKey = (McEliecePrivateKeyImpl) key;

            if (keySpec.isAssignableFrom(McEliecePrivateKeySpec.class)) {
                McElieceParameterSpec params = mcElieceKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new McEliecePrivateKeySpec(mcElieceKey.getEncoded(), params));
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
            if (key instanceof McEliecePublicKeyImpl) {
                McEliecePublicKeyImpl mcElieceKey = (McEliecePublicKeyImpl) key;
                return engineGeneratePublic(new McEliecePublicKeySpec(
                        mcElieceKey.getEncoded(),
                        mcElieceKey.getParams()
                ));
            } else if (key instanceof McEliecePrivateKeyImpl) {
                McEliecePrivateKeyImpl mcElieceKey = (McEliecePrivateKeyImpl) key;
                return engineGeneratePrivate(new McEliecePrivateKeySpec(
                        mcElieceKey.getEncoded(),
                        mcElieceKey.getParams()
                ));
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate key: " + e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}
