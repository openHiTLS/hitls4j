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

import org.openhitls.crypto.jce.interfaces.MLKEMPrivateKey;
import org.openhitls.crypto.jce.interfaces.MLKEMPublicKey;
import org.openhitls.crypto.jce.key.MLKEMPrivateKeyImpl;
import org.openhitls.crypto.jce.key.MLKEMPublicKeyImpl;
import org.openhitls.crypto.jce.spec.MLKEMParameterSpec;
import org.openhitls.crypto.jce.spec.MLKEMPrivateKeySpec;
import org.openhitls.crypto.jce.spec.MLKEMPublicKeySpec;

public class MLKEMKeyFactory extends KeyFactorySpi{

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof MLKEMPrivateKeySpec) {
            MLKEMPrivateKeySpec mlkemSpec = (MLKEMPrivateKeySpec) keySpec;
            return new MLKEMPrivateKeyImpl(mlkemSpec.getParams(), mlkemSpec.getEncoded());
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                return new MLKEMPrivateKeyImpl(((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException("Invalid PKCS8EncodedKeySpec for MLKEM private key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof MLKEMPublicKeySpec) {
            MLKEMPublicKeySpec mlkemSpec = (MLKEMPublicKeySpec) keySpec;
            return new MLKEMPublicKeyImpl(mlkemSpec.getParams(), mlkemSpec.getEncoded());
        } else if (keySpec instanceof X509EncodedKeySpec) {
            try {
                return new MLKEMPublicKeyImpl(((X509EncodedKeySpec) keySpec).getEncoded());
            } catch (Exception e) {
                throw new InvalidKeySpecException("Invalid X509EncodedKeySpec for ML-KEM public key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof MLKEMPublicKeyImpl) {
            MLKEMPublicKeyImpl mlkemKey = (MLKEMPublicKeyImpl) key;

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }

            if (keySpec.isAssignableFrom(MLKEMPublicKeySpec.class)) {
                MLKEMParameterSpec params = mlkemKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new MLKEMPublicKeySpec(mlkemKey.getEncoded(), params));
            }
        } else if (key instanceof MLKEMPrivateKeyImpl) {
            MLKEMPrivateKeyImpl mlkemKey = (MLKEMPrivateKeyImpl) key;

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }

            if (keySpec.isAssignableFrom(MLKEMPrivateKeySpec.class)) {
                MLKEMParameterSpec params = mlkemKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new MLKEMPrivateKeySpec(mlkemKey.getEncoded(), params));
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
            if (key instanceof MLKEMPublicKeyImpl) {
                MLKEMPublicKeyImpl mlkemKey = (MLKEMPublicKeyImpl) key;
                return engineGeneratePublic(new MLKEMPublicKeySpec(
                        mlkemKey.getEncoded(),
                        mlkemKey.getParams()
                ));
            } else if (key instanceof MLKEMPrivateKeyImpl) {
                MLKEMPrivateKeyImpl mlkemKey = (MLKEMPrivateKeyImpl) key;
                return engineGeneratePrivate(new MLKEMPrivateKeySpec(
                        mlkemKey.getEncoded(),
                        mlkemKey.getParams()
                ));
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate key: " + e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }

}
