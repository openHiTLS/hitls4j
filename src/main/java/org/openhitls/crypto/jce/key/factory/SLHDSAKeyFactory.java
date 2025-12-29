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

import org.openhitls.crypto.jce.key.SLHDSAPrivateKeyImpl;
import org.openhitls.crypto.jce.key.SLHDSAPublicKeyImpl;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;
import org.openhitls.crypto.jce.spec.SLHDSAPrivateKeySpec;
import org.openhitls.crypto.jce.spec.SLHDSAPublicKeySpec;

public class SLHDSAKeyFactory extends KeyFactorySpi{

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            return new SLHDSAPrivateKeyImpl(((PKCS8EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof SLHDSAPrivateKeySpec) {
            SLHDSAPrivateKeySpec spec = (SLHDSAPrivateKeySpec) keySpec;
            return new SLHDSAPrivateKeyImpl(spec.getParams(), spec.getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            return new SLHDSAPublicKeyImpl(((X509EncodedKeySpec) keySpec).getEncoded());
        } else if (keySpec instanceof SLHDSAPublicKeySpec) {
            SLHDSAPublicKeySpec spec = (SLHDSAPublicKeySpec) keySpec;
            return new SLHDSAPublicKeyImpl(spec.getParams(), spec.getEncoded());
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (key instanceof SLHDSAPrivateKeyImpl) {
            SLHDSAPrivateKeyImpl slhdsaKey = (SLHDSAPrivateKeyImpl) key;
            
            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            
            if (keySpec.isAssignableFrom(SLHDSAPrivateKeySpec.class)) {
                SLHDSAParameterSpec params = slhdsaKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new SLHDSAPrivateKeySpec(slhdsaKey.getEncoded(), params));
            }
        } else if (key instanceof SLHDSAPublicKeyImpl) {
            SLHDSAPublicKeyImpl slhdsaKey = (SLHDSAPublicKeyImpl) key;

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }

            if (keySpec.isAssignableFrom(SLHDSAPublicKeySpec.class)) {
                SLHDSAParameterSpec params = slhdsaKey.getParams();
                if (params == null) {
                    throw new InvalidKeySpecException("Key parameters cannot be null");
                }
                return keySpec.cast(new SLHDSAPublicKeySpec(slhdsaKey.getEncoded(), params));   
            }
        }

        throw new InvalidKeySpecException("Unsupported key type: " + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        try {
            if (key instanceof SLHDSAPublicKeyImpl) {
                SLHDSAPublicKeyImpl slhdsaKey = (SLHDSAPublicKeyImpl) key;
                return engineGeneratePublic(new SLHDSAPublicKeySpec(slhdsaKey.getEncoded(), slhdsaKey.getParams()));
            } else if (key instanceof SLHDSAPrivateKeyImpl) {
                SLHDSAPrivateKeyImpl slhdsaKey = (SLHDSAPrivateKeyImpl) key;
                return engineGeneratePrivate(new SLHDSAPrivateKeySpec(slhdsaKey.getEncoded(), slhdsaKey.getParams()));
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Failed to translate key: " + e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
    
}
