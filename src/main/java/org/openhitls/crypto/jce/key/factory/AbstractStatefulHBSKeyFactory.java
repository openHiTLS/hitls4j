package org.openhitls.crypto.jce.key.factory;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.spec.StatefulHBSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public abstract class AbstractStatefulHBSKeyFactory extends KeyFactorySpi {
    protected boolean supportsPrivateKeys() {
        return true;
    }

    protected abstract PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) throws InvalidKeySpecException;

    protected abstract PublicKey createPublic(StatefulHBSPublicKeySpec spec) throws InvalidKeySpecException;

    protected abstract boolean isPrivateSpec(KeySpec spec);

    protected abstract boolean isPublicSpec(KeySpec spec);

    protected abstract StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key)
            throws InvalidKeySpecException;

    protected abstract StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key)
            throws InvalidKeySpecException;

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Key specification cannot be null");
        }
        if (!supportsPrivateKeys()) {
            throw new InvalidKeySpecException("Private keys are not supported");
        }
        if (isPrivateSpec(keySpec)) {
            return createPrivate((StatefulHBSPrivateKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("Unsupported private key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("Key specification cannot be null");
        }
        if (isPublicSpec(keySpec)) {
            return createPublic((StatefulHBSPublicKeySpec) keySpec);
        }
        throw new InvalidKeySpecException("Unsupported public key specification: " + keySpec.getClass().getName());
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if (key == null || keySpec == null) {
            throw new InvalidKeySpecException("Key and keySpec cannot be null");
        }
        if (key instanceof AbstractStatefulHBSPrivateKey && StatefulHBSPrivateKeySpec.class.isAssignableFrom(keySpec)) {
            if (!supportsPrivateKeys()) {
                throw new InvalidKeySpecException("Private keys are not supported");
            }
            StatefulHBSPrivateKeySpec spec = toPrivateSpec((AbstractStatefulHBSPrivateKey) key);
            if (keySpec.isInstance(spec)) {
                return keySpec.cast(spec);
            }
            throw new InvalidKeySpecException("Requested private key specification does not match key algorithm");
        }
        if (key instanceof AbstractStatefulHBSPublicKey && StatefulHBSPublicKeySpec.class.isAssignableFrom(keySpec)) {
            StatefulHBSPublicKeySpec spec = toPublicSpec((AbstractStatefulHBSPublicKey) key);
            if (keySpec.isInstance(spec)) {
                return keySpec.cast(spec);
            }
            throw new InvalidKeySpecException("Requested public key specification does not match key algorithm");
        }
        throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }
        if (key instanceof AbstractStatefulHBSPrivateKey) {
            if (!supportsPrivateKeys()) {
                throw new InvalidKeyException("Private keys are not supported");
            }
            return key;
        }
        if (key instanceof AbstractStatefulHBSPublicKey) {
            return key;
        }
        throw new InvalidKeyException("Unsupported key type: " + key.getClass().getName());
    }
}

abstract class AbstractPublicOnlyStatefulHBSKeyFactory extends AbstractStatefulHBSKeyFactory {
    @Override
    protected final boolean supportsPrivateKeys() {
        return false;
    }

    @Override
    protected final PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) throws InvalidKeySpecException {
        throw new InvalidKeySpecException("Private keys are not supported");
    }

    @Override
    protected final boolean isPrivateSpec(KeySpec spec) {
        return false;
    }

    @Override
    protected final StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key)
            throws InvalidKeySpecException {
        throw new InvalidKeySpecException("Private keys are not supported");
    }
}
