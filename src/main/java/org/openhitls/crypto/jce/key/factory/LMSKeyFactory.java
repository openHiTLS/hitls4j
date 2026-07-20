package org.openhitls.crypto.jce.key.factory;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.LMSPublicKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public class LMSKeyFactory extends AbstractPublicOnlyStatefulHBSKeyFactory {
    @Override
    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        LMSPublicKeySpec lmsSpec = (LMSPublicKeySpec) spec;
        return new LMSPublicKeyImpl(lmsSpec.getParams(), lmsSpec.getEncoded());
    }

    @Override
    protected boolean isPublicSpec(KeySpec spec) {
        return spec instanceof LMSPublicKeySpec;
    }

    @Override
    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key)
            throws InvalidKeySpecException {
        if (!(key instanceof LMSPublicKeyImpl)) {
            throw new InvalidKeySpecException("Not an LMS public key");
        }
        LMSPublicKeyImpl lmsKey = (LMSPublicKeyImpl) key;
        return new LMSPublicKeySpec(lmsKey.getEncoded(), lmsKey.getParams());
    }
}
