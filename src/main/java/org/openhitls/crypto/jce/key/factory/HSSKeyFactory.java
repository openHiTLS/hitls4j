package org.openhitls.crypto.jce.key.factory;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.HSSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.HSSPublicKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public class HSSKeyFactory extends AbstractPublicOnlyStatefulHBSKeyFactory {
    @Override
    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        HSSPublicKeySpec hssSpec = (HSSPublicKeySpec) spec;
        return new HSSPublicKeyImpl(hssSpec.getParams(), hssSpec.getEncoded());
    }

    @Override
    protected boolean isPublicSpec(KeySpec spec) {
        return spec instanceof HSSPublicKeySpec;
    }

    @Override
    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key)
            throws InvalidKeySpecException {
        if (!(key instanceof HSSPublicKeyImpl)) {
            throw new InvalidKeySpecException("Not an HSS public key");
        }
        HSSPublicKeyImpl hssKey = (HSSPublicKeyImpl) key;
        return new HSSPublicKeySpec(hssKey.getEncoded(), hssKey.getParams());
    }
}
