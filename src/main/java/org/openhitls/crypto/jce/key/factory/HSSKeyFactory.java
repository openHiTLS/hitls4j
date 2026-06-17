package org.openhitls.crypto.jce.key.factory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.HSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.HSSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.HSSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.HSSPublicKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public class HSSKeyFactory extends AbstractStatefulHBSKeyFactory {
    protected PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) {
        HSSPrivateKeySpec hssSpec = (HSSPrivateKeySpec) spec;
        return new HSSPrivateKeyImpl(hssSpec.getParams(), hssSpec.getEncoded());
    }

    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        HSSPublicKeySpec hssSpec = (HSSPublicKeySpec) spec;
        return new HSSPublicKeyImpl(hssSpec.getParams(), hssSpec.getEncoded());
    }

    protected boolean isPrivateSpec(KeySpec spec) { return spec instanceof HSSPrivateKeySpec; }
    protected boolean isPublicSpec(KeySpec spec) { return spec instanceof HSSPublicKeySpec; }

    protected StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key) throws InvalidKeySpecException {
        if (!(key instanceof HSSPrivateKeyImpl)) throw new InvalidKeySpecException("Not an HSS private key");
        HSSPrivateKeyImpl hssKey = (HSSPrivateKeyImpl) key;
        return new HSSPrivateKeySpec(hssKey.getEncoded(), hssKey.getParams());
    }

    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key) throws InvalidKeySpecException {
        if (!(key instanceof HSSPublicKeyImpl)) throw new InvalidKeySpecException("Not an HSS public key");
        HSSPublicKeyImpl hssKey = (HSSPublicKeyImpl) key;
        return new HSSPublicKeySpec(hssKey.getEncoded(), hssKey.getParams());
    }
}
