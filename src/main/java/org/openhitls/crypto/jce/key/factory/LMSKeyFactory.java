package org.openhitls.crypto.jce.key.factory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.LMSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.LMSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.LMSPublicKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public class LMSKeyFactory extends AbstractStatefulHBSKeyFactory {
    protected PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) {
        LMSPrivateKeySpec lmsSpec = (LMSPrivateKeySpec) spec;
        return new LMSPrivateKeyImpl(lmsSpec.getParams(), lmsSpec.getEncoded());
    }

    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        LMSPublicKeySpec lmsSpec = (LMSPublicKeySpec) spec;
        return new LMSPublicKeyImpl(lmsSpec.getParams(), lmsSpec.getEncoded());
    }

    protected boolean isPrivateSpec(KeySpec spec) { return spec instanceof LMSPrivateKeySpec; }
    protected boolean isPublicSpec(KeySpec spec) { return spec instanceof LMSPublicKeySpec; }

    protected StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key) throws InvalidKeySpecException {
        if (!(key instanceof LMSPrivateKeyImpl)) throw new InvalidKeySpecException("Not an LMS private key");
        LMSPrivateKeyImpl lmsKey = (LMSPrivateKeyImpl) key;
        return new LMSPrivateKeySpec(lmsKey.getEncoded(), lmsKey.getParams());
    }

    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key) throws InvalidKeySpecException {
        if (!(key instanceof LMSPublicKeyImpl)) throw new InvalidKeySpecException("Not an LMS public key");
        LMSPublicKeyImpl lmsKey = (LMSPublicKeyImpl) key;
        return new LMSPublicKeySpec(lmsKey.getEncoded(), lmsKey.getParams());
    }
}
