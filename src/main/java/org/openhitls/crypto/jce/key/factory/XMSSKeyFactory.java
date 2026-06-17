package org.openhitls.crypto.jce.key.factory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.XMSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.StatefulHBSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;
import org.openhitls.crypto.jce.spec.XMSSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.XMSSPublicKeySpec;

public class XMSSKeyFactory extends AbstractStatefulHBSKeyFactory {
    protected PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) {
        XMSSPrivateKeySpec xmssSpec = (XMSSPrivateKeySpec) spec;
        return new XMSSPrivateKeyImpl(xmssSpec.getParams(), xmssSpec.getEncoded());
    }

    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        XMSSPublicKeySpec xmssSpec = (XMSSPublicKeySpec) spec;
        return new XMSSPublicKeyImpl(xmssSpec.getParams(), xmssSpec.getEncoded());
    }

    protected boolean isPrivateSpec(KeySpec spec) { return spec instanceof XMSSPrivateKeySpec; }
    protected boolean isPublicSpec(KeySpec spec) { return spec instanceof XMSSPublicKeySpec; }

    protected StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key) throws InvalidKeySpecException {
        if (!(key instanceof XMSSPrivateKeyImpl)) throw new InvalidKeySpecException("Not an XMSS private key");
        XMSSPrivateKeyImpl xmssKey = (XMSSPrivateKeyImpl) key;
        return new XMSSPrivateKeySpec(xmssKey.getEncoded(), xmssKey.getParams());
    }

    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key) throws InvalidKeySpecException {
        if (!(key instanceof XMSSPublicKeyImpl)) throw new InvalidKeySpecException("Not an XMSS public key");
        XMSSPublicKeyImpl xmssKey = (XMSSPublicKeyImpl) key;
        return new XMSSPublicKeySpec(xmssKey.getEncoded(), xmssKey.getParams());
    }
}
