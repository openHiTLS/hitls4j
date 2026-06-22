package org.openhitls.crypto.jce.key.factory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.XMSSMTPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSMTPublicKeyImpl;
import org.openhitls.crypto.jce.spec.StatefulHBSPrivateKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;
import org.openhitls.crypto.jce.spec.XMSSMTPrivateKeySpec;
import org.openhitls.crypto.jce.spec.XMSSMTPublicKeySpec;

public class XMSSMTKeyFactory extends AbstractStatefulHBSKeyFactory {
    protected PrivateKey createPrivate(StatefulHBSPrivateKeySpec spec) {
        XMSSMTPrivateKeySpec xmssmtSpec = (XMSSMTPrivateKeySpec) spec;
        return new XMSSMTPrivateKeyImpl(xmssmtSpec.getParams(), xmssmtSpec.getEncoded());
    }

    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        XMSSMTPublicKeySpec xmssmtSpec = (XMSSMTPublicKeySpec) spec;
        return new XMSSMTPublicKeyImpl(xmssmtSpec.getParams(), xmssmtSpec.getEncoded());
    }

    protected boolean isPrivateSpec(KeySpec spec) { return spec instanceof XMSSMTPrivateKeySpec; }
    protected boolean isPublicSpec(KeySpec spec) { return spec instanceof XMSSMTPublicKeySpec; }

    protected StatefulHBSPrivateKeySpec toPrivateSpec(AbstractStatefulHBSPrivateKey key) throws InvalidKeySpecException {
        if (!(key instanceof XMSSMTPrivateKeyImpl)) throw new InvalidKeySpecException("Not an XMSSMT private key");
        XMSSMTPrivateKeyImpl xmssmtKey = (XMSSMTPrivateKeyImpl) key;
        return new XMSSMTPrivateKeySpec(xmssmtKey.getEncoded(), xmssmtKey.getParams());
    }

    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key) throws InvalidKeySpecException {
        if (!(key instanceof XMSSMTPublicKeyImpl)) throw new InvalidKeySpecException("Not an XMSSMT public key");
        XMSSMTPublicKeyImpl xmssmtKey = (XMSSMTPublicKeyImpl) key;
        return new XMSSMTPublicKeySpec(xmssmtKey.getEncoded(), xmssmtKey.getParams());
    }
}
