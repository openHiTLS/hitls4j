package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.core.pqc.XMSSMTImpl;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.XMSSMTPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSMTPublicKeyImpl;

public class XMSSMTSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "XMSSMT";
    }

    protected StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data) {
        XMSSMTPrivateKeyImpl key = (XMSSMTPrivateKeyImpl) privateKey;
        try (XMSSMTImpl impl = new XMSSMTImpl(key.getParams())) {
            return impl.sign(privateState, data);
        }
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        XMSSMTPublicKeyImpl key = (XMSSMTPublicKeyImpl) publicKey;
        try (XMSSMTImpl impl = new XMSSMTImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
