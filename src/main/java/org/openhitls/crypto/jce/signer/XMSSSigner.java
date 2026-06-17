package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.core.pqc.XMSSImpl;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.XMSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSPublicKeyImpl;

public class XMSSSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "XMSS";
    }

    protected StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data) {
        XMSSPrivateKeyImpl key = (XMSSPrivateKeyImpl) privateKey;
        try (XMSSImpl impl = new XMSSImpl(key.getParams())) {
            return impl.sign(privateState, data);
        }
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        XMSSPublicKeyImpl key = (XMSSPublicKeyImpl) publicKey;
        try (XMSSImpl impl = new XMSSImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
