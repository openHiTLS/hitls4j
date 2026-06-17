package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.LMSImpl;
import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.LMSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;

public class LMSSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "LMS";
    }

    protected StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data) {
        LMSPrivateKeyImpl key = (LMSPrivateKeyImpl) privateKey;
        try (LMSImpl impl = new LMSImpl(key.getParams())) {
            return impl.sign(privateState, data);
        }
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        LMSPublicKeyImpl key = (LMSPublicKeyImpl) publicKey;
        try (LMSImpl impl = new LMSImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
