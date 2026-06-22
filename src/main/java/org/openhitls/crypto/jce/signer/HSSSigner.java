package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.HSSImpl;
import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.HSSPrivateKeyImpl;
import org.openhitls.crypto.jce.key.HSSPublicKeyImpl;

public class HSSSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "HSS";
    }

    protected StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data) {
        HSSPrivateKeyImpl key = (HSSPrivateKeyImpl) privateKey;
        try (HSSImpl impl = new HSSImpl(key.getParams())) {
            return impl.sign(privateState, data);
        }
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        HSSPublicKeyImpl key = (HSSPublicKeyImpl) publicKey;
        try (HSSImpl impl = new HSSImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
