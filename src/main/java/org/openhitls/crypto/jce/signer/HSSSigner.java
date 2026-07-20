package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.HSSImpl;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.HSSPublicKeyImpl;

public class HSSSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "HSS";
    }

    @Override
    protected boolean supportsSigning() {
        return false;
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        HSSPublicKeyImpl key = (HSSPublicKeyImpl) publicKey;
        try (HSSImpl impl = new HSSImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
