package org.openhitls.crypto.jce.signer;

import org.openhitls.crypto.core.pqc.LMSImpl;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;

public class LMSSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "LMS";
    }

    @Override
    protected boolean supportsSigning() {
        return false;
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        LMSPublicKeyImpl key = (LMSPublicKeyImpl) publicKey;
        try (LMSImpl impl = new LMSImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
