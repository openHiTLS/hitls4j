package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSPublicKeyImpl extends AbstractStatefulHBSPublicKey {
    public LMSPublicKeyImpl(LMSParameterSpec params, byte[] encoded) {
        super("LMS", params, encoded);
    }

    @Override
    public LMSParameterSpec getParams() {
        return (LMSParameterSpec) super.getParams();
    }
}
