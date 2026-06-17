package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSPrivateKeyImpl extends AbstractStatefulHBSPrivateKey {
    public LMSPrivateKeyImpl(LMSParameterSpec params, byte[] encoded) {
        super("LMS", params, encoded);
    }

    @Override
    public LMSParameterSpec getParams() {
        return (LMSParameterSpec) super.getParams();
    }
}
