package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSPublicKeyImpl extends AbstractStatefulHBSPublicKey {
    public HSSPublicKeyImpl(HSSParameterSpec params, byte[] encoded) {
        super("HSS", params, encoded);
    }

    @Override
    public HSSParameterSpec getParams() {
        return (HSSParameterSpec) super.getParams();
    }
}
