package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSPrivateKeyImpl extends AbstractStatefulHBSPrivateKey {
    public HSSPrivateKeyImpl(HSSParameterSpec params, byte[] encoded) {
        super("HSS", params, encoded);
    }

    @Override
    public HSSParameterSpec getParams() {
        return (HSSParameterSpec) super.getParams();
    }
}
