package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSPublicKeyImpl extends AbstractStatefulHBSPublicKey {
    public XMSSPublicKeyImpl(XMSSParameterSpec params, byte[] encoded) {
        super("XMSS", params, encoded);
    }

    @Override
    public XMSSParameterSpec getParams() {
        return (XMSSParameterSpec) super.getParams();
    }
}
