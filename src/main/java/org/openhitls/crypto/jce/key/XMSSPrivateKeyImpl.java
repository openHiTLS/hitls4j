package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSPrivateKeyImpl extends AbstractStatefulHBSPrivateKey {
    public XMSSPrivateKeyImpl(XMSSParameterSpec params, byte[] encoded) {
        super("XMSS", params, encoded);
    }

    @Override
    public XMSSParameterSpec getParams() {
        return (XMSSParameterSpec) super.getParams();
    }
}
