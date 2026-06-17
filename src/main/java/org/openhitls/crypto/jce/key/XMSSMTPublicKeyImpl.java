package org.openhitls.crypto.jce.key;

import org.openhitls.crypto.jce.spec.XMSSMTParameterSpec;

public class XMSSMTPublicKeyImpl extends AbstractStatefulHBSPublicKey {
    public XMSSMTPublicKeyImpl(XMSSMTParameterSpec params, byte[] encoded) {
        super("XMSSMT", params, encoded);
    }

    @Override
    public XMSSMTParameterSpec getParams() {
        return (XMSSMTParameterSpec) super.getParams();
    }
}
