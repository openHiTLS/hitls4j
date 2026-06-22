package org.openhitls.crypto.jce.spec;

public class XMSSMTPublicKeySpec extends StatefulHBSPublicKeySpec {
    public XMSSMTPublicKeySpec(byte[] encoded, XMSSMTParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public XMSSMTParameterSpec getParams() {
        return (XMSSMTParameterSpec) super.getParams();
    }
}
