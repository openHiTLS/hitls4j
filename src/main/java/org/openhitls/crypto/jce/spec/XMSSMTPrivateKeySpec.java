package org.openhitls.crypto.jce.spec;

public class XMSSMTPrivateKeySpec extends StatefulHBSPrivateKeySpec {
    public XMSSMTPrivateKeySpec(byte[] encoded, XMSSMTParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public XMSSMTParameterSpec getParams() {
        return (XMSSMTParameterSpec) super.getParams();
    }
}
