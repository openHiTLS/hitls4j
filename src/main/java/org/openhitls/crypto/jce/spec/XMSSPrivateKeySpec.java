package org.openhitls.crypto.jce.spec;

public class XMSSPrivateKeySpec extends StatefulHBSPrivateKeySpec {
    public XMSSPrivateKeySpec(byte[] encoded, XMSSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public XMSSParameterSpec getParams() {
        return (XMSSParameterSpec) super.getParams();
    }
}
