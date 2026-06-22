package org.openhitls.crypto.jce.spec;

public class XMSSPublicKeySpec extends StatefulHBSPublicKeySpec {
    public XMSSPublicKeySpec(byte[] encoded, XMSSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public XMSSParameterSpec getParams() {
        return (XMSSParameterSpec) super.getParams();
    }
}
