package org.openhitls.crypto.jce.spec;

public class HSSPrivateKeySpec extends StatefulHBSPrivateKeySpec {
    public HSSPrivateKeySpec(byte[] encoded, HSSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public HSSParameterSpec getParams() {
        return (HSSParameterSpec) super.getParams();
    }
}
