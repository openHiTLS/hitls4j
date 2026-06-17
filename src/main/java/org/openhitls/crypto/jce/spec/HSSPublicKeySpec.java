package org.openhitls.crypto.jce.spec;

public class HSSPublicKeySpec extends StatefulHBSPublicKeySpec {
    public HSSPublicKeySpec(byte[] encoded, HSSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public HSSParameterSpec getParams() {
        return (HSSParameterSpec) super.getParams();
    }
}
