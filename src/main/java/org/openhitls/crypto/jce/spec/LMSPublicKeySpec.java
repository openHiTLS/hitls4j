package org.openhitls.crypto.jce.spec;

public class LMSPublicKeySpec extends StatefulHBSPublicKeySpec {
    public LMSPublicKeySpec(byte[] encoded, LMSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public LMSParameterSpec getParams() {
        return (LMSParameterSpec) super.getParams();
    }
}
