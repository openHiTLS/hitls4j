package org.openhitls.crypto.jce.spec;

public class LMSPrivateKeySpec extends StatefulHBSPrivateKeySpec {
    public LMSPrivateKeySpec(byte[] encoded, LMSParameterSpec params) {
        super(encoded, params);
    }

    @Override
    public LMSParameterSpec getParams() {
        return (LMSParameterSpec) super.getParams();
    }
}
