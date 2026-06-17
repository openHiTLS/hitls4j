package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.XMSSMTParameterSpec;

public class XMSSMTParameters extends AbstractStatefulHBSParameters<XMSSMTParameterSpec> {
    @Override
    protected Class<XMSSMTParameterSpec> specClass() {
        return XMSSMTParameterSpec.class;
    }

    @Override
    protected String algorithmName() {
        return "XMSSMT";
    }
}
