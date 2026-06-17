package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSParameters extends AbstractStatefulHBSParameters<XMSSParameterSpec> {
    @Override
    protected Class<XMSSParameterSpec> specClass() {
        return XMSSParameterSpec.class;
    }

    @Override
    protected String algorithmName() {
        return "XMSS";
    }
}
