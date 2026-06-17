package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.LMSParameterSpec;

public class LMSParameters extends AbstractStatefulHBSParameters<LMSParameterSpec> {
    @Override
    protected Class<LMSParameterSpec> specClass() {
        return LMSParameterSpec.class;
    }

    @Override
    protected String algorithmName() {
        return "LMS";
    }
}
