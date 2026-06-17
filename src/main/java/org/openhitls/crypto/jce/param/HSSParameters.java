package org.openhitls.crypto.jce.param;

import org.openhitls.crypto.jce.spec.HSSParameterSpec;

public class HSSParameters extends AbstractStatefulHBSParameters<HSSParameterSpec> {
    @Override
    protected Class<HSSParameterSpec> specClass() {
        return HSSParameterSpec.class;
    }

    @Override
    protected String algorithmName() {
        return "HSS";
    }
}
