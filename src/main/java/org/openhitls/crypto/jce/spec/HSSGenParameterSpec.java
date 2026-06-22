package org.openhitls.crypto.jce.spec;

public class HSSGenParameterSpec extends HSSParameterSpec {
    public HSSGenParameterSpec(String[] lmsTypes, String[] otsTypes) {
        super(lmsTypes, otsTypes);
    }

    public static HSSGenParameterSpec named(String name) {
        HSSParameterSpec spec = HSSParameterSpec.named(name);
        return new HSSGenParameterSpec(spec.getLmsTypes(), spec.getOtsTypes());
    }
}
