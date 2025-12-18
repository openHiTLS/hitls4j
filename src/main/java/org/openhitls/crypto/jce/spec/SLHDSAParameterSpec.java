package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class SLHDSAParameterSpec implements AlgorithmParameterSpec{
    private final String name;
    public SLHDSAParameterSpec(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
