package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class MLKEMGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public MLKEMGenParameterSpec(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
