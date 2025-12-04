package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class MLDSAGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public MLDSAGenParameterSpec(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}