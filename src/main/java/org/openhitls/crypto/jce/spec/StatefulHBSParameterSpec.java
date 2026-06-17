package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public abstract class StatefulHBSParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    protected StatefulHBSParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
