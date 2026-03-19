package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class MLKEMGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public MLKEMGenParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        if (!name.matches("^ML-KEM-(512|768|1024)$")) {
            throw new IllegalArgumentException("Invalid ML-KEM parameter set: " + name);
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
