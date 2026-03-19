package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class FrodoKEMGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public FrodoKEMGenParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        if (!name.matches("^FrodoKEM-(640|976|1344)-(SHAKE|AES)$")) {
            throw new IllegalArgumentException("Invalid FrodoKEM parameter set: " + name);
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
