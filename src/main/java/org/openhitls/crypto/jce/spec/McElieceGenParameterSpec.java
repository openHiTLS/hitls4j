package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class McElieceGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    private static final String PARAM_REGEX =
            "^McEliece-(6688128|6688128f|6688128pc|6688128pcf|6960119|6960119f|6960119pc|6960119pcf|8192128|8192128f|8192128pc|8192128pcf)$";

    public McElieceGenParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        if (!name.matches(PARAM_REGEX)) {
            throw new IllegalArgumentException("Invalid McEliece parameter set: " + name);
        }
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
