package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class FrodoKEMParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public FrodoKEMParameterSpec(String name) {
        this.name = name;
    }

    public static final FrodoKEMParameterSpec FRODOKEM_640_SHAKE = new FrodoKEMParameterSpec("FrodoKEM-640-SHAKE");
    public static final FrodoKEMParameterSpec FRODOKEM_640_AES = new FrodoKEMParameterSpec("FrodoKEM-640-AES");
    public static final FrodoKEMParameterSpec FRODOKEM_976_SHAKE = new FrodoKEMParameterSpec("FrodoKEM-976-SHAKE");
    public static final FrodoKEMParameterSpec FRODOKEM_976_AES = new FrodoKEMParameterSpec("FrodoKEM-976-AES");
    public static final FrodoKEMParameterSpec FRODOKEM_1344_SHAKE = new FrodoKEMParameterSpec("FrodoKEM-1344-SHAKE");
    public static final FrodoKEMParameterSpec FRODOKEM_1344_AES = new FrodoKEMParameterSpec("FrodoKEM-1344-AES");

    public static FrodoKEMParameterSpec getParamByName(String name) {
        switch (name) {
            case "FrodoKEM-640-SHAKE":
                return FRODOKEM_640_SHAKE;
            case "FrodoKEM-640-AES":
                return FRODOKEM_640_AES;
            case "FrodoKEM-976-SHAKE":
                return FRODOKEM_976_SHAKE;
            case "FrodoKEM-976-AES":
                return FRODOKEM_976_AES;
            case "FrodoKEM-1344-SHAKE":
                return FRODOKEM_1344_SHAKE;
            case "FrodoKEM-1344-AES":
                return FRODOKEM_1344_AES;
            default:
                throw new IllegalArgumentException("Unsupported parameter set: " + name);
        }
    }

    public String getName() {
        return name;
    }
}
