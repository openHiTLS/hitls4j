package org.openhitls.crypto.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class McElieceParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    public McElieceParameterSpec(String name) {
        this.name = name;
    }

    public static final McElieceParameterSpec MCELIECE_6688128 = new McElieceParameterSpec("McEliece-6688128");
    public static final McElieceParameterSpec MCELIECE_6688128F = new McElieceParameterSpec("McEliece-6688128f");
    public static final McElieceParameterSpec MCELIECE_6688128PC = new McElieceParameterSpec("McEliece-6688128pc");
    public static final McElieceParameterSpec MCELIECE_6688128PCF = new McElieceParameterSpec("McEliece-6688128pcf");
    public static final McElieceParameterSpec MCELIECE_6960119 = new McElieceParameterSpec("McEliece-6960119");
    public static final McElieceParameterSpec MCELIECE_6960119F = new McElieceParameterSpec("McEliece-6960119f");
    public static final McElieceParameterSpec MCELIECE_6960119PC = new McElieceParameterSpec("McEliece-6960119pc");
    public static final McElieceParameterSpec MCELIECE_6960119PCF = new McElieceParameterSpec("McEliece-6960119pcf");
    public static final McElieceParameterSpec MCELIECE_8192128 = new McElieceParameterSpec("McEliece-8192128");
    public static final McElieceParameterSpec MCELIECE_8192128F = new McElieceParameterSpec("McEliece-8192128f");
    public static final McElieceParameterSpec MCELIECE_8192128PC = new McElieceParameterSpec("McEliece-8192128pc");
    public static final McElieceParameterSpec MCELIECE_8192128PCF = new McElieceParameterSpec("McEliece-8192128pcf");

    public static McElieceParameterSpec getParamByName(String name) {
        switch (name) {
            case "McEliece-6688128":
                return MCELIECE_6688128;
            case "McEliece-6688128f":
                return MCELIECE_6688128F;
            case "McEliece-6688128pc":
                return MCELIECE_6688128PC;
            case "McEliece-6688128pcf":
                return MCELIECE_6688128PCF;
            case "McEliece-6960119":
                return MCELIECE_6960119;
            case "McEliece-6960119f":
                return MCELIECE_6960119F;
            case "McEliece-6960119pc":
                return MCELIECE_6960119PC;
            case "McEliece-6960119pcf":
                return MCELIECE_6960119PCF;
            case "McEliece-8192128":
                return MCELIECE_8192128;
            case "McEliece-8192128f":
                return MCELIECE_8192128F;
            case "McEliece-8192128pc":
                return MCELIECE_8192128PC;
            case "McEliece-8192128pcf":
                return MCELIECE_8192128PCF;
            default:
                throw new IllegalArgumentException("Unsupported parameter set: " + name);
        }
    }

    public String getName() {
        return name;
    }
}
