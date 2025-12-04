package org.openhitls.crypto.jce.util;

import org.openhitls.crypto.jce.spec.MLDSAParameterSpec;

public class MLDSAUtil {
    public static String getParamSetName(MLDSAParameterSpec params) {
        int k = params.getK();
        return switch (k) {
            case 4 -> "ML-DSA-44";
            case 6 -> "ML-DSA-65";
            case 8 -> "ML-DSA-87";
            default -> throw new IllegalArgumentException("Unsupported MLDSA parameters");
        };
    }
}