package org.openhitls.crypto.jce.spec;

import java.util.Arrays;

public class HSSParameterSpec extends StatefulHBSParameterSpec {
    private final String[] lmsTypes;
    private final String[] otsTypes;

    public HSSParameterSpec(String[] lmsTypes, String[] otsTypes) {
        super(canonical(lmsTypes, otsTypes));
        validateLengths(lmsTypes, otsTypes);
        this.lmsTypes = normalizeLmsTypes(lmsTypes);
        this.otsTypes = normalizeOtsTypes(otsTypes);
    }

    public static HSSParameterSpec named(String name) {
        if ("HSS_SHA256_L2_H10_H10".equals(name)) {
            return repeated("CRYPT_LMS_SHA256_M32_H10", "CRYPT_LMOTS_SHA256_N32_W4", 2);
        } else if ("HSS_SHA256_L2_H15_H15".equals(name)) {
            return repeated("CRYPT_LMS_SHA256_M32_H15", "CRYPT_LMOTS_SHA256_N32_W4", 2);
        } else if ("HSS_SHA256_L2_H20_H20".equals(name)) {
            return repeated("CRYPT_LMS_SHA256_M32_H20", "CRYPT_LMOTS_SHA256_N32_W4", 2);
        } else if ("HSS_SHA256_L3_H10_H10_H10".equals(name)) {
            return repeated("CRYPT_LMS_SHA256_M32_H10", "CRYPT_LMOTS_SHA256_N32_W4", 3);
        }
        throw new IllegalArgumentException("Unsupported HSS parameter set: " + name);
    }

    private static HSSParameterSpec repeated(String lmsType, String otsType, int levels) {
        String[] lmsTypes = new String[levels];
        String[] otsTypes = new String[levels];
        Arrays.fill(lmsTypes, lmsType);
        Arrays.fill(otsTypes, otsType);
        return new HSSParameterSpec(lmsTypes, otsTypes);
    }

    private static String canonical(String[] lmsTypes, String[] otsTypes) {
        validateLengths(lmsTypes, otsTypes);
        return "HSS-L" + lmsTypes.length + "-" + Arrays.toString(normalizeLmsTypes(lmsTypes))
                + "-" + Arrays.toString(normalizeOtsTypes(otsTypes));
    }

    private static void validateLengths(String[] lmsTypes, String[] otsTypes) {
        if (lmsTypes == null || otsTypes == null) {
            throw new NullPointerException("HSS level parameter arrays cannot be null");
        }
        if (lmsTypes.length == 0 || lmsTypes.length > 3 || lmsTypes.length != otsTypes.length) {
            throw new IllegalArgumentException("HSS requires 1 to 3 matching LMS and OTS levels");
        }
    }

    private static String[] normalizeLmsTypes(String[] input) {
        String[] result = new String[input.length];
        for (int i = 0; i < input.length; i++) {
            result[i] = LMSParameterSpec.normalizeLmsType(input[i]);
        }
        return result;
    }

    private static String[] normalizeOtsTypes(String[] input) {
        String[] result = new String[input.length];
        for (int i = 0; i < input.length; i++) {
            result[i] = LMSParameterSpec.normalizeOtsType(input[i]);
        }
        return result;
    }

    public int getLevels() {
        return lmsTypes.length;
    }

    public String[] getLmsTypes() {
        return lmsTypes.clone();
    }

    public String[] getOtsTypes() {
        return otsTypes.clone();
    }
}
