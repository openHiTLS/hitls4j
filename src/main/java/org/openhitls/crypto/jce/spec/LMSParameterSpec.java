package org.openhitls.crypto.jce.spec;

public class LMSParameterSpec extends StatefulHBSParameterSpec {
    private final String lmsType;
    private final String otsType;

    public LMSParameterSpec(String lmsType, String otsType) {
        super(canonical(lmsType, otsType));
        this.lmsType = normalizeLmsType(lmsType);
        this.otsType = normalizeOtsType(otsType);
    }

    private static String canonical(String lmsType, String otsType) {
        return normalizeLmsType(lmsType) + "/" + normalizeOtsType(otsType);
    }

    static String normalizeLmsType(String name) {
        if (name == null) {
            throw new NullPointerException("lmsType cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!normalized.matches("^CRYPT_LMS_SHA256_M32_H(5|10|15|20|25)$")) {
            throw new IllegalArgumentException("Unsupported LMS tree type: " + name);
        }
        return normalized;
    }

    static String normalizeOtsType(String name) {
        if (name == null) {
            throw new NullPointerException("otsType cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!normalized.matches("^CRYPT_LMOTS_SHA256_N32_W(1|2|4|8)$")) {
            throw new IllegalArgumentException("Unsupported LM-OTS type: " + name);
        }
        return normalized;
    }

    public String getLmsType() {
        return lmsType;
    }

    public String getOtsType() {
        return otsType;
    }
}
