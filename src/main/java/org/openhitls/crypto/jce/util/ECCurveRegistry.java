package org.openhitls.crypto.jce.util;

import java.security.spec.ECParameterSpec;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.openhitls.crypto.jce.spec.ECNamedCurveSpec;

public final class ECCurveRegistry {
    private static final String OID_SECP256R1 = "1.2.840.10045.3.1.7";
    private static final String OID_SECP384R1 = "1.3.132.0.34";
    private static final String OID_SECP521R1 = "1.3.132.0.35";
    private static final String OID_SM2P256V1 = "1.2.156.10197.1.301";

    private static final Map<String, ECNamedCurveSpec> CANONICAL_CURVES = new LinkedHashMap<>();
    private static final Map<String, ECNamedCurveSpec> NAMED_CURVES = new HashMap<>();
    private static final Map<String, String> NAME_TO_OID = new HashMap<>();
    private static final Map<String, String> OID_TO_NAME = new HashMap<>();

    static {
        registerCurve("sm2p256v1", OID_SM2P256V1, ECNamedCurveSpec.getSM2Curve());
        registerCurve("secp256r1", OID_SECP256R1, ECNamedCurveSpec.getP256Curve());
        registerCurve("secp384r1", OID_SECP384R1, ECNamedCurveSpec.getP384Curve());
        registerCurve("secp521r1", OID_SECP521R1, ECNamedCurveSpec.getP521Curve());

        registerAlias("prime256v1", "secp256r1");
        registerAlias("p-256", "secp256r1");
        registerAlias("p-384", "secp384r1");
        registerAlias("p-521", "secp521r1");
    }

    private ECCurveRegistry() {
    }

    public static String canonicalName(String curveName) {
        if (curveName == null) {
            throw new IllegalArgumentException("Curve name cannot be null");
        }
        String normalized = normalize(curveName);
        String oid = NAME_TO_OID.get(normalized);
        if (oid == null) {
            throw new IllegalArgumentException("Unsupported EC curve: " + curveName);
        }
        return OID_TO_NAME.get(oid);
    }

    public static ECNamedCurveSpec getNamedCurve(String curveName) {
        ECNamedCurveSpec spec = NAMED_CURVES.get(normalize(curveName));
        if (spec == null) {
            throw new IllegalArgumentException("Unsupported curve: " + curveName);
        }
        return spec;
    }

    public static Map<String, ECParameterSpec> getNamedCurves() {
        return Collections.unmodifiableMap(new HashMap<String, ECParameterSpec>(NAMED_CURVES));
    }

    public static Collection<ECNamedCurveSpec> getCanonicalCurves() {
        return Collections.unmodifiableCollection(CANONICAL_CURVES.values());
    }

    public static String getOid(String curveName) {
        return NAME_TO_OID.get(normalize(curveName));
    }

    public static String getNameForOid(String oid) {
        return OID_TO_NAME.get(oid);
    }

    public static boolean isNistCurve(String curveName) {
        String canonical = canonicalName(curveName);
        return "secp256r1".equals(canonical)
                || "secp384r1".equals(canonical)
                || "secp521r1".equals(canonical);
    }

    public static boolean isSM2Curve(String curveName) {
        return "sm2p256v1".equals(canonicalName(curveName));
    }

    private static void registerCurve(String curveName, String oid, ECNamedCurveSpec spec) {
        CANONICAL_CURVES.put(curveName, spec);
        NAMED_CURVES.put(curveName, spec);
        NAME_TO_OID.put(curveName, oid);
        OID_TO_NAME.put(oid, curveName);
    }

    private static void registerAlias(String alias, String canonicalName) {
        NAMED_CURVES.put(alias, CANONICAL_CURVES.get(canonicalName));
        NAME_TO_OID.put(alias, NAME_TO_OID.get(canonicalName));
    }

    private static String normalize(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }
}
