package org.openhitls.crypto.jce.spec;

public class XMSSParameterSpec extends StatefulHBSParameterSpec {
    public XMSSParameterSpec(String name) {
        super(normalize(name));
    }

    public static String normalize(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        String normalized = name.replace('-', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!isSupportedParameterSet(normalized)) {
            throw new IllegalArgumentException("Unsupported XMSS parameter set: " + name);
        }
        return normalized;
    }

    private static boolean isSupportedParameterSet(String normalized) {
        String prefix = "CRYPT_XMSS_";
        if (!normalized.startsWith(prefix)) {
            return false;
        }
        String[] parts = normalized.substring(prefix.length()).split("_");
        if (parts.length != 3 || !isOneOf(parts[1], "10", "16", "20")) {
            return false;
        }
        if ("SHA2".equals(parts[0])) {
            return isOneOf(parts[2], "192", "256", "512");
        }
        if ("SHAKE".equals(parts[0])) {
            return isOneOf(parts[2], "256", "512");
        }
        if ("SHAKE256".equals(parts[0])) {
            return isOneOf(parts[2], "192", "256");
        }
        return false;
    }

    private static boolean isOneOf(String value, String... candidates) {
        for (String candidate : candidates) {
            if (candidate.equals(value)) {
                return true;
            }
        }
        return false;
    }
}
