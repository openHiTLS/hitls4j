package org.openhitls.crypto.jce.spec;

public class XMSSMTParameterSpec extends StatefulHBSParameterSpec {
    public XMSSMTParameterSpec(String name) {
        super(normalize(name));
    }

    public static String normalize(String name) {
        if (name == null) {
            throw new NullPointerException("name cannot be null");
        }
        String normalized = name.replace("XMSS^MT", "XMSSMT").replace('-', '_').replace('/', '_');
        if (!normalized.startsWith("CRYPT_")) {
            normalized = "CRYPT_" + normalized;
        }
        if (!isSupportedParameterSet(normalized)) {
            throw new IllegalArgumentException("Unsupported XMSSMT parameter set: " + name);
        }
        return normalized;
    }

    private static boolean isSupportedParameterSet(String normalized) {
        String prefix = "CRYPT_XMSSMT_";
        if (!normalized.startsWith(prefix)) {
            return false;
        }
        String[] parts = normalized.substring(prefix.length()).split("_");
        if (parts.length != 4 || !isSupportedLayer(parts[1], parts[2])) {
            return false;
        }
        if ("SHA2".equals(parts[0])) {
            return isOneOf(parts[3], "192", "256", "512");
        }
        if ("SHAKE".equals(parts[0])) {
            return isOneOf(parts[3], "256", "512");
        }
        if ("SHAKE256".equals(parts[0])) {
            return isOneOf(parts[3], "192", "256");
        }
        return false;
    }

    private static boolean isSupportedLayer(String height, String layers) {
        if ("20".equals(height)) {
            return isOneOf(layers, "2", "4");
        }
        if ("40".equals(height)) {
            return isOneOf(layers, "2", "4", "8");
        }
        if ("60".equals(height)) {
            return isOneOf(layers, "3", "6", "12");
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
