package org.openhitls.crypto.jce.param;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.AlgorithmParametersSpi;
import java.util.Map;
import java.util.Arrays;

import org.openhitls.crypto.jce.util.ECCurveRegistry;
import org.openhitls.crypto.jce.util.ECUtil;

/**
 * EC algorithm parameters implementation.
 */
public class ECParameters extends AlgorithmParametersSpi {
    private ECParameterSpec ecParameterSpec;
    private String name;

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec instanceof ECParameterSpec) {
            ECParameterSpec newSpec = (ECParameterSpec)paramSpec;
            String newName = canonicalCurveName(getCurveName(newSpec));
            ecParameterSpec = newSpec;
            name = newName;
        } else if (paramSpec instanceof ECGenParameterSpec) {
            String newName = canonicalCurveName(((ECGenParameterSpec)paramSpec).getName());
            ecParameterSpec = ECCurveRegistry.getNamedCurve(newName);
            name = newName;
        } else {
            throw new InvalidParameterSpecException("ECParameterSpec or ECGenParameterSpec required");
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        engineInit(params, null);
    }

    protected void engineInit(byte[] params, String format) throws IOException {
        if (!isSupportedFormat(format)) {
            throw new IOException("Unsupported EC parameters format: " + format);
        }

        String oid = decodeDerOid(params);
        String curveName = ECCurveRegistry.getNameForOid(oid);
        if (curveName == null) {
            throw new IOException("Unsupported EC curve OID: " + oid);
        }

        name = curveName;
        ecParameterSpec = ECCurveRegistry.getNamedCurve(curveName);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new NullPointerException("paramSpec == null");
        }

        if (ECParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (ecParameterSpec == null) {
                throw new InvalidParameterSpecException("ECParameterSpec not initialized");
            }
            return (T)ecParameterSpec;
        }

        if (ECGenParameterSpec.class.isAssignableFrom(paramSpec)) {
            if (name != null) {
                return (T)new ECGenParameterSpec(name);
            }
        }

        throw new InvalidParameterSpecException("Unknown parameter spec: " + paramSpec.getName());
    }

    protected byte[] engineGetEncoded() throws IOException {
        return engineGetEncoded(null);
    }

    protected byte[] engineGetEncoded(String format) throws IOException {
        if (!isSupportedFormat(format)) {
            throw new IOException("Unsupported EC parameters format: " + format);
        }
        if (name == null) {
            throw new IOException("EC parameters not initialized with a supported named curve");
        }

        String oid = ECCurveRegistry.getOid(name);
        if (oid == null) {
            throw new IOException("Unsupported EC curve: " + name);
        }
        return encodeDerOid(oid);
    }

    protected String engineToString() {
        return name != null ? name : "Unnamed EC Parameters";
    }

    // Make namedCurves accessible
    public static Map<String, ECParameterSpec> getNamedCurves() {
        return ECCurveRegistry.getNamedCurves();
    }

    private static String canonicalCurveName(String curveName) throws InvalidParameterSpecException {
        try {
            return ECCurveRegistry.canonicalName(curveName);
        } catch (RuntimeException e) {
            throw new InvalidParameterSpecException("Unknown curve name: " + curveName);
        }
    }

    private static String getCurveName(ECParameterSpec params) throws InvalidParameterSpecException {
        try {
            return ECUtil.getCurveName(params);
        } catch (RuntimeException e) {
            InvalidParameterSpecException exception =
                    new InvalidParameterSpecException("Unsupported EC parameters");
            exception.initCause(e);
            throw exception;
        }
    }

    private static boolean isSupportedFormat(String format) {
        return format == null
                || "ASN.1".equalsIgnoreCase(format)
                || "X.509".equalsIgnoreCase(format);
    }

    private static byte[] encodeDerOid(String oid) throws IOException {
        return der(0x06, encodeOidValue(oid));
    }

    private static byte[] encodeOidValue(String oid) throws IOException {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IOException("Invalid OID: " + oid);
        }

        long first = Long.parseLong(parts[0]);
        long second = Long.parseLong(parts[1]);
        if (first < 0 || first > 2 || second < 0 || (first < 2 && second > 39)) {
            throw new IOException("Invalid OID: " + oid);
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, first * 40 + second);
        for (int i = 2; i < parts.length; i++) {
            long value = Long.parseLong(parts[i]);
            if (value < 0) {
                throw new IOException("Invalid OID: " + oid);
            }
            writeBase128(out, value);
        }
        return out.toByteArray();
    }

    private static byte[] der(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }

        int bytes = 0;
        int value = length;
        while (value > 0) {
            bytes++;
            value >>= 8;
        }
        out.write(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            out.write((length >> (8 * i)) & 0xff);
        }
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        int length = 1;
        long remaining = value;
        while ((remaining >>= 7) > 0) {
            length++;
        }
        for (int i = length - 1; i >= 0; i--) {
            int b = (int) ((value >> (7 * i)) & 0x7f);
            if (i != 0) {
                b |= 0x80;
            }
            out.write(b);
        }
    }

    private static String decodeDerOid(byte[] encoded) throws IOException {
        if (encoded == null) {
            throw new IOException("EC parameters encoding cannot be null");
        }
        if (encoded.length < 2 || (encoded[0] & 0xff) != 0x06) {
            throw new IOException("EC parameters must be a DER OBJECT IDENTIFIER");
        }

        int offset = 2;
        int lengthByte = encoded[1] & 0xff;
        int length;
        if (lengthByte < 0x80) {
            length = lengthByte;
        } else {
            int lengthBytes = lengthByte & 0x7f;
            if (lengthBytes == 0) {
                throw new IOException("Indefinite length is not valid DER");
            }
            if (lengthBytes > 4 || offset + lengthBytes > encoded.length) {
                throw new IOException("Invalid DER length");
            }

            length = 0;
            for (int i = 0; i < lengthBytes; i++) {
                int next = encoded[offset++] & 0xff;
                if (i == 0 && next == 0) {
                    throw new IOException("Non-minimal DER length");
                }
                if (length > (Integer.MAX_VALUE >>> 8)) {
                    throw new IOException("Invalid DER length");
                }
                length = (length << 8) | next;
            }
            if (length < 0x80) {
                throw new IOException("Non-minimal DER length");
            }
        }

        if (length == 0 || length != encoded.length - offset) {
            throw new IOException("Invalid DER OBJECT IDENTIFIER length");
        }

        return decodeOidValue(Arrays.copyOfRange(encoded, offset, offset + length));
    }

    private static String decodeOidValue(byte[] encoded) throws IOException {
        int[] offset = new int[] {0};
        long firstValue = readBase128(encoded, offset);
        StringBuilder oid = new StringBuilder();
        if (firstValue < 40) {
            oid.append("0.").append(firstValue);
        } else if (firstValue < 80) {
            oid.append("1.").append(firstValue - 40);
        } else {
            oid.append("2.").append(firstValue - 80);
        }

        while (offset[0] < encoded.length) {
            oid.append('.').append(readBase128(encoded, offset));
        }
        return oid.toString();
    }

    private static long readBase128(byte[] encoded, int[] offset) throws IOException {
        if (offset[0] >= encoded.length) {
            throw new IOException("Truncated OID");
        }

        long value = 0;
        boolean firstByte = true;
        while (offset[0] < encoded.length) {
            int b = encoded[offset[0]++] & 0xff;
            if (firstByte && b == 0x80) {
                throw new IOException("Non-minimal OID encoding");
            }
            firstByte = false;
            if (value > (Long.MAX_VALUE >> 7)) {
                throw new IOException("OID value too large");
            }
            value = (value << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) {
                return value;
            }
        }
        throw new IOException("Truncated OID");
    }
}
